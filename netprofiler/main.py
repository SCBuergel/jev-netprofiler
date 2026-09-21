"""Command line entry point.

  netprofiler                      capture vif* + Jev + TUI in one process
  netprofiler --headless           capture + Jev, JSON lines on stdout (service)
  netprofiler --attach STATE.json  TUI only, reading the service's state file
  netprofiler --pcap FILE          replay a capture as a single vif (offline dev)
  netprofiler --dry-run            no Jev calls; fake answers for UI work
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import multiprocessing
import os
import signal
import sys
from pathlib import Path

from .config import DEFAULT_POPULATION, MODEL, Settings
from .engine import Engine

log = logging.getLogger("netprofiler")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="netprofiler", description="Qubes net-qube traffic profiler (nfstream + Jev + Textual)")
    p.add_argument("--catalog", type=Path, default=None, help="activities.yaml (default: bundled)")
    p.add_argument("--pcap", type=Path, default=None, help="replay this pcap instead of capturing vif* interfaces")
    p.add_argument("--speed", type=float, default=1.0, help="pcap replay speed multiplier")
    p.add_argument("--interface", "-i", action="append", default=[], help="capture only these vif* interfaces (repeatable; eth0 is always refused)")
    p.add_argument("--local-net", action="append", default=[], help="CIDR of the downstream (qube) side, for upload/download orientation when the SYN and private-address heuristics cannot tell (repeatable)")
    p.add_argument("--self", dest="self_capture", action="store_true", help="also profile this qube's own applications on eth0, leaving the profiler's own Jev traffic out")
    p.add_argument("--self-iface", default="eth0", help="interface for --self (default eth0)")
    p.add_argument("--dump-questions", action="store_true", help="print the exact Jev questions (built from the catalog) as JSON and exit")
    p.add_argument("--include-own-traffic", action="store_true", help="with --self: do not exclude the profiler's own flows (to see the contamination)")
    p.add_argument("--raw", action="store_true", help="raw-packet mode: send a headers-only tcpdump log (no payload, opaque addresses) instead of the reduced description")
    p.add_argument("--raw-batch", type=float, default=5.0, help="raw mode: seconds per batch and per Jev call (default 5)")
    p.add_argument("--raw-budget", type=int, default=12000, help="raw mode: token ceiling for the packet log per call (default 12000)")
    p.add_argument("--raw-keep-ips", action="store_true", help="raw mode: send real remote addresses instead of opaque endpoint ids")
    p.add_argument("--no-heartbeat", action="store_true", help="do not send the per-second multicast packet that keeps nfstream expiring idle flows on quiet vifs")
    p.add_argument("--headless", action="store_true", help="no TUI; print one JSON line per vif per tick")
    p.add_argument("--show-shape", action="store_true", help="with --headless, include the rendered shape text")
    p.add_argument("--quiet", action="store_true", help="with --headless, print nothing per tick (state file only)")
    p.add_argument("--attach", type=Path, default=None, help="TUI only: read snapshots from this state file")
    p.add_argument("--state-file", type=Path, default=None, help="write a JSON snapshot here every tick (for --attach)")
    p.add_argument("--dry-run", action="store_true", help="never call Jev; use a fake client")
    p.add_argument("--api-key", default=None, help="TypeSafe API key (default: $TYPESAFE_API_KEY)")
    p.add_argument("--model", default=MODEL)
    p.add_argument("--population", type=int, default=DEFAULT_POPULATION, help="population for the anonymity-set figure")
    p.add_argument("--log", type=Path, default=None, help="log file (default: stderr in --headless, none in TUI)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def settings_from(args: argparse.Namespace) -> Settings:
    s = Settings()
    if args.catalog:
        s.catalog_path = args.catalog
    s.pcap = args.pcap
    s.pcap_speed = args.speed
    s.interfaces = args.interface
    s.local_nets = args.local_net
    s.heartbeat = not args.no_heartbeat
    s.raw = args.raw
    s.raw_batch_s = args.raw_batch
    s.raw_budget_tokens = args.raw_budget
    s.raw_keep_ips = args.raw_keep_ips
    s.self_capture = args.self_capture
    s.self_iface = args.self_iface
    s.include_own = args.include_own_traffic
    s.dry_run = args.dry_run
    s.headless = args.headless
    s.state_file = args.state_file
    s.population = args.population
    s.api_key = args.api_key
    s.model = args.model
    return s


def setup_logging(args: argparse.Namespace) -> None:
    level = logging.DEBUG if args.verbose else logging.INFO
    if args.log:
        logging.basicConfig(filename=str(args.log), level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    elif args.headless:
        logging.basicConfig(stream=sys.stderr, level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, handlers=[logging.NullHandler()])


async def run_headless(engine: Engine, show_shape: bool, quiet: bool = False) -> None:
    def hook(session, answer, events) -> None:
        if quiet:
            for e in events:  # transitions are still worth a journal line
                log.info("%s %s %s %.2f", session.vif, e.kind, engine.display_name(e.activity), e.probability)
            return
        snap = engine.snapshot()["vifs"].get(session.vif, {})
        line = {k: v for k, v in snap.items() if k not in ("shape_text", "confidence_history", "intensity_history")}
        line["vif"] = session.vif
        top = engine.snapshot()
        line["tokens_per_s"] = top["tokens_per_s"]
        line["tokens_in_total"] = top["tokens_in"]
        line["answered_this_tick"] = answer is not None
        line["new_events"] = [(e.kind, engine.display_name(e.activity), round(e.probability, 3)) for e in events]
        if show_shape:
            line["shape_text"] = snap.get("shape_text")
        print(json.dumps(line), flush=True)

    engine.on_update(hook)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, engine.stop)
    await engine.run()


async def run_tui(engine: Engine) -> None:
    from .ui import ProfilerApp

    app = ProfilerApp(engine.snapshot, on_quit=engine.stop)
    engine_task = asyncio.create_task(engine.run())
    try:
        await app.run_async()
    finally:
        engine.stop()
        try:
            await asyncio.wait_for(engine_task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            engine_task.cancel()


def _reset_signals_in_child() -> None:
    """nfstream forks its meter processes from our thread; without this they
    inherit asyncio's no-op SIGTERM/SIGINT handlers and cannot be terminated
    politely."""
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (ValueError, OSError):
            pass


os.register_at_fork(after_in_child=_reset_signals_in_child)


def _hard_exit(code: int) -> None:
    """nfstream runs its meters as multiprocessing children that block in
    libpcap; multiprocessing's atexit handler would join them forever. Stop
    them explicitly and leave without running atexit hooks."""
    children = multiprocessing.active_children()
    log.debug("shutdown: %d meter processes: %s", len(children), [c.pid for c in children])
    for child in children:
        child.terminate()
    for child in children:
        child.join(timeout=2)
        if child.is_alive():
            log.debug("shutdown: pid %s ignored SIGTERM, killing", child.pid)
            child.kill()
            child.join(timeout=2)
    log.debug("shutdown: still alive: %s", [c.pid for c in multiprocessing.active_children()])
    sys.stdout.flush()
    sys.stderr.flush()
    logging.shutdown()
    os._exit(code)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args)
    if args.attach:
        from .ui import ProfilerApp, file_provider

        ProfilerApp(file_provider(args.attach), refresh_s=1.0).run()
        return 0
    settings = settings_from(args)
    if args.dump_questions:
        from .catalog import load_catalog
        from .jev import FakeJevClient

        print(json.dumps(FakeJevClient(load_catalog(settings.catalog_path)).questions_json(), indent=2))
        return 0
    engine = Engine(settings)
    code = 0
    try:
        if args.headless:
            asyncio.run(run_headless(engine, args.show_shape, args.quiet))
        else:
            asyncio.run(run_tui(engine))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    except BaseException:  # anything else must still reach _hard_exit
        log.exception("fatal")
        code = 1
    _hard_exit(code)
    return code


if __name__ == "__main__":
    sys.exit(main())

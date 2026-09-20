"""Tick loop: every TICK_SECONDS, reduce each vif's window, ask Jev (unless a
call is still outstanding for that vif, in which case the tick is dropped),
and fold the answer into the per-vif analysis."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from .analysis import Event, VifAnalysis
from .capture import CaptureManager
from .catalog import Activity, load_catalog
from .config import NOUL_EVENT_THRESHOLD, TICK_SECONDS, Settings
from .jev import Answer, FakeJevClient, JevClient, PreviousTop
from .reduce import Measures, assert_numbers_free, describe, measure, render

log = logging.getLogger("netprofiler.engine")


@dataclass
class VifSession:
    vif: str
    analysis: VifAnalysis
    previous: PreviousTop = field(default_factory=PreviousTop)
    prev_measures: Measures | None = None
    shape_text: str = ""
    jev_state: dict = field(default_factory=dict)  # exactly what the last call sent
    status: str = "starting"
    last_error: str | None = None
    excluded: str = ""  # self capture: how many flows were left out and why
    ticks: int = 0
    task: asyncio.Task | None = None


UpdateHook = Callable[[VifSession, Answer | None, list[Event]], None]


class Engine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.catalog: list[Activity] = load_catalog(settings.catalog_path)
        self.by_key = {a.key: a for a in self.catalog}
        self.sessions: dict[str, VifSession] = {}
        self.capture = CaptureManager(settings.interfaces or None, settings.local_nets or None, heartbeat=settings.heartbeat)
        self.capture.on_new_vif = self._on_new_vif
        self._hooks: list[UpdateHook] = []
        self._new_vif_hooks: list[Callable[[str], None]] = []
        self._stop = asyncio.Event()
        key = settings.resolved_api_key()
        if settings.dry_run:
            self.client = FakeJevClient(self.catalog)
        elif not key:
            raise SystemExit("no API key: set TYPESAFE_API_KEY or pass --api-key (or use --dry-run)")
        else:
            self.client = JevClient(key, self.catalog, model=settings.model)

    # -- wiring -----------------------------------------------------------
    def on_update(self, hook: UpdateHook) -> None:
        self._hooks.append(hook)

    def on_new_vif(self, hook: Callable[[str], None]) -> None:
        self._new_vif_hooks.append(hook)

    def _on_new_vif(self, vif: str) -> None:
        if vif not in self.sessions:
            self.sessions[vif] = VifSession(
                vif=vif,
                analysis=VifAnalysis(n_options=len(self.catalog), population=self.settings.population),
            )
        for h in self._new_vif_hooks:
            h(vif)

    def display_name(self, key: str) -> str:
        a = self.by_key.get(key)
        return a.name if a else key

    # -- lifecycle ---------------------------------------------------------
    def start_capture(self) -> None:
        if self.settings.pcap:
            self.capture.add_pcap(self.settings.pcap, self.settings.pcap_speed, loop=False)
            return
        if self.settings.self_capture:
            self.capture.add_self(include_own=self.settings.include_own, iface=self.settings.self_iface)
        if not self.capture.scan(force=True) and not self.settings.self_capture:
            log.info("no vif* interfaces yet (no qube uses this one as NetVM); rescanning every few seconds")

    async def run(self) -> None:
        self.start_capture()
        try:
            while not self._stop.is_set():
                t0 = time.monotonic()
                if self.settings.pcap and self.settings.headless and self._replay_drained():
                    break  # checked before the tick so the last call has had a tick to land
                if not self.settings.pcap:
                    self.capture.scan()
                self.tick()
                self._write_state()
                elapsed = time.monotonic() - t0
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=max(0.05, TICK_SECONDS - elapsed))
                except asyncio.TimeoutError:
                    pass
        finally:
            self.capture.stop_all()
            for s in self.sessions.values():
                if s.task and not s.task.done():
                    s.task.cancel()
            await self.client.close()

    def stop(self) -> None:
        self._stop.set()

    def _replay_drained(self) -> bool:
        """Headless pcap mode: finished once replay ended and the window emptied."""
        for vif, cap in self.capture.captures.items():
            if not getattr(cap, "done", False):
                return False
            if self.capture.windows[vif].snapshot().segs:
                return False
        return all(not (s.task and not s.task.done()) for s in self.sessions.values())

    # -- one tick ----------------------------------------------------------
    def tick(self) -> None:
        self.capture.flush()
        for vif, s in list(self.sessions.items()):
            window = self.capture.windows.get(vif)
            cap = self.capture.captures.get(vif)
            if window is None or cap is None:
                continue
            s.ticks += 1
            view = window.snapshot()
            m = measure(view.segs, view.new_endpoints, view.end_ms, flow_first_seen=view.flow_first_seen)
            shape = describe(m, s.prev_measures)
            s.prev_measures = m
            text = render(shape)
            assert_numbers_free(text)
            s.shape_text = text
            if cap.error and not cap.alive:
                s.status = f"capture error: {cap.error}"[:60]
            elif getattr(cap, "done", False):
                s.status = "replay finished"
            excluded = getattr(cap, "excluded_own", None)
            if excluded is not None:
                s.excluded = f"own {excluded}" + (f" downstream {cap.excluded_downstream}" if cap.excluded_downstream else "")
            if self.client.is_busy(vif):
                s.analysis.note_dropped()
                s.status = "dropped tick (call in flight)"
                self._emit(s, None, [])
                continue
            s.status = "asking"
            s.jev_state = self.client.build_state(text, s.previous)
            s.task = asyncio.get_event_loop().create_task(self._ask(s, s.jev_state))

    async def _ask(self, s: VifSession, state: dict) -> None:
        try:
            answer = await self.client.ask(s.vif, state)
        except Exception as e:
            s.last_error = f"{type(e).__name__}: {e}"[:120]
            s.status = "error"
            log.warning("jev call failed for %s: %s", s.vif, e)
            self._emit(s, None, [])
            return
        if answer is None:
            s.analysis.note_dropped()
            self._emit(s, None, [])
            return
        events = s.analysis.ingest(answer, NOUL_EVENT_THRESHOLD)
        s.previous = PreviousTop(sorted(answer.probabilities.items(), key=lambda kv: kv[1], reverse=True)[:3])
        s.status = "ok"
        s.last_error = None
        self._emit(s, answer, events)

    def _emit(self, s: VifSession, answer: Answer | None, events: list[Event]) -> None:
        for h in self._hooks:
            try:
                h(s, answer, events)
            except Exception:
                log.exception("update hook failed")

    # -- snapshots ---------------------------------------------------------
    def snapshot(self) -> dict:
        out = {"t": time.time(), "catalog_size": len(self.catalog), "vifs": {}}
        for vif, s in self.sessions.items():
            a = s.analysis
            la = a.last_answer
            out["vifs"][vif] = {
                "status": s.status,
                "error": s.last_error,
                "excluded": s.excluded,
                "ticks": s.ticks,
                "answered": a.answered_ticks,
                "dropped": a.dropped_ticks,
                "top": [(self.display_name(k), round(p, 4)) for k, p in a.top_smoothed()],
                "current": self.display_name(la.top) if la else None,
                "confidence": la.confidence if la else None,
                "intensity": la.intensity if la else None,
                "interactivity": la.interactivity if la else None,
                "nouls": la.nouls if la else None,
                "tick_entropy_bits": round(a.tick_entropy, 3),
                "tick_bits": round(a.tick_bits, 3),
                "total_bits": round(a.total_bits, 3),
                "raw_total_bits": round(a.raw_total_bits, 3),
                "episodes": a.episodes,
                "anonymity_set": a.anonymity_set(),
                "confidence_history": list(a.confidence_history),
                "intensity_history": list(a.intensity_history),
                "events": [(e.tick, e.kind, self.display_name(e.activity), round(e.probability, 3)) for e in list(a.events)[-30:]],
                "latency_s": la.latency_s if la else None,
                "shape_text": s.shape_text,
                "jev_state": s.jev_state,
            }
        return out

    def _write_state(self) -> None:
        p: Path | None = self.settings.state_file
        if not p:
            return
        try:
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text(json.dumps(self.snapshot()))
            tmp.replace(p)
        except OSError as e:
            log.warning("state file: %s", e)

"""Textual TUI: one pane per vif, side by side.

Each pane shows the current activity, a bar chart of the top five smoothed
probabilities, sparklines of the last 60 ticks, the transition-event log and a
large accumulating bits-leaked counter with the anonymity set size under it.

The app renders from a snapshot dict (see Engine.snapshot) supplied by a
callable, so it works in-process or attached to a state file.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Callable

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Digits, Footer, Header, Label, RichLog, Sparkline, Static

from .config import HISTORY_TICKS, TOP_N

SnapshotProvider = Callable[[], dict]

BAR_CHARS = " ▏▎▍▌▋▊▉█"


def pane_id(vif: str) -> str:
    """Xen names look like vif12.0; Textual IDs allow only [A-Za-z0-9_-]."""
    return "pane-" + "".join(c if c.isalnum() or c in "-_" else "_" for c in vif)


def bar(fraction: float, width: int) -> str:
    fraction = max(0.0, min(1.0, fraction))
    full = int(fraction * width)
    rem = fraction * width - full
    partial = BAR_CHARS[int(rem * (len(BAR_CHARS) - 1))] if full < width else ""
    return "█" * full + partial


def human_count(n: float) -> str:
    if n < 1000:
        return f"{n:.0f}"
    for unit in ("thousand", "million", "billion", "trillion"):
        n /= 1000.0
        if n < 1000:
            return f"{n:.3g} {unit}"
    return f"{n:.3g} quadrillion"


class VifPane(Vertical):
    DEFAULT_CSS = """
    VifPane { border: round $accent; padding: 0 1; width: 1fr; height: 1fr; }
    VifPane > .title { text-style: bold; color: $accent; }
    VifPane > .status { color: $text-muted; }
    VifPane > .activity { text-style: bold; height: 2; }
    VifPane > .bars { height: 7; }
    VifPane > .sparklabel { color: $text-muted; height: 1; }
    VifPane > Sparkline { height: 2; margin: 0 0 0 0; }
    VifPane > RichLog { height: 1fr; min-height: 4; border: solid $panel; }
    VifPane > Digits { width: 100%; text-align: center; color: $warning; }
    VifPane > .bits { text-align: center; color: $text-muted; }
    VifPane > .anon { text-align: center; text-style: bold; }
    """

    def __init__(self, vif: str) -> None:
        super().__init__(id=pane_id(vif))
        self.vif = vif
        self._logged_events = 0

    def compose(self) -> ComposeResult:
        yield Label(self.vif, classes="title")
        yield Label("starting", classes="status")
        yield Static("—", classes="activity")
        yield Static("", classes="bars")
        yield Label("confidence · last 60 ticks", classes="sparklabel")
        yield Sparkline([0.0] * HISTORY_TICKS, summary_function=max, id="spark-conf")
        yield Label("intensity", classes="sparklabel")
        yield Sparkline([0.0] * HISTORY_TICKS, summary_function=max, id="spark-int")
        yield RichLog(markup=True, wrap=True, max_lines=200, id="events")
        yield Digits("0.0", id="bits")
        yield Label("bits leaked this session", classes="bits")
        yield Label("", classes="anon")

    def update_from(self, v: dict, catalog_size: int) -> None:
        status = v.get("status") or ""
        extra = f"  ticks {v.get('ticks', 0)}  answered {v.get('answered', 0)}  dropped {v.get('dropped', 0)}"
        if v.get("latency_s") is not None:
            extra += f"  jev {v['latency_s']*1000:.0f}ms"
        if v.get("error"):
            extra += f"  [red]{v['error']}[/]"
        self.query_one(".status", Label).update(status + extra)

        cur = v.get("current")
        conf = v.get("confidence")
        inten = v.get("intensity")
        inter = v.get("interactivity")
        if cur:
            line = Text.assemble((cur, "bold"), "  ", (f"conf {conf:.2f}", "dim"))
            line.append(f"\nintensity {inten:.2f}  interactivity {inter:.2f}", style="dim")
            nouls = v.get("nouls") or {}
            flags = [k for k, p in nouls.items() if p >= 0.6]
            if flags:
                line.append("  " + " ".join(flags), style="yellow")
        else:
            line = Text("waiting for first answer…", style="dim")
        self.query_one(".activity", Static).update(line)

        # bar chart (top five, smoothed)
        top = v.get("top") or []
        width = max(10, self.size.width - 30)
        t = Text()
        for name, p in top[:TOP_N]:
            t.append(f"{name[:18]:<18} ", style="bold" if name == cur else "")
            t.append(bar(p, width), style="cyan" if name == cur else "blue")
            t.append(f" {p*100:4.0f}%\n", style="dim")
        self.query_one(".bars", Static).update(t)

        def pad(seq: list[float]) -> list[float]:
            seq = list(seq)[-HISTORY_TICKS:]
            return [0.0] * (HISTORY_TICKS - len(seq)) + seq

        self.query_one("#spark-conf", Sparkline).data = pad(v.get("confidence_history") or [])
        self.query_one("#spark-int", Sparkline).data = pad(v.get("intensity_history") or [])

        # event log: append only what we have not shown yet
        events = v.get("events") or []
        log = self.query_one("#events", RichLog)
        if len(events) < self._logged_events:  # engine restarted
            log.clear()
            self._logged_events = 0
        for tick, kind, activity, p in events[self._logged_events :]:
            colour = {"just_started": "green", "just_ended": "red", "someone_is_typing": "magenta", "automated": "yellow"}.get(kind, "white")
            log.write(f"[dim]#{tick:>4}[/] [{colour}]{kind:<17}[/] {activity} [dim]{p:.2f}[/]")
        self._logged_events = len(events)

        bits = float(v.get("total_bits") or 0.0)
        self.query_one("#bits", Digits).update(f"{bits:.1f}")
        tick_bits = v.get("tick_bits") or 0.0
        ent = v.get("tick_entropy_bits") or 0.0
        self.query_one(".bits", Label).update(
            f"bits leaked · {v.get('episodes', 0)} episodes · this tick {tick_bits:.2f}/{math.log2(max(2, catalog_size)):.2f} · H {ent:.2f} · raw {float(v.get('raw_total_bits') or 0):.0f}"
        )
        anon = v.get("anonymity_set")
        if anon is not None:
            self.query_one(".anon", Label).update(f"anonymity set ≈ {human_count(anon)}")


class ProfilerApp(App):
    TITLE = "net-qube traffic profiler"
    CSS = """
    #panes { height: 1fr; }
    #empty { content-align: center middle; height: 1fr; color: $text-muted; }
    """
    BINDINGS = [("q", "quit", "Quit"), ("s", "toggle_shape", "Show shape text")]

    def __init__(self, provider: SnapshotProvider, refresh_s: float = 0.5, on_quit: Callable[[], None] | None = None) -> None:
        super().__init__()
        self._provider = provider
        self._refresh = refresh_s
        self._on_quit = on_quit
        self._show_shape = False
        self._last: dict = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Horizontal(id="panes")
        yield Static("waiting for vif* interfaces…", id="empty")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(self._refresh, self.refresh_panes)

    def refresh_panes(self) -> None:
        try:
            snap = self._provider()
        except Exception as e:  # state file mid-write, etc.
            self.sub_title = f"snapshot error: {e}"
            return
        self._last = snap
        vifs = snap.get("vifs", {})
        panes = self.query_one("#panes", Horizontal)
        empty = self.query_one("#empty", Static)
        empty.display = not vifs
        for vif in vifs:
            if not panes.query(f"#{pane_id(vif)}"):
                panes.mount(VifPane(vif))
        for vif, v in vifs.items():
            try:
                panes.query_one(f"#{pane_id(vif)}", VifPane).update_from(v, snap.get("catalog_size", 2))
            except Exception as e:
                self.log.error(f"pane update failed for {vif}: {e!r}")
        total = sum(float(v.get("total_bits") or 0) for v in vifs.values())
        self.sub_title = f"{len(vifs)} vif · {total:.1f} bits total"
        if self._show_shape and vifs:
            first = next(iter(vifs.values()))
            self.notify(first.get("shape_text", "")[:600], title="shape text (first vif)", timeout=4)
            self._show_shape = False

    def action_toggle_shape(self) -> None:
        self._show_shape = True

    async def action_quit(self) -> None:
        if self._on_quit:
            self._on_quit()
        self.exit()


def file_provider(path: Path) -> SnapshotProvider:
    def read() -> dict:
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            return {"vifs": {}}

    return read

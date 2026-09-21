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
import time
from pathlib import Path
from typing import Callable

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
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
    VifPane > .error { color: $error; text-style: bold; display: none; }
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
        self._logged_error: str | None = None

    def compose(self) -> ComposeResult:
        yield Label("self (this qube's apps on eth0)" if self.vif == "self" else self.vif, classes="title")
        yield Label("starting", classes="status")
        yield Static("", classes="error")
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
        if v.get("excluded"):
            extra += f"  excluded {v['excluded']}"
        if v.get("errors"):
            extra += f"  [red]errors {v['errors']}[/]"
        self.query_one(".status", Label).update(status + extra)

        # API errors get their own wrapped line and a log entry, never a cropped tail
        err = self.query_one(".error", Static)
        message = v.get("error")
        if message:
            age = time.time() - float(v.get("error_at") or time.time())
            err.update(Text(f"Jev call failed {age:.0f} s ago: {message}", style="bold red"))
            err.display = True
            if message != self._logged_error:
                self.query_one("#events", RichLog).write(f"[red]jev error:[/] {message}")
                self._logged_error = message
        else:
            err.display = False

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
    """Panes side by side. Keys: 1-9 show only that interface, a show all,
    x hide the selected interface, d toggle the raw Jev input, q quit."""

    TITLE = "net-qube traffic profiler"
    CSS = """
    #panes { height: 1fr; }
    #empty { content-align: center middle; height: 1fr; color: $text-muted; }
    #raw { height: 45%; border: round $secondary; padding: 0 1; display: none; }
    #raw > .rawtitle { color: $secondary; text-style: bold; height: 1; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("a", "show_all", "All interfaces"),
        ("x", "hide_selected", "Hide selected"),
        ("d", "toggle_raw", "Raw Jev input"),
    ] + [(str(i), f"select({i})", f"#{i}") for i in range(1, 10)]

    def __init__(self, provider: SnapshotProvider, refresh_s: float = 0.5, on_quit: Callable[[], None] | None = None) -> None:
        super().__init__()
        self._provider = provider
        self._refresh = refresh_s
        self._on_quit = on_quit
        self._last: dict = {}
        self._order: list[str] = []  # interfaces in first-seen order; number keys index this
        self._selected: str | None = None  # None = all
        self._hidden: set[str] = set()
        self._show_raw = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Horizontal(id="panes")
        yield Static("waiting for vif* interfaces…", id="empty")
        with VerticalScroll(id="raw"):
            yield Label("", classes="rawtitle")
            yield Static("", id="rawbody")
        yield Footer()

    # -- interface selection ------------------------------------------------
    def _visible(self, vif: str) -> bool:
        if vif in self._hidden:
            return False
        return self._selected is None or vif == self._selected

    def action_select(self, n: int) -> None:
        if 1 <= n <= len(self._order):
            self._selected = self._order[n - 1]
            self._hidden.discard(self._selected)
            self.refresh_panes()

    def action_show_all(self) -> None:
        self._selected = None
        self._hidden.clear()
        self.refresh_panes()

    def action_hide_selected(self) -> None:
        target = self._selected or (self._order[0] if self._order else None)
        if target is None:
            return
        self._hidden.add(target)
        self._selected = None
        self.refresh_panes()

    def action_toggle_raw(self) -> None:
        self._show_raw = not self._show_raw
        self.query_one("#raw").display = self._show_raw
        self.refresh_panes()

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
        if not vifs:
            if snap.get("_missing"):
                empty.update(f"no state file at {snap['_missing']}\nis the service running?  systemctl status netprofiler")
            elif snap.get("t") and time.time() - snap["t"] > 10:
                empty.update(f"state file is {time.time() - snap['t']:.0f} s old: the service has stopped writing\njournalctl -u netprofiler")
            else:
                empty.update("service running, no vif* interfaces yet\nnothing uses this qube as its NetVM; start a qube that does")
        for vif in vifs:
            if vif not in self._order:
                self._order.append(vif)
            if not panes.query(f"#{pane_id(vif)}"):
                panes.mount(VifPane(vif))
        for vif, v in vifs.items():
            try:
                pane = panes.query_one(f"#{pane_id(vif)}", VifPane)
                pane.display = self._visible(vif)
                pane.update_from(v, snap.get("catalog_size", 2))
            except Exception as e:
                self.log.error(f"pane update failed for {vif}: {e!r}")
        total = sum(float(v.get("total_bits") or 0) for v in vifs.values())
        keys = "  ".join(f"{i+1}:{name}" + ("" if self._visible(name) else " (hidden)") for i, name in enumerate(self._order))
        self.sub_title = f"{snap.get('mode', 'shape')} mode · {snap.get('tokens_per_s', 0)} tok/s · {len(vifs)} interface(s) · {total:.1f} bits total · {keys}"
        if self._show_raw:
            target = self._selected or next((n for n in self._order if self._visible(n)), None)
            v = vifs.get(target or "", {})
            self.query_one(".rawtitle", Label).update(f"raw input to Jev for {target}: the `state` of the last call (questions are static: netprofiler --dump-questions)")
            self.query_one("#rawbody", Static).update(render_state(v.get("jev_state") or {}) if v else "")

    async def action_quit(self) -> None:
        if self._on_quit:
            self._on_quit()
        self.exit()


def render_state(state: dict) -> str:
    """The `state` dict as it is sent, but with text fields shown as text
    (newlines rendered) rather than as JSON-escaped strings."""
    parts = []
    for key, value in state.items():
        if isinstance(value, str):
            parts.append(f"{key}:\n{value}")
        else:
            parts.append(f"{key}:\n{json.dumps(value, indent=2)}")
    return "\n\n".join(parts)


def file_provider(path: Path) -> SnapshotProvider:
    def read() -> dict:
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            return {"vifs": {}, "_missing": str(path)}

    return read

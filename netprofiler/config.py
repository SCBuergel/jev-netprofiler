"""Tunables shared across the profiler. Everything is a plain constant so the
reducer, the capture layer and the UI agree on window and tick sizes."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Timing (seconds)
WINDOW_SECONDS = 10.0  # rolling window reduced on every tick
TICK_SECONDS = 2.0  # reduction + Jev call cadence
ACTIVE_TIMEOUT = 2  # nfstream: cut long flows every 2s so they land in the window
IDLE_TIMEOUT = 2  # nfstream: expire quiet flows after 2s
SPLT_ANALYSIS = 10  # nfstream: first N packets' sizes/directions/IATs per flow
VIF_SCAN_SECONDS = 3.0  # how often /sys/class/net is rescanned for new vif*

# Interfaces
VIF_PREFIX = "vif"
FORBIDDEN_INTERFACES = frozenset({"eth0", "lo"})  # never captured, ever

# Heartbeat. nfstream only expires idle flows when a packet arrives on the
# interface, so a short burst followed by silence would stay invisible. One
# tiny UDP packet per second to an organisation-local multicast group, sent
# out of each vif, keeps the meter clock moving; the downstream kernel drops
# it (nothing has joined the group) and the capture filters it out.
HEARTBEAT_SECONDS = 1.0
HEARTBEAT_GROUP = "239.192.255.254"
HEARTBEAT_PORT = 65530

# Model
MODEL = "jev-1.13.0"
CATALOG_MAX = 255  # Choice accepts up to 255 options
CATALOG_PATH_DEFAULT = Path(__file__).resolve().parent.parent / "activities.yaml"

# Display / analysis
HISTORY_TICKS = 60  # sparkline length
TOP_N = 5  # bars shown
SMOOTHING_SPAN_TICKS = 4  # EMA span for displayed probabilities
SMOOTHING_ALPHA = 2.0 / (SMOOTHING_SPAN_TICKS + 1)  # 0.4
PREVIOUS_TOP_K = 3  # previous-tick answers carried into state
NOUL_EVENT_THRESHOLD = 0.6  # a transition Noul above this is logged as an event
DEFAULT_POPULATION = 8_000_000_000  # anonymity set = population / 2**bits

API_KEY_ENV = "TYPESAFE_API_KEY"


@dataclass
class Settings:
    catalog_path: Path = CATALOG_PATH_DEFAULT
    pcap: Path | None = None
    pcap_speed: float = 1.0
    interfaces: list[str] = field(default_factory=list)  # explicit override
    local_nets: list[str] = field(default_factory=list)  # CIDRs of the downstream side (orientation override)
    heartbeat: bool = True  # send the idle-expiry heartbeat on each captured vif
    self_capture: bool = False  # also profile this qube's own apps on eth0
    self_iface: str = "eth0"  # interface for --self (override only for testing)
    include_own: bool = False  # debugging: do not exclude the profiler's own flows
    raw: bool = False  # raw-packet mode: tcpdump log instead of the reduced description
    raw_batch_s: float = 5.0  # one Jev call per interface every this many seconds
    raw_budget_tokens: int = 12000  # ceiling for the packet log per call
    dry_run: bool = False  # reduce and print, never call Jev
    headless: bool = False  # no TUI; log ticks as JSON lines to stdout
    state_file: Path | None = None  # JSON snapshot written every tick
    population: int = DEFAULT_POPULATION
    api_key: str | None = None
    model: str = MODEL

    def resolved_api_key(self) -> str | None:
        return self.api_key or os.environ.get(API_KEY_ENV) or None

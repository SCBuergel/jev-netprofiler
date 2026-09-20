"""Entropy, bit accounting and smoothing. All pure Python, all in-process.

Bits leaked per tick = log2(N) - H(p): how far Jev's activity distribution is
from a uniform prior over the N catalog entries.

Session accounting is per *episode*: when the top activity changes, that
tick's bits are added in full (a new observation about what the person is
doing). While the same activity persists, only any further increase over the
episode's running maximum is added, so a ten-minute idle stretch counts once,
not three hundred times. Episodes are detected on the *smoothed* (4-tick EMA)
top activity, so a single-tick flap does not open a new one. `raw_total_bits`
keeps the plain per-tick sum for comparison.

Anonymity set = population / 2**bits, floored at one person.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field

from .config import HISTORY_TICKS, SMOOTHING_ALPHA, TOP_N
from .jev import Answer


def shannon_entropy_bits(probabilities: dict[str, float]) -> float:
    total = sum(p for p in probabilities.values() if p > 0)
    if total <= 0:
        return 0.0
    h = 0.0
    for p in probabilities.values():
        if p > 0:
            q = p / total
            h -= q * math.log2(q)
    return h


def identifying_bits(probabilities: dict[str, float], n_options: int) -> float:
    if n_options <= 1:
        return 0.0
    return max(0.0, math.log2(n_options) - shannon_entropy_bits(probabilities))


def anonymity_set(population: int, bits: float) -> float:
    return max(1.0, population / (2.0**bits))


@dataclass
class Event:
    tick: int
    kind: str  # just_started / just_ended / automated / someone_is_typing
    activity: str
    probability: float


@dataclass
class VifAnalysis:
    """Per-vif accumulated analysis state fed by successive Answers."""

    n_options: int
    population: int
    alpha: float = SMOOTHING_ALPHA
    tick: int = 0
    smoothed: dict[str, float] = field(default_factory=dict)
    last_top: str | None = None
    last_answer: Answer | None = None
    tick_bits: float = 0.0
    tick_entropy: float = 0.0
    total_bits: float = 0.0
    raw_total_bits: float = 0.0  # plain per-tick sum, for reference
    episode_max_bits: float = 0.0
    episodes: int = 0
    confidence_history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_TICKS))
    intensity_history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_TICKS))
    events: deque = field(default_factory=lambda: deque(maxlen=200))
    noul_state: dict[str, bool] = field(default_factory=dict)  # edge detection for events
    answered_ticks: int = 0
    dropped_ticks: int = 0

    def ingest(self, a: Answer, noul_threshold: float) -> list[Event]:
        self.tick += 1
        self.answered_ticks += 1
        self.last_answer = a

        # EMA over ~4 ticks for display; keys missing from the answer decay
        keys = set(self.smoothed) | set(a.probabilities)
        for k in keys:
            prev = self.smoothed.get(k, 0.0)
            cur = a.probabilities.get(k, 0.0)
            self.smoothed[k] = prev + self.alpha * (cur - prev)
        smoothed_top = max(self.smoothed.items(), key=lambda kv: kv[1])[0]

        # Entropy and bits; episodes open on the smoothed top, not the raw one
        self.tick_entropy = shannon_entropy_bits(a.probabilities)
        self.tick_bits = identifying_bits(a.probabilities, self.n_options)
        self.raw_total_bits += self.tick_bits
        if self.last_top is None or smoothed_top != self.last_top:
            self.episodes += 1
            self.episode_max_bits = self.tick_bits
            self.total_bits += self.tick_bits
        elif self.tick_bits > self.episode_max_bits:
            self.total_bits += self.tick_bits - self.episode_max_bits
            self.episode_max_bits = self.tick_bits
        self.last_top = smoothed_top

        self.confidence_history.append(a.confidence)
        self.intensity_history.append(a.intensity)

        # Rising-edge detection on transition Nouls -> event log entries
        new_events: list[Event] = []
        for kind, p in a.nouls.items():
            on = p >= noul_threshold
            was = self.noul_state.get(kind, False)
            if on and not was:
                ev = Event(tick=self.tick, kind=kind, activity=a.top, probability=p)
                self.events.append(ev)
                new_events.append(ev)
            self.noul_state[kind] = on
        return new_events

    def note_dropped(self) -> None:
        self.dropped_ticks += 1

    def top_smoothed(self, n: int = TOP_N) -> list[tuple[str, float]]:
        return sorted(self.smoothed.items(), key=lambda kv: kv[1], reverse=True)[:n]

    def anonymity_set(self) -> float:
        return anonymity_set(self.population, self.total_bits)

"""Activity catalog: name + one-line flow-shape description per entry."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .config import CATALOG_MAX

_KEY_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class Activity:
    key: str  # option name sent to Jev and returned in answers
    name: str  # display name
    shape: object  # the option's criteria: a one-line string, or a mapping of named fields


def _key(name: str) -> str:
    return _KEY_RE.sub("_", name.strip().lower()).strip("_")


def load_catalog(path: Path) -> list[Activity]:
    raw = yaml.safe_load(path.read_text())
    entries = raw.get("activities") if isinstance(raw, dict) else raw
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: expected a non-empty 'activities' list")
    out: list[Activity] = []
    seen: set[str] = set()
    for e in entries:
        if not isinstance(e, dict) or "name" not in e or "shape" not in e:
            raise ValueError(f"{path}: every entry needs 'name' and 'shape': {e!r}")
        k = _key(str(e["name"]))
        if not k or k in seen:
            raise ValueError(f"{path}: duplicate or empty activity name {e['name']!r}")
        seen.add(k)
        shape = e["shape"]
        if isinstance(shape, dict):
            shape = {str(f): (" ".join(str(v).split()) if isinstance(v, str) else v) for f, v in shape.items()}
        else:
            shape = " ".join(str(shape).split())
        out.append(Activity(key=k, name=str(e["name"]).strip(), shape=shape))
    if len(out) > CATALOG_MAX:
        raise ValueError(f"{path}: {len(out)} activities; Choice allows at most {CATALOG_MAX}")
    return out


def criteria(catalog: list[Activity]) -> dict[str, object]:
    return {a.key: a.shape for a in catalog}

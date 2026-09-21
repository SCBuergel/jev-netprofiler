"""Offline evaluation of question sets against recorded, labelled states.

A dataset is a `--show-shape` headless run (`ds_<tag>.jsonl`) plus its
scenario log (`ds_scen_<tag>.log`). Each tick's recorded `jev_state` is
re-sent to Jev with the question set under test (previous answers reset to
"none yet" so variants are compared on identical inputs), and accuracy and
the mean probability on the expected activity are reported per scenario.

    python tools/eval_questions.py --data DIR --tags shape,raw,rawips \\
        --catalog tools/questions/v1.yaml --instructions v1 --every 4
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netprofiler.catalog import load_catalog  # noqa: E402
from netprofiler.jev import INTENSITY_LEVELS, INTERACTIVITY_LEVELS, NOUL_QUESTIONS, build_questions  # noqa: E402

EXPECT = {"browsing": "web_browsing", "download": "large_file_download", "upload": "large_file_upload", "wallet": "wallet_polling_rpc",
          "chat": "chat", "torrent": "torrent", "ssh_typing": "ssh", "idle": "idle"}
WARMUP_S = 12


def load_dataset(data: Path, tag: str, every: int) -> list[dict]:
    tl = []
    for line in open(data / f"ds_scen_{tag}.log"):
        m = re.match(r"(\d\d):(\d\d):(\d\d) (\w+) for", line)
        if m:
            h, mi, s, name = m.groups()
            tl.append((int(h) * 3600 + int(mi) * 60 + int(s), name))
    rows = [json.loads(l) for l in open(data / f"ds_{tag}.jsonl") if l.strip()]
    first = open(data / f"ds_scen_{tag}.log").readline()[:8]
    h, mi, s = map(int, first.split(":"))
    t0 = h * 3600 + mi * 60 + s - 5
    starts: dict[str, list[int]] = defaultdict(list)
    for ts, name in tl:
        starts[name].append(ts)

    def label(secs):
        cur = "pre"
        for ts, name in tl:
            if secs >= ts:
                cur = name
        return cur

    out = []
    for i, r in enumerate(rows):
        t = t0 + i * 2
        sc = label(t)
        if sc == "pre" or not r.get("jev_state"):
            continue
        st = max(x for x in starts[sc] if x <= t)
        if t - st < WARMUP_S:
            continue
        out.append({"tag": tag.split("_")[0], "scenario": sc, "expected": EXPECT[sc], "state": r["jev_state"], "tick": r["ticks"]})
    return out[::every]


def instructions_variant(name: str) -> dict:
    from importlib import import_module

    mod = import_module(f"tools.questions.instructions_{name}")
    return mod.ACTIVITY_INSTRUCTIONS


async def evaluate(samples: list[dict], catalog_path: Path, instr: str, concurrency: int) -> tuple[list[dict], int]:
    from typesafe_sdk import AsyncTypeSafeClient, Choice, Score, Noul

    catalog = load_catalog(catalog_path)
    questions = build_questions(catalog)
    if instr != "v0":
        questions["activity"] = Choice(instructions=instructions_variant(instr), criteria={a.key: a.shape for a in catalog})
    sem = asyncio.Semaphore(concurrency)
    tokens = 0
    results = []

    async def one(sample):
        nonlocal tokens
        state = dict(sample["state"])
        for k in ("previous_window_top_answers", "previous_batch_top_answers"):
            if k in state:
                state[k] = "none yet"
        async with sem:
            resp = await client.system_one(state=state, questions=questions)
        a = resp.answers["activity"]
        tokens += resp.usage.input_tokens or 0
        results.append({**{k: v for k, v in sample.items() if k != "state"}, "choice": a.choice, "p_expected": a.probabilities.get(sample["expected"], 0.0), "confidence": a.confidence})

    async with AsyncTypeSafeClient(model="jev-1.13.0", timeout=30) as client:
        await asyncio.gather(*(one(s) for s in samples))
    return results, tokens


def report(results: list[dict], tags: list[str]) -> None:
    order = ["browsing", "download", "upload", "wallet", "chat", "torrent", "ssh_typing", "idle"]
    print(f"{'scenario':<11}" + "".join(f"| {t:<30}" for t in tags))
    totals = {t: [0, 0, 0.0] for t in tags}
    for sc in order:
        cells = []
        for t in tags:
            rs = [r for r in results if r["tag"] == t and r["scenario"] == sc]
            if not rs:
                cells.append("-")
                continue
            acc = sum(r["choice"] == r["expected"] for r in rs) / len(rs)
            p = sum(r["p_expected"] for r in rs) / len(rs)
            top = Counter(r["choice"] for r in rs).most_common(1)[0][0]
            cells.append(f"{acc:.0%} p={p:.2f} ({top}, n={len(rs)})")
            if sc != "idle":
                totals[t][0] += sum(r["choice"] == r["expected"] for r in rs)
                totals[t][1] += len(rs)
                totals[t][2] += sum(r["p_expected"] for r in rs)
        print(f"{sc:<11}" + "".join(f"| {c:<30}" for c in cells))
    print(f"{'ALL(non-idle)':<11}" + "".join(f"| acc {v[0]/max(1,v[1]):.0%}  mean p {v[2]/max(1,v[1]):.2f}      " for v in totals.values()))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, required=True)
    ap.add_argument("--tags", default="shape,raw,rawips")
    ap.add_argument("--catalog", type=Path, default=Path("tools/questions/v0.yaml"))
    ap.add_argument("--instructions", default="v0")
    ap.add_argument("--every", type=int, default=4)
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--save", type=Path, default=None)
    ap.add_argument("--scenarios", default=None, help="comma-separated subset of scenarios")
    ap.add_argument("--summary-field", action="store_true", help="raw states: move the summary line into its own state field")
    args = ap.parse_args()
    tags = args.tags.split(",")
    samples = [s for t in tags for s in load_dataset(args.data, t, args.every)]
    tags = list(dict.fromkeys(t.split("_")[0] for t in tags))  # report per mode
    if args.scenarios:
        keep = set(args.scenarios.split(","))
        samples = [s for s in samples if s["scenario"] in keep]
    if args.summary_field:
        for s in samples:
            log = s["state"].get("packet_log")
            if log and log.startswith("summary:"):
                first, _, rest = log.partition("\n")
                s["state"] = {"legend": s["state"]["legend"], "summary": first[len("summary: "):], "packet_log": rest, **{k: v for k, v in s["state"].items() if k not in ("legend", "packet_log")}}
    print(f"{len(samples)} samples, catalog {args.catalog}, instructions {args.instructions}")
    results, tokens = asyncio.run(evaluate(samples, args.catalog, args.instructions, args.concurrency))
    report(results, tags)
    print(f"input tokens: {tokens}")
    if args.save:
        args.save.write_text(json.dumps(results))


if __name__ == "__main__":
    main()

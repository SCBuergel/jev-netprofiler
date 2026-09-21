# jev-netprofiler

Shows what a network gateway can tell about you from traffic *shape* alone.

It watches the network interfaces of a Qubes OS net-qube, turns each ten
seconds of flow metadata into a short text made only of level words (no
addresses, ports, sizes or timestamps), asks TypeSafe's Jev model which
activity from a small catalog that shape looks like, and displays the answer
in a terminal UI with a running count of identifying bits. Jev never sees a
number; all arithmetic is local Python. Addresses and ports are hashed with
a per-process salt the moment a packet or flow record is parsed and are
never stored, in either mode.

![terminal UI](docs/screenshot.png)

## Target environment

- A Qubes OS qube with `provides_network=True` (a net-qube): every downstream
  qube's `vif*` interface gets a pane. The qube's own applications can be
  profiled too (self mode, on `eth0`), with the profiler's own traffic left
  out.
- Any other Linux box in self mode: `netprofiler --self --self-iface <iface>`.
- Root is needed for packet capture. Python 3.11+ (template needs
  `python3-venv`, or `uv` in the qube). libpcap is bundled in the nfstream
  wheel.
- A TypeSafe API key (`TYPESAFE_API_KEY`).

## Install on a Qubes net-qube

1. In the template: `sudo apt install python3 python3-venv git`, shut it
   down, restart the net-qube. (Alternative without touching the template:
   `curl -LsSf https://astral.sh/uv/install.sh | sh` inside the qube.)
2. In the qube:
   ```sh
   git clone https://github.com/SCBuergel/jev-netprofiler.git
   cd jev-netprofiler
   echo 'TYPESAFE_API_KEY=...' > .env
   sudo ./install.sh
   ```
   This puts everything under `/rw/config/netprofiler`, starts a systemd
   service (`--headless --self`), and hooks `/rw/config/rc.local` so it
   survives reboots. `SELF=0 sudo ./install.sh` skips self mode.
3. Watch it:
   ```sh
   sudo /rw/config/netprofiler/venv/bin/netprofiler --attach /run/netprofiler/state.json
   ```
   Panes appear as soon as a qube using this one as NetVM starts.

## Activities

idle, unknown, web browsing, ssh, software updates, chat, wallet polling
rpc, torrent, large file upload, large file download, claude code.

Edit `activities.yaml` to change them (name plus a one-line shape
description, up to 255 entries).

## Terminal UI

One pane per interface: current activity with confidence, top-five bar
chart, sparklines of confidence and intensity over the last 60 ticks, an
event log (`just_started`, `just_ended`, `automated`, `someone_is_typing`),
the bits-leaked counter and the anonymity set it implies.

Keys: `1`..`9` show only that interface, `x` hide the selected one, `a` show
all, `d` toggle a panel with the exact `state` sent to Jev for the selected
pane, `q` quit. The questions are static; `netprofiler --dump-questions`
prints them.

## Run by hand

```sh
uv venv .venv && uv pip install -p .venv/bin/python -e '.[dev]'
export TYPESAFE_API_KEY=...

sudo -E .venv/bin/netprofiler                    # net-qube mode, TUI
sudo -E .venv/bin/netprofiler --self             # plus this qube's own apps
.venv/bin/netprofiler --pcap file.pcap --speed 2 # replay a capture offline
.venv/bin/netprofiler --headless --show-shape --pcap file.pcap --dry-run   # no API calls
.venv/bin/pytest
```

`--include-own-traffic` keeps the profiler's own Jev calls in the self pane
(they read as `wallet polling rpc`, which is the point of excluding them).
`--self-iface` picks the interface for self mode (default `eth0`).
`--local-net CIDR` sets which side of a flow is the downstream qube when the
SYN direction and private/public split cannot tell. `--no-heartbeat` stops
the one-packet-per-second multicast keepalive that lets nfstream expire idle
flows on a silent vif.

## How it works

Every 2 s per interface: nfstream flow segments from the last 10 s are
reduced to statistics (flows, endpoints, direction, bursts and gaps, packet
sizes, spacing, transport, trend), each mapped to a word, rendered into
about 700 tokens of prose with a guard against digits. Burst start times are also kept for a
minute per interface so the text can say whether bursts come at a regular
or a human-looking rhythm over a longer horizon than one window. One Jev
call fans out a Choice over the catalog, Scores for intensity and
interactivity, and four Nouls. One call in flight per interface; a tick arriving while one is
outstanding is dropped. Shannon entropy of the Choice distribution gives
bits = log2(N) - H; bits accumulate once per activity episode (episodes
follow the 4-tick smoothed top answer); anonymity set = population / 2^bits.

## Raw-packet mode (experimental, this branch)

`--raw` replaces the reduced description with a filtered packet log.
`tcpdump -nn -tt -q -l -s 96` records headers only (payload is never
captured), one line per packet; every `--raw-batch` seconds (default 5) the
last `--raw-window` seconds (default: the batch) are encoded and sent as the
state. Columns kept: time (as the delay since the previous line), flow id,
direction, payload length; a flow table gives protocol and an opaque
endpoint id, and a summary line gives flow, endpoint, packet, byte and pause
counts plus how many flows opened during the window and lived under 2 s.
Pure TCP acks are counted per flow rather than listed. The text is kept
under `--raw-budget` tokens (default 12000) by a ladder: verbatim lines,
then run-length encoding of identical packets, then 100 ms and 500 ms
per-flow bins, then truncation. Jev tokenizes these digit-heavy lines at
about one token per character, so a verbatim line costs ~11 tokens.

`--raw-ips` is a third, opt-in mode that keeps the real local and remote
addresses and ports in the flow table. In the other two modes addresses and
ports are hashed with a per-process salt while a record is parsed and never
stored.

## Question tuning

In TypeSafe terms the "prompt" is the question set: the Choice question's
`instructions`, each catalog option's `criteria` (the `shape` entries in
`activities.yaml`), and the Score levels and Noul criteria. The state
framing (the raw legend and summary line) is the other lever. All modes use
the same questions.

`tools/eval_questions.py` re-asks Jev on recorded, labelled states (a
`--show-shape` run plus its scenario log), with the previous-answer field
reset, so question variants are compared on identical inputs.
`tools/questions/` holds the variants:

- v0: the original one-line shape descriptions.
- v1: a rigid decision procedure plus structured criteria with cues for
  both input forms. Helped torrent, broke wallet: it tied wallet-vs-chat to
  a rhythm word the reducer gets wrong as often as right.
- v2: v0 wording, a note that the state may be prose or a packet log, three
  tie-break hints, and `not_for` contrasts on the bulk/torrent/browsing
  group.
- v3: v2 with wallet, chat and ssh rewritten from the reducer's *observed*
  words. The original text had them inverted: a real wallet poll is a short
  TLS exchange of medium packets every few seconds with an irregular
  rhythm; an IRC client is nearly silent with clock-like keepalives.
- v4 (shipped): v3 plus packet-log cues for browsing vs download (flows
  that all open and end within two seconds vs one flow alive all window).

Offline accuracy on the same recorded windows (top answer, non-idle
scenarios; chat and ssh-typing counted as in the table below):

| set | shape | raw (10 s window) | raw with addresses |
|---|---|---|---|
| v0 | 52 % | 54 % | 62 % |
| v3 | 82 % | 66 % | 74 % |
| v4 | 82 % | 71 % | 79 % |

Per scenario with v4 (accuracy, mean probability on the right answer):

| scenario | shape | raw | raw with addresses |
|---|---|---|---|
| web browsing | 100 %, 0.87 | 40 %, 0.28 | 60 %, 0.37 |
| large file download | 100 %, 1.00 | 100 %, 1.00 | 100 %, 1.00 |
| large file upload | 100 %, 0.98 | 100 %, 0.99 | 100 %, 0.99 |
| wallet polling rpc | 100 %, 0.99 | 100 %, 0.87 | 83 %, 0.80 |
| chat (IRC) | 50 %, 0.46 | 50 %, 0.24 | 38 %, 0.26 |
| torrent | 75 %, 0.51 | 100 %, 0.77 | 100 %, 0.98 |
| ssh typing | 75 %, 0.75 | 0 %, 0.13 | 80 %, 0.72 |

What the remaining errors are: the chat misses are windows in which the
IRC client sent nothing (the state says no flows); the torrent misses in
shape mode are windows where one peer carried nearly all bytes; the raw
ssh failure comes from the test itself, whose typing session runs without a
tty so the server only ever receives keystrokes and sends bare acks, which
a packet log reads as inbound data (the reducer's cadence word is
direction-agnostic and survives it). Addresses help raw mode mostly on
ssh and browsing; their cost is that every destination is sent to Jev.

Cost per mode (one call every 2 s, measured live): shape ~1,000 tok/s;
raw with a 10 s window ~2,100 tok/s; raw with addresses about the same
plus the address text. The v4 questions add ~18 % to every call over v0.

## Local test rig

`tools/fake_qube.py` plays a downstream qube on a veth pair (`vif99.0` on
the host, `qube0` in a network namespace) with scripted scenarios; the
docstring has the setup and teardown commands.

## What it gets right, and not

Tested on a public Ubuntu server in self mode with real traffic: web
browsing 0.9, large file download 0.99, large file upload 0.99, ssh with
`someone_is_typing` 0.8, wallet polling an RPC 0.9 (once a minute of rhythm
has built up), torrent 0.98 at first and then alternating with large file
download as the client settles on one fast peer, software updates recognised
at the start and then read as a large download once the sustained fetch
dominates. Chat (IRC, a line every few seconds) is the weak spot: one tiny
burst every few seconds on one flow looks the same as a polling wallet at
this granularity, and it mostly reads as `wallet polling rpc`. Claude Code
is in the catalog but was not tested on the server.

Unsolicited inbound noise on a public address (port scans answered with a
reset, unanswered UDP, pings) is filtered before the window; a Qubes qube
behind NAT never sees it.

## Limits

- nfstream expires idle flows only when a packet arrives on the interface;
  the heartbeat exists for that. The window ends 2.25 s behind the present
  because the newest segment of an ongoing flow is still inside nfstream.
- Burst structure is estimated from 2 s flow segments; sub-segment timing
  comes only from each segment's first ten packets.
- The profiler's own DNS lookups are not excluded from the self pane (one
  per new connection, tiny).
- Level thresholds in `netprofiler/levels.py` were set by hand.

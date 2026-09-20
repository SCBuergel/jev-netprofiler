# netprofiler

Traffic profiler for a Qubes OS net-qube. It captures flow metadata on every
`vif*` interface (one downstream qube each), describes the traffic shape of
the last ten seconds in words, asks TypeSafe's Jev model which catalogued
activity that shape resembles, and shows the result in a terminal UI together
with a running count of identifying bits.

Jev receives text made of level words only ("download-dominated",
"keystroke-like", "brief idle gaps"). No addresses, ports, byte counts,
timestamps or packet counts leave the qube. Every calculation (bucketing,
entropy, bit accounting, smoothing) is done in Python; Jev only maps a
described shape to an activity name. `eth0` is never captured.

## How it works

Every two seconds, per vif:

1. nfstream flow records from the last 10 s (flows are cut every 2 s by
   `active_timeout=2`, so long flows arrive as 2 s segments) are reduced to
   statistics: active flows, endpoints and first-contact endpoints, byte and
   packet direction, throughput and packet-rate level, burst and idle
   structure at 250 ms resolution, packet-size distribution, inter-arrival
   spacing and regularity, transport mix, trend against the previous window.
2. Each statistic becomes a named level (`netprofiler/levels.py`) and the
   levels are rendered into a text block of roughly 700 tokens. A guard
   refuses to send any text containing a digit.
3. One `system_one` call to `jev-1.13.0` with that text and the previous
   tick's top three answers (as `strong / likely / possible / faint`). The
   call fans out seven questions: a Choice over the activity catalog, Scores
   for intensity and interactivity, and Nouls for `just_started`,
   `just_ended`, `automated` and `someone_is_typing`. At most one call is in
   flight per vif; a tick that arrives while one is outstanding is dropped.
4. From the Choice distribution: Shannon entropy, bits = log2(N) - H, an
   exponential moving average over four ticks for display, and rising-edge
   detection on the Nouls (threshold 0.6) for the event log.

Bits accumulate per episode. When the smoothed top activity changes, that
tick's bits are added in full; while it persists, only further sharpening
beyond the episode's running maximum is added, so ten minutes of idle count
once. The anonymity set shown is `population / 2^bits` with a default
population of 8 billion (`--population`). The plain per-tick sum is shown as
`raw` for comparison. Both figures treat episodes as independent observations,
which makes them an upper bound.

## Install on the net-qube

The qube's template needs python3 3.11 or newer with the venv module, and
git to clone with. On a Debian template:

```sh
sudo apt install python3 python3-venv git
```

then shut the template down and restart the net-qube. libpcap is bundled in
the nfstream wheel, so no capture library is needed. If you would rather not
touch the template, install uv in the qube's home instead
(`curl -LsSf https://astral.sh/uv/install.sh | sh`); the installer uses it
when present.

In the qube:

```sh
git clone https://github.com/SCBuergel/jev-netprofiler.git
cd jev-netprofiler
echo 'TYPESAFE_API_KEY=...' > .env
sudo ./install.sh
```

The script copies the package to `/rw/config/netprofiler`, creates a venv
there (with `uv` if present, else `python3 -m venv`), writes the API key to
`/rw/config/netprofiler/env` (from `$TYPESAFE_API_KEY`, else `./.env`, else a
placeholder to edit), generates the systemd unit, links it into
`/etc/systemd/system`, appends a hook to `/rw/config/rc.local` that re-links
it on every boot, and starts the service. Running it again is harmless.

The service runs as root (libpcap needs `CAP_NET_RAW`), captures every
`vif*`, calls Jev, writes `/run/netprofiler/state.json` each tick and logs
transitions to the journal. To watch it:

```sh
sudo /rw/config/netprofiler/venv/bin/netprofiler --attach /run/netprofiler/state.json
```

A disposable net-qube has no persistent `/rw`; install into its template
instead.

## Run by hand

```sh
uv venv .venv && uv pip install -p .venv/bin/python -e '.[dev]'
export TYPESAFE_API_KEY=...            # or put it in .env

sudo -E .venv/bin/netprofiler          # capture vif*, call Jev, TUI in one process
.venv/bin/netprofiler --pcap file.pcap --speed 2   # replay a capture as one vif at 2x, real Jev calls
.venv/bin/netprofiler --pcap file.pcap --dry-run   # no API calls, fake answers
.venv/bin/netprofiler --headless --show-shape --pcap file.pcap   # JSON per tick, includes the text Jev sees
.venv/bin/pytest                       # needs neither libpcap nor network
```

Other flags: `-i vif3.0` to capture only named interfaces (`eth0` is refused
even if listed), `--local-net CIDR` to state which side of a flow is the
downstream qube when the SYN direction and private/public address split
cannot tell, `--no-heartbeat` (see limits), `--catalog`, `--model`,
`--state-file`, `--quiet`, `--log`.

The TUI shows one pane per vif side by side: current activity with
confidence, intensity and interactivity; a bar chart of the top five smoothed
probabilities; sparklines of confidence and intensity over the last 60 ticks;
the event log; the bits counter with the anonymity set under it. Keys: `q`
quit, `s` show the current shape text.

## Activity catalog

`activities.yaml` holds up to 255 entries, each a `name` and a one-line
`shape`. The shape lines are the Choice option descriptions Jev sees, so
write them in the reducer's vocabulary (flows, direction, bursts, packet
sizes, spacing, idle gaps, endpoints, transport) and never mention ports or
services. Keep `idle` and `unknown`; they are the no-match outcomes.

The shipped catalog has 30 entries in three groups: everyday activities for
contrast (browsing, streaming, calls, messaging, ssh, downloads, package and
dependency fetches, torrents), privacy tooling (VPN, Tor browsing, a mixnet
node with cover traffic) and Ethereum (node initial sync, node following the
chain, validator attesting, block proposal, wallet polling an RPC endpoint,
sending a transaction, a DeFi swap in a browser dapp, an NFT mint rush, an
MEV bot, a websocket block subscription).

## Local test without a downstream qube

`tools/fake_qube.py` stands in for a qube on a veth pair. The host end is
named `vif99.0`; the peer lives in a network namespace on an isolated
`10.137.99.0/24` link, so `eth0`, routing and DNS are untouched. The one host
change is an nftables rule limited to `vif99.0` in Qubes' `custom-input`
chain, because the default input policy drops new connections.

```sh
sudo ip netns add npf
sudo ip link add vif99.0 type veth peer name qube0 netns npf
sudo ip addr add 10.137.99.1/24 dev vif99.0 && sudo ip link set vif99.0 up
sudo ip -n npf addr add 10.137.99.2/24 dev qube0 && sudo ip -n npf link set qube0 up && sudo ip -n npf link set lo up
sudo nft add rule ip qubes custom-input iifname "vif99.0" accept

python tools/fake_qube.py serve &
sudo -E .venv/bin/netprofiler -i vif99.0 --local-net 10.137.99.2/32
sudo ip netns exec npf python tools/fake_qube.py play      # all scenarios, about five minutes
sudo ip netns exec npf python tools/fake_qube.py play node wallet sendtx   # or a selection

sudo ip netns del npf
sudo nft -a list chain ip qubes custom-input               # note the handle, then
sudo nft delete rule ip qubes custom-input handle <n>
```

Scenarios: typing, download, call, browsing, node (eight peer flows with
gossip and a burst every 12 s slot), wallet (an RPC poll every 4 s), mevbot,
sendtx (quiet, one short burst, quiet). On these Jev answers `ssh
interactive session` (with `someone_is_typing` around 0.9), `video
streaming`, `video call`, `web browsing`, `ethereum node following the
chain`, `wallet polling an rpc endpoint`, `mev bot` and `sending a
transaction from a wallet`, each at confidence 0.8 to 0.99 once the window
has filled. The download reads as streaming because its read-and-sleep
throttle really does produce 2 s bursts.

## Limits

- nfstream expires an idle flow only when a packet arrives on the interface.
  To keep short bursts followed by silence visible (a wallet sending one
  transaction, say), the profiler sends one 44-byte UDP packet per second out
  of each captured vif to the multicast group 239.192.255.254, which the
  downstream kernel drops and the capture filters out. `--no-heartbeat`
  turns this off; a burst then surfaces only when the next packet arrives.
- The analysed window ends 2.25 s behind the present, since an ongoing flow's
  newest segment is still inside nfstream.
- Burst and gap structure is estimated by spreading each 2 s segment's
  packets evenly over its lifetime. Sub-segment timing comes only from the
  first ten packets of each segment.
- The catalog is the whole hypothesis space. Level thresholds in
  `netprofiler/levels.py` were set by hand on synthetic traffic and may need
  adjusting for real links.

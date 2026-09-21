"""Activity Choice instructions, variant v1: a decision procedure that works
on either a prose shape description or a headers-only packet log."""

ACTIVITY_INSTRUCTIONS = {
    "question": "Which catalogued activity best explains the traffic in the state?",
    "input": (
        "The state is either a prose description of traffic shape in level words, or a headers-only packet log "
        "with a summary line, a flow table and per-packet lines (delay since the previous line in ms, flow id with "
        "direction, payload bytes; pure acks are counted, not listed). Read whichever form is present."
    ),
    "procedure": [
        "Almost no packets, only a handful of tiny ones with long silence: idle.",
        "One flow carrying nearly everything as full-size packets (around 1400 bytes) back to back for seconds: large file download if inbound, large file upload if outbound.",
        "Dozens of flows to dozens of endpoints active at the same time, traffic spread across them: torrent.",
        "A burst of many new short flows to several endpoints within a second or two, then seconds of quiet, then another burst: web browsing. If instead a few flows fetch large amounts of data one after another with machine-like pacing and no pauses: software updates.",
        "Otherwise there is one or a few long-lived flows with small packets; decide by rhythm: tiny outbound packets under 100 bytes at uneven gaps of roughly 80 to 500 ms, each answered within tens of ms, is ssh; one small exchange every few seconds at even, clock-like spacing is wallet polling rpc; small exchanges at uneven spacing, sometimes a few in a row, then long pauses, is chat; several long-lived flows where a large outbound burst is followed by a stream of small inbound packets lasting seconds is claude code.",
        "unknown only when traffic is clearly present and fits none of the above.",
    ],
    "continuity": "Previous top answers may be given; keep the same answer when the traffic has not meaningfully changed, switch when it has.",
}

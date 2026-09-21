"""Activity Choice instructions, variant v3: v2 with the small-flow tie-break
rewritten from observed traffic (a wallet poll is a multi-packet TLS
exchange; a chat client mostly shows keepalives)."""

ACTIVITY_INSTRUCTIONS = {
    "question": "Which catalogued activity best explains the traffic in the state?",
    "input": (
        "The state is either a prose description of traffic shape in level words, or a headers-only packet log "
        "with a summary line, a flow table and per-packet lines. Read whichever form is present."
    ),
    "focus": "Judge from shape: how many flows and endpoints, how long they live, direction, burst structure, packet sizes, inter-arrival rhythm, idle gaps.",
    "tie_breaks": [
        "Many flows to many endpoints active at once with bytes spread across them is torrent, even when the volume is high; a single dominant flow is a download or upload.",
        "A burst of many new short-lived flows to several endpoints followed by seconds of quiet is web browsing, even when the burst moves a lot of data; a few flows fetching file after file without pauses is software updates.",
        "One or a few long-lived flows of tiny packets with a keystroke-like uneven cadence is ssh. A single flow that wakes every few seconds for a short rapid exchange of medium-sized packets and is otherwise sporadic is wallet polling rpc. A single flow that is almost silent, with at most one tiny burst per window and machine-like regular keepalives, is chat, not idle: idle has no flow at all.",
    ],
    "continuity": "Previous top answers may be given; keep the same answer when the traffic has not meaningfully changed, switch when it has.",
}

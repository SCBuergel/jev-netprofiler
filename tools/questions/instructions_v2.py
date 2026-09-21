"""Activity Choice instructions, variant v2: v0's question with an input
note for both forms and two tie-break hints, no rigid procedure."""

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
        "A single long-lived flow of tiny packets is ssh when the outbound packets come at an uneven human rhythm, wallet polling rpc when there is one small exchange every few seconds and nothing else, chat when small exchanges come irregularly and sometimes a few together.",
    ],
    "continuity": "Previous top answers may be given; keep the same answer when the traffic has not meaningfully changed, switch when it has.",
}

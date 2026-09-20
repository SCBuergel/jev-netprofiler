"""Local test harness: a fake downstream qube on a veth pair.

Setup (root; nothing here touches eth0, the default route or DNS):

    ip netns add npf
    ip link add vif99.0 type veth peer name qube0 netns npf
    ip addr add 10.137.99.1/24 dev vif99.0 && ip link set vif99.0 up
    ip -n npf addr add 10.137.99.2/24 dev qube0 && ip -n npf link set qube0 up && ip -n npf link set lo up
    nft add rule ip qubes custom-input iifname "vif99.0" accept   # Qubes' input policy is drop

Then, in three terminals:

    python tools/fake_qube.py serve                       # host side: servers on 10.137.99.1
    sudo -E .venv/bin/netprofiler -i vif99.0 --local-net 10.137.99.2/32
    sudo ip netns exec npf python tools/fake_qube.py play  # inside the namespace: all scenarios
    sudo ip netns exec npf python tools/fake_qube.py play claudecode wallet   # or just some
    (`call` is kept as an out-of-catalog scenario: it should come out as unknown)

Teardown:

    ip netns del npf            # takes qube0 and therefore vif99.0 with it
    nft -a list chain ip qubes custom-input   # then: nft delete rule ip qubes custom-input handle <n>

Stdlib only so it runs inside the bare namespace.
"""

from __future__ import annotations

import http.server
import os
import random
import socket
import socketserver
import sys
import threading
import time
import urllib.request

HOST = "10.137.99.1"
ECHO_PORT = 2222  # ssh-like
HTTP_PORTS = (8080, 8081, 8082)  # three "web endpoints"
UDP_PORT = 5000  # call-like
RPC_PORT = 8545  # "rpc endpoint" (echo)
LLM_PORT = 7777  # "model api": takes an upload, streams a response
BIG = 64 * 1024 * 1024


# ---------------------------------------------------------------- servers --
class _Echo(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class _Http(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a) -> None:  # quiet
        pass

    def do_GET(self) -> None:
        if self.path.startswith("/big"):
            size = BIG
        else:
            size = random.randint(2_000, 60_000)
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.end_headers()
        chunk = os.urandom(65536)
        left = size
        try:
            while left > 0:
                n = min(left, len(chunk))
                self.wfile.write(chunk[:n])
                left -= n
        except BrokenPipeError:
            pass


class _Llm(socketserver.StreamRequestHandler):
    """Reads `<8-byte length><upload>` and streams a response in small chunks
    at token-like intervals, like a model API answering a coding agent."""

    def handle(self) -> None:
        while True:
            hdr = self.rfile.read(8)
            if len(hdr) < 8:
                return
            n = int.from_bytes(hdr, "big")
            self.rfile.read(n)
            time.sleep(random.uniform(0.5, 2.0))  # time to first token
            end = time.time() + random.uniform(4, 15)
            try:
                while time.time() < end:
                    self.wfile.write(os.urandom(random.randint(120, 450)))
                    self.wfile.flush()
                    time.sleep(random.uniform(0.02, 0.09))
                self.wfile.write(b"\0" * 8)  # end marker
                self.wfile.flush()
            except BrokenPipeError:
                return


def _udp_responder() -> None:
    """A call peer: on first packet from a client, stream back at the same
    rate independently (real calls are two unsynchronised streams, not echo)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, UDP_PORT))
    last_seen: dict = {}

    def stream(addr, size):
        period = 1.0 / 50
        nxt = time.time()
        while time.time() - last_seen.get(addr, 0) < 1.0:
            s.sendto(os.urandom(size + random.randint(-20, 20)), addr)
            nxt += period + random.uniform(-0.002, 0.002)
            time.sleep(max(0.0, nxt - time.time()))
        last_seen.pop(addr, None)

    while True:
        data, addr = s.recvfrom(4096)
        new = addr not in last_seen
        last_seen[addr] = time.time()
        if new:
            threading.Thread(target=stream, args=(addr, len(data)), daemon=True).start()


def serve() -> None:
    socketserver.TCPServer.allow_reuse_address = True
    threads = [
        threading.Thread(target=socketserver.ThreadingTCPServer((HOST, ECHO_PORT), _Echo).serve_forever, daemon=True),
        threading.Thread(target=_udp_responder, daemon=True),
    ]
    for p in HTTP_PORTS:
        srv = http.server.ThreadingHTTPServer((HOST, p), _Http)
        threads.append(threading.Thread(target=srv.serve_forever, daemon=True))
    threads.append(threading.Thread(target=socketserver.ThreadingTCPServer((HOST, RPC_PORT), _Echo).serve_forever, daemon=True))
    threads.append(threading.Thread(target=socketserver.ThreadingTCPServer((HOST, LLM_PORT), _Llm).serve_forever, daemon=True))
    for t in threads:
        t.start()
    print(f"serving echo:{ECHO_PORT} http:{HTTP_PORTS} udp:{UDP_PORT} on {HOST}", flush=True)
    while True:
        time.sleep(3600)


# -------------------------------------------------------------- scenarios --
def _say(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def typing(seconds: float) -> None:
    """ssh-like: one long-lived TCP flow, 36-byte keystrokes at human intervals, echoed back."""
    _say(f"typing for {seconds:.0f}s")
    s = socket.create_connection((HOST, ECHO_PORT))
    s.settimeout(2)
    end = time.time() + seconds
    while time.time() < end:
        s.sendall(os.urandom(36))
        s.recv(4096)
        # bursts of keystrokes with occasional thinking pauses
        time.sleep(random.uniform(0.08, 0.45) if random.random() > 0.08 else random.uniform(1.0, 2.5))
    s.close()


def download(seconds: float, rate_bps: float = 2_500_000) -> None:
    """one dominant download flow, throttled by reading slowly."""
    _say(f"download for {seconds:.0f}s")
    r = urllib.request.urlopen(f"http://{HOST}:{HTTP_PORTS[0]}/big", timeout=10)
    end = time.time() + seconds
    chunk = 32768
    while time.time() < end:
        t0 = time.time()
        if not r.read(chunk):
            break
        time.sleep(max(0.0, chunk / rate_bps - (time.time() - t0)))
    r.close()


def call(seconds: float, pps: float = 50, size: int = 200) -> None:
    """UDP ping-pong at a fixed rate: balanced, regular, medium packets."""
    _say(f"call for {seconds:.0f}s")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.05)
    end = time.time() + seconds
    period = 1.0 / pps
    nxt = time.time()
    while time.time() < end:
        s.sendto(os.urandom(size + random.randint(-20, 20)), (HOST, UDP_PORT))
        nxt += period + random.uniform(-0.002, 0.002)  # a little jitter
        while time.time() < nxt:  # drain whatever arrived meanwhile
            try:
                s.recvfrom(4096)
            except socket.timeout:
                break
        time.sleep(max(0.0, nxt - time.time()))
    s.close()


def browsing(seconds: float) -> None:
    """bursts of many short requests to several endpoints, then reading pauses."""
    _say(f"browsing for {seconds:.0f}s")
    end = time.time() + seconds
    while time.time() < end:
        n = random.randint(6, 14)
        ths = []
        for i in range(n):
            port = random.choice(HTTP_PORTS)

            def fetch(port=port, i=i):
                try:
                    urllib.request.urlopen(f"http://{HOST}:{port}/asset{i}", timeout=5).read()
                except Exception:
                    pass

            t = threading.Thread(target=fetch)
            t.start()
            ths.append(t)
            time.sleep(random.uniform(0.02, 0.2))
        for t in ths:
            t.join()
        time.sleep(random.uniform(3.0, 7.0))  # reading


def _rpc_roundtrip(s: socket.socket, size: int) -> None:
    s.sendall(os.urandom(size))
    got = 0
    while got < size:
        chunk = s.recv(65536)
        if not chunk:
            break
        got += len(chunk)



def claudecode(seconds: float) -> None:
    """coding agent: upload a large prompt, read a streamed reply, pause, repeat."""
    _say(f"claudecode for {seconds:.0f}s")
    s = socket.create_connection((HOST, LLM_PORT))
    s.settimeout(30)
    end = time.time() + seconds
    while time.time() < end:
        n = random.randint(20_000, 90_000)
        s.sendall(n.to_bytes(8, "big") + os.urandom(n))
        tail = b""
        while not tail.endswith(b"\0" * 8):
            chunk = s.recv(65536)
            if not chunk:
                return
            tail = (tail + chunk)[-8:]
        time.sleep(random.uniform(2, 8))  # reading, tool calls, typing the next turn
    s.close()


def wallet(seconds: float, every: float = 4.0) -> None:
    """wallet polling an rpc endpoint: a tiny request/response every few seconds."""
    _say(f"wallet for {seconds:.0f}s")
    s = socket.create_connection((HOST, RPC_PORT))
    s.settimeout(2)
    end = time.time() + seconds
    while time.time() < end:
        for _ in range(random.randint(1, 3)):
            _rpc_roundtrip(s, random.randint(120, 400))
        time.sleep(every)
    s.close()




def idle(seconds: float) -> None:
    _say(f"idle for {seconds:.0f}s")
    time.sleep(seconds)


SCRIPT = [
    (idle, 8),
    (typing, 30),
    (idle, 12),
    (download, 25),
    (idle, 12),
    (browsing, 35),
    (idle, 12),
    (claudecode, 45),
    (idle, 12),
    (wallet, 30),
    (idle, 10),
]


def play(names: list[str]) -> None:
    steps = SCRIPT if not names else [(globals()[n], 25) for n in names]
    for fn, secs in steps:
        try:
            fn(secs)
        except Exception as e:
            _say(f"{fn.__name__} failed: {e!r}")
    _say("script finished")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("serve", "play"):
        print(__doc__)
        sys.exit(2)
    if sys.argv[1] == "serve":
        serve()
    else:
        play(sys.argv[2:])

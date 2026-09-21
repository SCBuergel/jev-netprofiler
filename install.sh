#!/bin/bash
# Install netprofiler on a Qubes net-qube. Run as root from the project dir:
#
#     sudo ./install.sh
#
# Copies the package to /rw/config/netprofiler, builds a venv there, installs
# the systemd unit, hooks /rw/config/rc.local so the unit is re-linked at every
# boot (an AppVM's /etc is not persistent), and starts the service.
#
# Needs python3 >= 3.11 that can create a venv with pip (Debian: the
# python3-venv package in the template), or uv in the qube, tcpdump (the
# default capture mode), plus network access to fetch wheels. libpcap for
# shape mode is bundled in the nfstream wheel.
# The API key is taken from TYPESAFE_API_KEY, else from ./.env, else you are
# asked to edit the env file afterwards.
#
# Options:
#     SELF=0              do not profile this qube's own applications on eth0
#                         (default SELF=1: the service runs with --self as well
#                         as capturing any vif*; its own Jev traffic is excluded)
# Overrides (for testing or unusual layouts):
#     DEST=/some/dir      install location   (default /rw/config/netprofiler)
#     RC_LOCAL=/some/file rc.local to hook    (default /rw/config/rc.local)
#     NO_SYSTEMD=1        skip unit link, daemon-reload and start
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${DEST:-/rw/config/netprofiler}"
RC_LOCAL="${RC_LOCAL:-/rw/config/rc.local}"
NO_SYSTEMD="${NO_SYSTEMD:-}"
SELF="${SELF:-1}"
UNIT=netprofiler.service
SELF_FLAG=""; [ "$SELF" = "1" ] && SELF_FLAG=" --self"

die() { echo "install.sh: $*" >&2; exit 1; }
step() { echo ">> $*"; }

if [ -z "$NO_SYSTEMD" ] && [ "$(id -u)" -ne 0 ]; then
    die "run as root (sudo ./install.sh), or set NO_SYSTEMD=1 for a user-only install"
fi

# --- preflight ---------------------------------------------------------------
command -v python3 >/dev/null || die "python3 not found; install python3 in the template"
command -v tcpdump >/dev/null || die "tcpdump not found; install it in the template (apt install tcpdump): the default capture mode needs it"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "python3 >= 3.11 required, found $(python3 --version 2>&1)"
# uv if available (also under the invoking user's home when run via sudo),
# else python3 -m venv, which on Debian needs python3-venv for pip.
UV="$(command -v uv || true)"
[ -z "$UV" ] && [ -n "${SUDO_USER:-}" ] && [ -x "/home/$SUDO_USER/.local/bin/uv" ] && UV="/home/$SUDO_USER/.local/bin/uv"
if [ -z "$UV" ] && ! python3 -c 'import ensurepip' 2>/dev/null; then
    cat >&2 <<'MSG'
install.sh: python3 cannot create a venv with pip (no ensurepip module).
  Either, in the template:   sudo apt install python3-venv
          then shut the template down and restart this qube,
  or, in this qube only:     curl -LsSf https://astral.sh/uv/install.sh | sh
          then run install.sh again.
MSG
    exit 1
fi

case "$DEST" in /home/*|/root|/root/*) die "DEST=$DEST is under a home directory, which the unit's ProtectHome hides; install elsewhere (default /rw/config/netprofiler)";; esac

# --- files -------------------------------------------------------------------
step "copying files to $DEST"
mkdir -p "$DEST"
rm -rf "$DEST/netprofiler"
cp -r "$SRC/netprofiler" "$DEST/"
cp "$SRC/activities.yaml" "$SRC/pyproject.toml" "$SRC/README.md" "$DEST/"
mkdir -p "$DEST/tools" && cp "$SRC/tools/fake_qube.py" "$DEST/tools/"
find "$DEST/netprofiler" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

# --- API key -----------------------------------------------------------------
step "API key: $DEST/env"
if [ ! -f "$DEST/env" ]; then
    if [ -n "${TYPESAFE_API_KEY:-}" ]; then
        printf 'TYPESAFE_API_KEY=%s\n' "$TYPESAFE_API_KEY" > "$DEST/env"
    elif [ -f "$SRC/.env" ]; then
        cp "$SRC/.env" "$DEST/env"
    else
        printf 'TYPESAFE_API_KEY=replace_me\n' > "$DEST/env"
        echo ">> no key found: edit $DEST/env and set TYPESAFE_API_KEY" >&2
    fi
fi
chmod 600 "$DEST/env"

# --- venv --------------------------------------------------------------------
if [ -n "$UV" ]; then
    step "creating venv with uv ($UV)"
    [ -x "$DEST/venv/bin/python" ] || "$UV" venv -q -p python3 "$DEST/venv"
    step "installing dependencies (nfstream, numpy, pandas, textual, typesafe-sdk; about 100 MB of wheels)"
    "$UV" pip install -p "$DEST/venv/bin/python" "$DEST" 2>&1 | grep -E '^(Resolved|Prepared|Installed|error|  ×|  ╰)' || true
else
    step "creating venv with python3 -m venv"
    # a venv left over from a failed attempt may exist without pip: rebuild it
    if ! "$DEST/venv/bin/python" -m pip --version >/dev/null 2>&1; then
        rm -rf "$DEST/venv"
        python3 -m venv "$DEST/venv" || die "python3 -m venv failed"
    fi
    step "installing dependencies (nfstream, numpy, pandas, textual, typesafe-sdk; about 100 MB of wheels)"
    "$DEST/venv/bin/python" -m pip install --quiet --upgrade pip
    "$DEST/venv/bin/python" -m pip install --progress-bar off "$DEST" 2>&1 | grep -E '^(Collecting|Downloading|Successfully|ERROR)' || true
fi
"$DEST/venv/bin/netprofiler" --help > /dev/null || die "installed package does not run"
step "installed package runs"
rm -rf "$DEST/build" "$DEST"/*.egg-info

# --- systemd unit --------------------------------------------------------------
step "writing $DEST/$UNIT"
cat > "$DEST/$UNIT" <<EOF
[Unit]
Description=Qubes net-qube traffic profiler (nfstream + Jev)
After=qubes-network.service

[Service]
Type=simple
EnvironmentFile=$DEST/env
WorkingDirectory=$DEST
RuntimeDirectory=netprofiler
ExecStart=$DEST/venv/bin/netprofiler --headless --quiet$SELF_FLAG --catalog $DEST/activities.yaml --state-file /run/netprofiler/state.json --record $DEST/samples.jsonl --label-file /run/netprofiler/label
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/netprofiler $DEST
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# --- rc.local hook (idempotent) ------------------------------------------------
step "hooking $RC_LOCAL"
mkdir -p "$(dirname "$RC_LOCAL")"
touch "$RC_LOCAL"
if ! grep -q "$DEST/$UNIT" "$RC_LOCAL"; then
    cat >> "$RC_LOCAL" <<EOF

# netprofiler: /etc is not persistent in an AppVM, so re-link the unit each boot
if [ -f $DEST/$UNIT ]; then
    ln -sf $DEST/$UNIT /etc/systemd/system/$UNIT
    systemctl daemon-reload
    systemctl start $UNIT
fi
EOF
fi
chmod +x "$RC_LOCAL"

# --- start now ----------------------------------------------------------------
if [ -z "$NO_SYSTEMD" ]; then
    step "starting $UNIT"
    ln -sf "$DEST/$UNIT" "/etc/systemd/system/$UNIT"
    systemctl daemon-reload
    systemctl restart "$UNIT"
    sleep 2
    systemctl --no-pager --lines=0 status "$UNIT" | sed -n '1,3p'
    journalctl -u "$UNIT" --no-pager -n 3 -o cat --since '-30s' 2>/dev/null | sed 's/^/   /'
fi

echo
VIFS="$(ls /sys/class/net 2>/dev/null | grep '^vif' | tr '\n' ' ' || true)"
if [ -n "$VIFS" ]; then
    echo "downstream interfaces now: $VIFS"
else
    echo "no vif* interfaces: nothing is using this qube as its NetVM. Start a qube whose"
    echo "NetVM is this one and a vif appears; the service picks it up within a few seconds."
fi
[ "$SELF" = "1" ] && echo "this qube's own applications are profiled too (pane 'self'); SELF=0 ./install.sh turns that off"
echo "watch it:  sudo $DEST/venv/bin/netprofiler --attach /run/netprofiler/state.json"
echo "record labelled samples: press l in the viewer (or: echo 'web browsing' | sudo tee /run/netprofiler/label); they land in $DEST/samples.jsonl"

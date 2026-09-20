#!/bin/bash
# Install netprofiler on a Qubes net-qube. Run as root from the project dir:
#
#     sudo ./install.sh
#
# Copies the package to /rw/config/netprofiler, builds a venv there, installs
# the systemd unit, hooks /rw/config/rc.local so the unit is re-linked at every
# boot (an AppVM's /etc is not persistent), and starts the service.
#
# Needs: python3 >= 3.11 (plus uv or the venv module), libpcap, and network
# access to fetch wheels.
# The API key is taken from TYPESAFE_API_KEY, else from ./.env, else you are
# asked to edit the env file afterwards.
#
# Overrides (for testing or unusual layouts):
#     DEST=/some/dir      install location   (default /rw/config/netprofiler)
#     RC_LOCAL=/some/file rc.local to hook    (default /rw/config/rc.local)
#     NO_SYSTEMD=1        skip unit link, daemon-reload and start
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${DEST:-/rw/config/netprofiler}"
RC_LOCAL="${RC_LOCAL:-/rw/config/rc.local}"
NO_SYSTEMD="${NO_SYSTEMD:-}"
UNIT=netprofiler.service

if [ -z "$NO_SYSTEMD" ] && [ "$(id -u)" -ne 0 ]; then
    echo "run as root (sudo ./install.sh), or set NO_SYSTEMD=1 for a user-only install" >&2
    exit 1
fi

# --- files -------------------------------------------------------------------
mkdir -p "$DEST"
rm -rf "$DEST/netprofiler"
cp -r "$SRC/netprofiler" "$DEST/"
cp "$SRC/activities.yaml" "$SRC/pyproject.toml" "$SRC/README.md" "$DEST/"
mkdir -p "$DEST/tools" && cp "$SRC/tools/fake_qube.py" "$DEST/tools/"
find "$DEST/netprofiler" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

# --- API key -----------------------------------------------------------------
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
# uv if available (also under the invoking user's home when run via sudo),
# else python3 -m venv (needs the python3-venv package on Debian templates).
UV="$(command -v uv || true)"
[ -z "$UV" ] && [ -n "${SUDO_USER:-}" ] && [ -x "/home/$SUDO_USER/.local/bin/uv" ] && UV="/home/$SUDO_USER/.local/bin/uv"
if [ -n "$UV" ]; then
    [ -x "$DEST/venv/bin/python" ] || "$UV" venv -q "$DEST/venv"
    "$UV" pip install -q -p "$DEST/venv/bin/python" "$DEST"
else
    [ -x "$DEST/venv/bin/python" ] || python3 -m venv "$DEST/venv"
    "$DEST/venv/bin/python" -m pip install --quiet --upgrade pip
    "$DEST/venv/bin/python" -m pip install --quiet "$DEST"
fi
"$DEST/venv/bin/netprofiler" --help > /dev/null
rm -rf "$DEST/build" "$DEST"/*.egg-info

# --- systemd unit --------------------------------------------------------------
cat > "$DEST/$UNIT" <<EOF
[Unit]
Description=Qubes net-qube traffic profiler (nfstream + Jev)
After=qubes-network.service

[Service]
Type=simple
EnvironmentFile=$DEST/env
WorkingDirectory=$DEST
RuntimeDirectory=netprofiler
ExecStart=$DEST/venv/bin/netprofiler --headless --quiet --catalog $DEST/activities.yaml --state-file /run/netprofiler/state.json
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/netprofiler
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# --- rc.local hook (idempotent) ------------------------------------------------
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
    ln -sf "$DEST/$UNIT" "/etc/systemd/system/$UNIT"
    systemctl daemon-reload
    systemctl restart "$UNIT"
    sleep 1
    systemctl --no-pager --lines=0 status "$UNIT" | head -3
fi

echo
echo "installed to $DEST"
echo "watch it:  sudo $DEST/venv/bin/netprofiler --attach /run/netprofiler/state.json"

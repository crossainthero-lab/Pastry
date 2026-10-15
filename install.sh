#!/usr/bin/env bash
# Install Pastry into a virtual environment in this directory.
#   ./install.sh            create .venv and install dependencies
#   ./install.sh --systemd  also install the systemd service (asks for sudo)
#   ./install.sh --lan-systemd  same, but the service serves HTTPS on the LAN (port 8443)
set -euo pipefail

cd "$(dirname "$0")"
HOME_DIR="$(pwd)"
WANT_SYSTEMD=0
UNIT_SRC=deploy/pastry.service
[[ "${1:-}" == "--systemd" ]] && WANT_SYSTEMD=1
if [[ "${1:-}" == "--lan-systemd" ]]; then WANT_SYSTEMD=1; UNIT_SRC=deploy/pastry-lan.service; fi

if ! command -v python3 >/dev/null; then
  echo "python3 is required. On Ubuntu: sudo apt install python3 python3-venv" >&2
  exit 1
fi
PY_OK=$(python3 -c 'import sys; print(int(sys.version_info >= (3, 10)))')
if [[ "$PY_OK" != "1" ]]; then
  echo "Python 3.10 or newer is required." >&2
  exit 1
fi
if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "The venv module is missing. On Ubuntu: sudo apt install python3-venv" >&2
  exit 1
fi

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e . >/dev/null
mkdir -p config data backups
chmod 700 config data backups

echo
echo "Installed. Next steps:"
echo "  1. Create the admin account:   .venv/bin/pastry setup"
echo "  2. Start the server:           .venv/bin/pastry start"
echo "     Then open http://127.0.0.1:8787 in a browser on this machine."

if [[ $WANT_SYSTEMD -eq 1 ]]; then
  UNIT=/etc/systemd/system/pastry.service
  TMP="$(mktemp)"
  sed -e "s|__USER__|$(id -un)|g" -e "s|__GROUP__|$(id -gn)|g" -e "s|__HOME__|$HOME_DIR|g" "$UNIT_SRC" > "$TMP"
  sudo install -m 644 "$TMP" "$UNIT"
  rm -f "$TMP"
  sudo systemctl daemon-reload
  echo "Installed $UNIT. After 'pastry setup' succeeds, run:"
  echo "  sudo systemctl enable --now pastry"
fi

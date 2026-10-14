#!/usr/bin/env bash
# Build the wheel, install it into a clean virtual environment with ONLY the base dependencies,
# and check that the recipient CLI works without the server stack. Used locally and in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PY="${PYTHON:-python3}"

cd "$ROOT"
"$PY" -m pip wheel . --no-deps -w "$WORK/dist" -q
WHEEL="$(ls "$WORK"/dist/*.whl)"
echo "built: $(basename "$WHEEL")"

# The wheel must not carry secrets, databases, fixtures, tests or packages.
if unzip -l "$WHEEL" | grep -E "auth\.json|\.db$|\.pastry$|fixtures/|tests/|release\.key|config/"; then
  echo "unexpected files in the wheel" >&2
  exit 1
fi

"$PY" -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q "$WHEEL"
"$WORK/venv/bin/pastry" --version

# Recipient workflow without the server stack: build a package, inspect it, and confirm the
# server dependencies are genuinely absent.
"$WORK/venv/bin/python" - "$WORK" <<'PY'
import importlib.util, subprocess, sys
from pathlib import Path
from pastry import package as pk
from pastry.crypto import KdfParams

work = Path(sys.argv[1])
for module in ("fastapi", "uvicorn", "jinja2"):
    assert importlib.util.find_spec(module) is None, f"{module} should not be installed for recipients"
data = pk.build_package([{"name": "CI entry", "username": "u", "password": "p" * 12, "notes": "",
                          "url": "", "fields": []}], "correct horse battery", "ci package",
                        allow_copy=False, expires_at=None, kdf=KdfParams(1, 8192, 1))
path = work / "ci.pastry"
path.write_bytes(data)
out = subprocess.run([str(Path(sys.executable).with_name("pastry")), "inspect", str(path)],
                     capture_output=True, text=True, check=True).stdout
assert "ci package" in out and "encrypted" in out and "p" * 12 not in out
header, entries = pk.open_package(data, "correct horse battery")
assert entries[0]["name"] == "CI entry"
print("recipient CLI check passed")
PY

# Starting the server without its extra must fail with a clear message, not a traceback.
if "$WORK/venv/bin/pastry" start 2>"$WORK/start.err"; then
  echo "pastry start unexpectedly succeeded without the server extra" >&2
  exit 1
fi
grep -q "server needs its extra packages" "$WORK/start.err"
echo "wheel verification passed"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== unit + integration tests =="
python3 -m unittest discover -s tests -v

echo
echo "== live smoke scan against fixture (offline, hermetic) =="
VIBESAFE_NO_EPHEMERAL=1 python3 scripts/scan.py --only secrets,sast,iac \
  --out-dir "$(mktemp -d)" tests/fixtures/vulnerable-app

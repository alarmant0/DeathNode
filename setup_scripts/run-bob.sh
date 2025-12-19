#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${DEATHNODE_CLEAN:-0}" == "1" ]]; then
  rm -rf target
fi

NODE_PASS="bob123" \
DEATHNODE_GATEWAY_URL="${DEATHNODE_GATEWAY_URL:-https://10.0.2.10:443}" \
./setup_scripts/run-vm.sh bob

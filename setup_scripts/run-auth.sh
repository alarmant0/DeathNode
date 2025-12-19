#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${DEATHNODE_CLEAN:-0}" == "1" ]]; then
  rm -rf target
fi

AUTH_PASS="${AUTH_PASS:-auth123}" \
CA_PASS="${CA_PASS:-capass123}" \
./setup_scripts/run-vm.sh auth

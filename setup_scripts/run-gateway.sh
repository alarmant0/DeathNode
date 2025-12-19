#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BRANCH="${DEATHNODE_BRANCH:-Security-Challenge-A}"

if [[ "${DEATHNODE_GIT_SYNC:-1}" == "1" ]]; then
  git fetch --all --prune
  git checkout "$BRANCH"
  git pull --ff-only
fi

if [[ "${DEATHNODE_CLEAN:-0}" == "1" ]]; then
  rm -rf target
fi

GATEWAY_PASS="${GATEWAY_PASS:-server}" \
CA_PASS="${CA_PASS:-capass123}" \
DEATHNODE_AUTH_URL="${DEATHNODE_AUTH_URL:-https://10.0.1.20:443}" \
./setup_scripts/run-vm.sh gateway

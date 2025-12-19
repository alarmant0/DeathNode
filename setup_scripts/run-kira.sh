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

NODE_PASS="${NODE_PASS:-kira12}" \
DEATHNODE_GATEWAY_URL="${DEATHNODE_GATEWAY_URL:-https://10.0.2.10:443}" \
./setup_scripts/run-vm.sh kira

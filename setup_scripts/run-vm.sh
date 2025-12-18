#!/usr/bin/env bash
set -euo pipefail

ROLE="${1:-}"

if [[ -z "$ROLE" ]]; then
  echo "Usage: ./setup_scripts/run-vm.sh <auth|gateway|alice|bob|kira>"
  exit 1
fi

repo_root() {
  local d
  d="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  echo "$d"
}

script_dir() {
  echo "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
}

ensure_repo_ca_present() {
  local root ca_ks ca_crt
  root="$(repo_root)"
  ca_ks="$root/certs/ca/ca.p12"
  ca_crt="$root/certs/ca/ca.crt"
  if [[ -f "$ca_ks" && -f "$ca_crt" ]]; then
    return 0
  fi
  echo "Missing repo CA under certs/ca/." >&2
  echo "Run on your machine (once): ./setup_scripts/ca-generate.sh" >&2
  echo "Then commit + push certs/ca/ and re-clone on VMs." >&2
  return 1
}

cd "$(repo_root)"

SCRIPTS="$(script_dir)"

case "$ROLE" in
  auth)
    ensure_repo_ca_present
    AUTH_PASS="${AUTH_PASS:-auth123}" CA_PASS="${CA_PASS:-capass123}" "$SCRIPTS/auth-setup-tls.sh"
    AUTH_PASS="${AUTH_PASS:-auth123}" "$SCRIPTS/auth-start.sh"
    ;;

  gateway)
    ensure_repo_ca_present
    GATEWAY_PASS="${GATEWAY_PASS:-server}" CA_PASS="${CA_PASS:-capass123}" "$SCRIPTS/gateway-setup-tls.sh"
    mkdir -p "$HOME/certs"
    GATEWAY_PASS="${GATEWAY_PASS:-server}" CA_CRT_PATH="$(repo_root)/certs/ca/ca.crt" "$SCRIPTS/gateway-import-auth-cert.sh"
    GATEWAY_PASS="${GATEWAY_PASS:-server}" "$SCRIPTS/gateway-start.sh"
    ;;

  alice|bob|kira)
    ensure_repo_ca_present
    case "$ROLE" in
      alice) NODE_PASS_DEFAULT="alice12" ;;
      bob) NODE_PASS_DEFAULT="bob123" ;;
      kira) NODE_PASS_DEFAULT="kira12" ;;
    esac
    NODE_PASS="${NODE_PASS:-$NODE_PASS_DEFAULT}"
    mkdir -p "$HOME/certs"
    NODE_PASS="$NODE_PASS" CA_CRT_PATH="$(repo_root)/certs/ca/ca.crt" "$SCRIPTS/node-import-gateway-cert.sh"
    NODE_PASS="$NODE_PASS" "$SCRIPTS/node-start.sh"
    ;;

  *)
    echo "Unknown role: $ROLE" >&2
    echo "Usage: ./setup_scripts/run-vm.sh <auth|gateway|alice|bob|kira>" >&2
    exit 1
    ;;
esac

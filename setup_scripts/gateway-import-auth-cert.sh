#!/usr/bin/env bash
set -euo pipefail

GATEWAY_PASS="${GATEWAY_PASS:-server}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_CRT_PATH="${CA_CRT_PATH:-$ROOT_DIR/certs/ca/ca.crt}"

mkdir -p "$HOME/certs"

keytool -importcert \
  -alias ca \
  -file "$CA_CRT_PATH" \
  -keystore "$HOME/certs/truststore.p12" \
  -storetype PKCS12 \
  -storepass "$GATEWAY_PASS" \
  -noprompt

echo "$HOME/certs/truststore.p12"

#!/usr/bin/env bash
set -euo pipefail

GATEWAY_PASS="${GATEWAY_PASS:-server}"
GATEWAY_IP="${GATEWAY_IP:-10.0.2.10}"
GATEWAY_DNS="${GATEWAY_DNS:-deathnode-gateway}"

CA_PASS="${CA_PASS:-capass123}"

mkdir -p "$HOME/certs"

rm -f \
  "$HOME/certs/gateway.p12" \
  "$HOME/certs/gateway.csr" \
  "$HOME/certs/gateway-signed.crt" \
  >/dev/null 2>&1 || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_KS="$ROOT_DIR/certs/ca/ca.p12"
CA_CRT="$ROOT_DIR/certs/ca/ca.crt"

if [[ ! -f "$CA_KS" || ! -f "$CA_CRT" ]]; then
  echo "Missing CA files in repo: $CA_KS and/or $CA_CRT" >&2
  echo "Run: ./setup_scripts/ca-generate.sh  (and commit/push certs/ca)" >&2
  exit 1
fi

keytool -genkeypair \
  -alias gateway \
  -keyalg RSA -keysize 2048 \
  -storetype PKCS12 \
  -keystore "$HOME/certs/gateway.p12" \
  -storepass "$GATEWAY_PASS" -keypass "$GATEWAY_PASS" \
  -dname "CN=$GATEWAY_DNS" \
  -ext "SAN=IP:$GATEWAY_IP,DNS:$GATEWAY_DNS"

keytool -certreq \
  -alias gateway \
  -keystore "$HOME/certs/gateway.p12" \
  -storetype PKCS12 \
  -storepass "$GATEWAY_PASS" \
  -file "$HOME/certs/gateway.csr" \
  -ext "SAN=IP:$GATEWAY_IP,DNS:$GATEWAY_DNS"

keytool -gencert \
  -alias ca \
  -keystore "$CA_KS" \
  -storetype PKCS12 \
  -storepass "$CA_PASS" \
  -infile "$HOME/certs/gateway.csr" \
  -outfile "$HOME/certs/gateway-signed.crt" \
  -rfc \
  -validity 365 \
  -ext "SAN=IP:$GATEWAY_IP,DNS:$GATEWAY_DNS"

keytool -importcert \
  -alias ca \
  -file "$CA_CRT" \
  -keystore "$HOME/certs/gateway.p12" \
  -storetype PKCS12 \
  -storepass "$GATEWAY_PASS" \
  -noprompt

keytool -importcert \
  -alias gateway \
  -file "$HOME/certs/gateway-signed.crt" \
  -keystore "$HOME/certs/gateway.p12" \
  -storetype PKCS12 \
  -storepass "$GATEWAY_PASS" \
  -noprompt

echo "$HOME/certs/gateway.p12"

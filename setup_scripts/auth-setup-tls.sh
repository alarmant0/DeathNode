#!/usr/bin/env bash
set -euo pipefail

AUTH_PASS="${AUTH_PASS:-auth123}"
AUTH_IP="${AUTH_IP:-10.0.1.20}"
AUTH_DNS="${AUTH_DNS:-blind-auth}"

CA_PASS="${CA_PASS:-capass123}"

mkdir -p "$HOME/certs"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_KS="$ROOT_DIR/certs/ca/ca.p12"
CA_CRT="$ROOT_DIR/certs/ca/ca.crt"

if [[ ! -f "$CA_KS" || ! -f "$CA_CRT" ]]; then
  echo "Missing CA files in repo: $CA_KS and/or $CA_CRT" >&2
  echo "Run: ./setup_scripts/ca-generate.sh  (and commit/push certs/ca)" >&2
  exit 1
fi

keytool -genkeypair \
  -alias auth \
  -keyalg RSA -keysize 2048 \
  -storetype PKCS12 \
  -keystore "$HOME/certs/auth.p12" \
  -storepass "$AUTH_PASS" -keypass "$AUTH_PASS" \
  -dname "CN=$AUTH_DNS" \
  -ext "SAN=IP:$AUTH_IP,DNS:$AUTH_DNS"

keytool -certreq \
  -alias auth \
  -keystore "$HOME/certs/auth.p12" \
  -storetype PKCS12 \
  -storepass "$AUTH_PASS" \
  -file "$HOME/certs/auth.csr" \
  -ext "SAN=IP:$AUTH_IP,DNS:$AUTH_DNS"

keytool -gencert \
  -alias ca \
  -keystore "$CA_KS" \
  -storetype PKCS12 \
  -storepass "$CA_PASS" \
  -infile "$HOME/certs/auth.csr" \
  -outfile "$HOME/certs/auth-signed.crt" \
  -rfc \
  -validity 365 \
  -ext "SAN=IP:$AUTH_IP,DNS:$AUTH_DNS"

keytool -importcert \
  -alias ca \
  -file "$CA_CRT" \
  -keystore "$HOME/certs/auth.p12" \
  -storetype PKCS12 \
  -storepass "$AUTH_PASS" \
  -noprompt

keytool -importcert \
  -alias auth \
  -file "$HOME/certs/auth-signed.crt" \
  -keystore "$HOME/certs/auth.p12" \
  -storetype PKCS12 \
  -storepass "$AUTH_PASS" \
  -noprompt

echo "$HOME/certs/auth.p12"

#!/usr/bin/env bash
set -euo pipefail

CA_PASS="${CA_PASS:-capass123}"
CA_DNS="${CA_DNS:-deathnode-ca}"

repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

ROOT="$(repo_root)"
mkdir -p "$ROOT/certs/ca"

if [[ -f "$ROOT/certs/ca/ca.p12" && -f "$ROOT/certs/ca/ca.crt" ]]; then
  echo "CA already exists: $ROOT/certs/ca/ca.p12"
  echo "CA cert:          $ROOT/certs/ca/ca.crt"
  exit 0
fi

keytool -genkeypair \
  -alias ca \
  -keyalg RSA -keysize 2048 \
  -storetype PKCS12 \
  -keystore "$ROOT/certs/ca/ca.p12" \
  -storepass "$CA_PASS" -keypass "$CA_PASS" \
  -dname "CN=$CA_DNS" \
  -ext bc:c

keytool -exportcert -rfc \
  -alias ca \
  -keystore "$ROOT/certs/ca/ca.p12" -storepass "$CA_PASS" \
  -file "$ROOT/certs/ca/ca.crt"

echo "Created CA keystore: $ROOT/certs/ca/ca.p12"
echo "Created CA cert:     $ROOT/certs/ca/ca.crt"

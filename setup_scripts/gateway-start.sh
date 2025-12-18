#!/usr/bin/env bash
set -euo pipefail

GATEWAY_PASS="${GATEWAY_PASS:-server}"

export DEATHNODE_TLS_KEYSTORE_PATH="$HOME/certs/gateway.p12"
export DEATHNODE_TLS_KEYSTORE_PASSWORD="$GATEWAY_PASS"
export DEATHNODE_TLS_TRUSTSTORE_PATH="$HOME/certs/truststore.p12"
export DEATHNODE_TLS_TRUSTSTORE_PASSWORD="$GATEWAY_PASS"

export DEATHNODE_AUTH_URL="${DEATHNODE_AUTH_URL:-https://10.0.1.20:443}"

mvn -DskipTests compile -Pserver exec:java

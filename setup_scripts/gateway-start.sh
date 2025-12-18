#!/usr/bin/env bash
set -euo pipefail

GATEWAY_PASS="${GATEWAY_PASS:-server}"

export DEATHNODE_TLS_KEYSTORE_PATH="$HOME/certs/gateway.p12"
export DEATHNODE_TLS_KEYSTORE_PASSWORD="$GATEWAY_PASS"
export DEATHNODE_TLS_TRUSTSTORE_PATH="$HOME/certs/truststore.p12"
export DEATHNODE_TLS_TRUSTSTORE_PASSWORD="$GATEWAY_PASS"

mvn -DskipTests compile -Pserver exec:java

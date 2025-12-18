#!/usr/bin/env bash
set -euo pipefail

NODE_PASS="${NODE_PASS:-alice12}"

export DEATHNODE_TLS_TRUSTSTORE_PATH="$HOME/certs/truststore.p12"
export DEATHNODE_TLS_TRUSTSTORE_PASSWORD="$NODE_PASS"

export DEATHNODE_GATEWAY_URL="${DEATHNODE_GATEWAY_URL:-https://10.0.2.10:443}"

mvn -DskipTests compile exec:java

#!/usr/bin/env bash
set -euo pipefail

NODE_PASS="${NODE_PASS:-alice12}"

export DEATHNODE_TLS_TRUSTSTORE_PATH="$HOME/certs/truststore.p12"
export DEATHNODE_TLS_TRUSTSTORE_PASSWORD="$NODE_PASS"

mvn -DskipTests compile exec:java

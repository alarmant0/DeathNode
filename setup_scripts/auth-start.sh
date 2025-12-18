#!/usr/bin/env bash
set -euo pipefail

AUTH_PASS="${AUTH_PASS:-auth123}"

export DEATHNODE_TLS_KEYSTORE_PATH="$HOME/certs/auth.p12"
export DEATHNODE_TLS_KEYSTORE_PASSWORD="$AUTH_PASS"

mvn -DskipTests compile -Pauth exec:java

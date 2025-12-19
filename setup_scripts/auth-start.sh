#!/usr/bin/env bash
set -euo pipefail

AUTH_PASS="${AUTH_PASS:-auth123}"

CERT_USER="${SUDO_USER:-$USER}"
CERT_HOME="/home/$CERT_USER/certs"
if [[ "$CERT_USER" == "root" ]]; then
  CERT_HOME="$HOME/certs"
fi

export DEATHNODE_TLS_KEYSTORE_PATH="$CERT_HOME/auth.p12"
export DEATHNODE_TLS_KEYSTORE_PASSWORD="$AUTH_PASS"

mvn -DskipTests compile -Pauth exec:java

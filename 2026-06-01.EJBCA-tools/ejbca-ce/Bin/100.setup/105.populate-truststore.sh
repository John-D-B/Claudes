#!/usr/bin/env bash
# 105.populate-truststore.sh — import ManagementCA into WildFly's truststore.
#
# Root cause this fixes: the keyfactor/ejbca-ce image's "simple" TLS bootstrap
# creates the *server* keystore but leaves truststore.jks empty. WildFly's
# https-listener is configured `want-client-auth="true"` — it asks for a
# client cert and validates against the truststore. With an empty truststore,
# *any* client cert fails validation and WildFly silently drops the connection
# (curl sees "Empty reply"; Python sees RemoteDisconnected).
#
# Importing the ManagementCA root lets WildFly validate certs issued by it
# (i.e., our eltadmin cert from 1.4b, and any future admin cert).
#
# Requires: Creds/elt/ce-managementca.crt (produced by 1.4b)

version='1.0.0'

set -euo pipefail

# Default to host.k3d.internal so localhost-ownership conflicts on the operator
# machine do not bite. Override with HOST=... on the command line. For local DEV,
# put `127.0.0.1 host.k3d.internal` in /etc/hosts so the FQDN resolves to loopback.
HOST="${HOST:-host.k3d.internal}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/../../stack" && pwd)"
# Credentials live at repo-root ./Creds/elt/ — see 1.4b for rationale.
CA_LOCAL="$(cd "$SCRIPT_DIR/../.." && pwd)/Creds/elt/ce-managementca.crt"

TS_PATH="/opt/keyfactor/appserver/standalone/configuration/truststore.jks"

# Truststore credential from standalone.xml's <credential-reference clear-text="…"/>
# for key-store name="httpsTS". Reading dynamically each run keeps the script
# correct if the password ever changes between image versions.
cd "$STACK_DIR"
TS_PASS=$(docker compose exec -T ejbca sh -c "
    awk '/key-store name=\"httpsTS\"/,/<\/key-store>/' \
        /opt/keyfactor/appserver/standalone/configuration/standalone.xml \
    | grep -oP 'clear-text=\"\\K[^\"]+' \
    | head -1
" | tr -d '\r')

if [ -z "$TS_PASS" ]; then
    echo "ERROR: could not extract truststore password from standalone.xml" >&2
    exit 1
fi

if [ ! -s "$CA_LOCAL" ]; then
    echo "ERROR: $CA_LOCAL is missing — run 1.4b first" >&2
    exit 1
fi

echo "==> Truststore before:"
docker compose exec -T ejbca keytool -list -keystore "$TS_PATH" \
    -storepass "$TS_PASS" 2>&1 | head -10

echo "==> Streaming ce-managementca.crt to a writable in-container path"
# `docker compose cp` writes files as root; the container runs as UID 10001
# and can't read them. Stream via stdin so the file is owned by 10001.
# /opt/keyfactor/tmp is owned by 10001 per image layout.
docker compose exec -T ejbca sh -c "cat > /opt/keyfactor/tmp/ce-managementca.crt" \
    < "$CA_LOCAL"

echo "==> Removing any stale alias, then importing into truststore"
docker compose exec -T ejbca keytool -delete \
    -alias managementca \
    -keystore "$TS_PATH" \
    -storepass "$TS_PASS" 2>/dev/null || true
docker compose exec -T ejbca keytool -importcert \
    -file /opt/keyfactor/tmp/ce-managementca.crt \
    -alias managementca \
    -keystore "$TS_PATH" \
    -storepass "$TS_PASS" \
    -noprompt 2>&1 | grep -v "^$" || true

echo "==> Truststore after:"
docker compose exec -T ejbca keytool -list -keystore "$TS_PATH" \
    -storepass "$TS_PASS" 2>&1 | grep -E "Your keystore|trustedCertEntry|managementca"

echo
echo "==> Restarting EJBCA so WildFly reloads the truststore"
docker compose restart ejbca

echo "==> Waiting for EJBCA health endpoint to recover (~60s typical)"
end=$(($(date +%s) + 180))
while [ $(date +%s) -lt $end ]; do
    body=$(curl -s http://${HOST}:8080/ejbca/publicweb/healthcheck/ejbcahealth 2>/dev/null || true)
    if [ "$body" = "ALLOK" ]; then
        echo "  health: ALLOK"
        echo
        echo "==================== 1.4c complete ===================="
        exit 0
    fi
    sleep 5
    printf "."
done
echo
echo "WARNING: health endpoint didn't return ALLOK within 180s. Check 'docker compose logs ejbca'." >&2
exit 1

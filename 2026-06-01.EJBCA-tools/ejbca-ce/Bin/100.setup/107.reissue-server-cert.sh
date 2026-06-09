#!/usr/bin/env bash
# 107.reissue-server-cert.sh — re-issue EJBCA's WildFly server TLS cert
# with reachable SANs and replace the WildFly keystore in-place.
#
# Background:
#   The keyfactor/ejbca-ce container's bootstrap creates a server cert
#   with CN/SAN = the container hostname (a random 12-hex string), so
#   any client outside the docker bridge can't TLS-verify it against a
#   reachable hostname. Phase 2's cert-manager Issuer running in k3d hits
#   exactly this — it connects via host.k3d.internal:8443 and rejects the
#   cert. This script issues a new cert with the SANs we actually need
#   and swaps it in.
#
# What it does:
#   1. Reads WildFly's existing keystore password from standalone.xml so
#      we don't need to reconfigure WildFly afterward.
#   2. Adds (or refreshes) an end entity named `ejbca-server-mtls` using
#      the ManagementCA + SERVER cert profile + JKS token, with SANs:
#        - dNSName=host.k3d.internal   (k3d auto-injected hostAlias)
#        - dNSName=localhost           (direct host access)
#        - dNSName=host.docker.internal (Docker Desktop convention)
#        - dNSName=<container hostname> (preserve the existing alias path)
#   3. Runs `ejbca.sh batch` to materialise the keystore at /opt/keyfactor/p12/.
#   4. Backs up the live WildFly keystore.jks and replaces it with the new one.
#   5. Restarts the EJBCA service; polls 8443 until TLS is back.
#   6. Prints the new server cert's SANs as a verification.
#
# Idempotent: the EE-add step retries with delete+re-add if it already exists.
# Safe to re-run.

version='1.0.0'

set -euo pipefail

# Default to host.k3d.internal so localhost-ownership conflicts on the operator
# machine do not bite. Override with HOST=... on the command line. For local DEV,
# put `127.0.0.1 host.k3d.internal` in /etc/hosts so the FQDN resolves to loopback.
HOST="${HOST:-host.k3d.internal}"

# --- config ----------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$REPO_ROOT/stack/docker-compose.yml}"
EJBCA_SERVICE="${EJBCA_SERVICE:-ejbca}"

EE_USER="${EE_USER:-ejbca-server-mtls}"
# ELT-Server-End-Entity profile is CN-only (no O= permitted), allows multiple
# dNSName SANs (post-1.5 update: 4 modifiable + 1 auto-from-CN), and locks the
# usable cert profile to ELT-Server-profile (the one with Allow Validity
# Override and Single Active Certificate Constraint set).
EE_DN="${EE_DN:-CN=host.k3d.internal}"
CA_NAME="${CA_NAME:-ManagementCA}"
CERT_PROFILE="${CERT_PROFILE:-ELT-Server-profile}"
EE_PROFILE="${EE_PROFILE:-ELT-Server-End-Entity}"

# In-container paths
WILDFLY_HOME='/opt/keyfactor/appserver'
STANDALONE_XML="$WILDFLY_HOME/standalone/configuration/standalone.xml"
P12_DIR='/opt/keyfactor/p12'
# EJBCA's container bootstrap regenerates the runtime keystore at
# $WILDFLY_HOME/standalone/configuration/keystore.jks on every boot,
# importing from the persistent SOURCE path below. We write the new
# keystore + its storepasswd to the source path instead, so it survives.
# See keystore_test_and_rewrite() in /opt/keyfactor/bin/internal/after-deployed.sh.
PERSISTENT_BASE='/mnt/persistent/secrets/tls'

# --- helpers ---------------------------------------------------------------
_dc_exec() {
    docker compose -f "$COMPOSE_FILE" exec -T "$EJBCA_SERVICE" "$@"
}

echo "=== 1.4e  Re-issue EJBCA server TLS cert with reachable SANs ==="

# Discover container hostname so we keep an alias for it.
# Use cat /etc/hostname rather than `hostname` — the EJBCA image ships without
# /bin/hostname in $PATH.
CONTAINER_HOSTNAME="$(_dc_exec cat /etc/hostname | tr -d '\r\n ')"
# The EE profile's first SAN slot has "Use entity CN field" checked, which
# auto-mirrors CN into a DNSName SAN (per Chrome-58 / CABF norms). So we omit
# host.k3d.internal here — it's already covered by the CN-derived slot — and
# pass only the three additional SANs we want.
SANS="dNSName=localhost,dNSName=host.docker.internal,dNSName=${CONTAINER_HOSTNAME}"

# Read the PERSISTENT keystore password — the bootstrap uses this to open
# the source keystore on every boot and re-encrypts the runtime keystore to a
# fresh random password each time, so the runtime (standalone.xml) password
# is NOT a stable target.
SOURCE_STOREPASSWD_FILE="$PERSISTENT_BASE/$( _dc_exec cat /etc/hostname | tr -d '\r\n ' )/server.storepasswd"
WILDFLY_PASS="$(_dc_exec cat "$SOURCE_STOREPASSWD_FILE" | tr -d '\r\n ')"
test -n "$WILDFLY_PASS" || { echo "ERROR: could not read persistent storepasswd at $SOURCE_STOREPASSWD_FILE" >&2; exit 1; }

echo "  EE user        : $EE_USER"
echo "  EE DN          : $EE_DN"
echo "  SANs           : $SANS"
echo "  CA             : $CA_NAME"
echo "  cert profile   : $CERT_PROFILE"
echo "  ee profile     : $EE_PROFILE"
echo "  source path    : $PERSISTENT_BASE/$CONTAINER_HOSTNAME/server.jks"
echo "  WildFly pass   : (read from standalone.xml — using existing)"
echo

# --- 1. Add (or refresh) the end entity ------------------------------------
echo "[1/6] Adding end entity '$EE_USER' (delete+add for idempotency)"
# Use single-dash -force per ejbca.sh ra delendentity --help.
_dc_exec ejbca.sh ra delendentity --username "$EE_USER" -force 2>/dev/null || true

_dc_exec ejbca.sh ra addendentity \
    --username "$EE_USER" \
    --password "$WILDFLY_PASS" \
    --dn "$EE_DN" \
    --altname "$SANS" \
    --caname "$CA_NAME" \
    --type 1 \
    --token JKS \
    --certprofile "$CERT_PROFILE" \
    --eeprofile "$EE_PROFILE"

# addendentity stores the password hashed; `batch` requires a separate
# cleartext copy on the EE. Set it explicitly.
echo "      setting cleartext password (required for batch)"
_dc_exec ejbca.sh ra setclearpwd --username "$EE_USER" --password "$WILDFLY_PASS"

# --- 2. Generate keystore via batch ---------------------------------------
echo "[2/6] Generating JKS keystore via 'ejbca.sh batch $EE_USER'"
_dc_exec ejbca.sh batch "$EE_USER"

NEW_JKS="$P12_DIR/$EE_USER.jks"
_dc_exec test -f "$NEW_JKS" \
    || { echo "ERROR: expected new keystore at $NEW_JKS, not found." >&2; exit 1; }

# --- 3. Sanity-check the new keystore alias + password --------------------
echo "[3/6] Verifying new keystore contents"
_dc_exec keytool -list -keystore "$NEW_JKS" -storepass "$WILDFLY_PASS" | head -15

# --- 4. Install at persistent source path so it survives boots ----------
echo "[4/6] Installing keystore at persistent source path"
SOURCE_DIR="$PERSISTENT_BASE/$CONTAINER_HOSTNAME"
SOURCE_KS="$SOURCE_DIR/server.jks"
SOURCE_PWD="$SOURCE_DIR/server.storepasswd"
TS="$(date +%Y%m%d-%H%M%S)"

_dc_exec sh -c "
    mkdir -p '$SOURCE_DIR' &&
    if [ -f '$SOURCE_KS' ]; then cp '$SOURCE_KS' '$SOURCE_KS.bak.$TS'; fi &&
    cp '$NEW_JKS' '$SOURCE_KS' &&
    chmod 644 '$SOURCE_KS'
"
echo "  source : $SOURCE_KS"
echo "  pwfile : $SOURCE_PWD (kept as-is — new keystore matches its password)"

# --- 5. Restart EJBCA + wait for 8443 -------------------------------------
echo "[5/6] Restarting '$EJBCA_SERVICE' service"
docker compose -f "$COMPOSE_FILE" restart "$EJBCA_SERVICE"

echo "      waiting for https://${HOST}:8443/ejbca/ to come back..."
for i in $(seq 1 60); do
    if curl -sk -o /dev/null -w '%{http_code}' --max-time 3 https://${HOST}:8443/ejbca/ 2>/dev/null | grep -qE '^(200|302|401|403)$'; then
        echo "      back up after ${i}s"
        break
    fi
    sleep 2
done

# --- 6. Verify new server cert SANs ---------------------------------------
echo "[6/6] New server cert verification"
openssl s_client -connect ${HOST}:8443 -showcerts </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -ext subjectAltName

echo
echo "=== 1.4e done — EJBCA server cert reissued; restart the cert-manager"
echo "    issuer pod (or wait for next reconcile) to pick up the new cert. ==="

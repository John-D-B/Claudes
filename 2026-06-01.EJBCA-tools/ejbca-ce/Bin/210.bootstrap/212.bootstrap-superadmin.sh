#!/usr/bin/env bash
# 212.bootstrap-superadmin.sh — re-issue the auto-bootstrapped SuperAdmin
# client P12 from the keyfactor/ejbca-ce image.
#
# Workflow context: this was the first attempt at producing a usable admin
# cert for the local CE stack. The cert it generates is for the end entity
# the image auto-bootstraps (CN = the container hostname), which the image
# also uses as its server cert — same DN on both sides. That collision
# triggered WildFly's mTLS handler to silently drop the connection, which
# we eventually traced in step 1.4d.
#
# 1.4b superseded this approach by creating a distinct end entity
# (CN=ELT-Admin) whose DN doesn't clash with the server cert. The current
# operational flow uses 1.4b, not this script.
#
# This script remains in the workflow record. Its output lives in
# ./Creds/1.4/ alongside the other artifacts from this attempt.
#
# Safe to re-run — flips the EE status back to NEW each time.

version='1.0.0'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/../../stack" && pwd)"
# Workflow artifacts from step 1.4 — see ./Creds/1.4/.
OUT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/Creds/1.4"

ADMIN_PASS="ejbcadev"            # dev-only password (>= 6 chars for keytool/P12)
EJBCA="/opt/keyfactor/bin/ejbca.sh"

mkdir -p "$OUT_DIR"
cd "$STACK_DIR"

# The admin end entity username is the EJBCA container's hostname.
# The minimal image lacks `hostname` and `cat`, so query from the host side
# via docker inspect.
ADMIN_USER="$(docker inspect -f '{{.Config.Hostname}}' ejbca-ce)"
if [ -z "$ADMIN_USER" ]; then
    echo "ERROR: could not determine EJBCA container hostname" >&2
    exit 1
fi
echo "==> SuperAdmin end entity: $ADMIN_USER"

echo "==> Setting password (clear) and status=NEW"
docker compose exec -T ejbca "$EJBCA" ra setclearpwd "$ADMIN_USER" "$ADMIN_PASS"
docker compose exec -T ejbca "$EJBCA" ra setendentitystatus "$ADMIN_USER" 10

echo "==> Running ejbca.sh batch to regenerate keystore"
docker compose exec -T ejbca "$EJBCA" batch "$ADMIN_USER"

echo "==> Locating generated keystore inside container"
# EJBCA writes to /opt/keyfactor/p12/<username>.<ext>. Despite the class
# name BatchMakeP12Command, the actual format follows the end entity's
# tokenType — auto-bootstrap defaults to JKS, which we convert on the host.
KS_IN_CONTAINER=$(docker compose exec -T ejbca sh -c '
    for ext in p12 jks; do
        f="/opt/keyfactor/p12/'"$ADMIN_USER"'.$ext"
        [ -f "$f" ] && { echo "$f"; exit 0; }
    done
    ls /opt/keyfactor/p12/*.p12 /opt/keyfactor/p12/*.jks 2>/dev/null | head -1
' | tr -d '\r')

if [ -z "$KS_IN_CONTAINER" ]; then
    echo "ERROR: no keystore found in /opt/keyfactor/p12/ after batch." >&2
    docker compose logs --tail 20 ejbca
    exit 1
fi

KS_EXT="${KS_IN_CONTAINER##*.}"
echo "==> Found: $KS_IN_CONTAINER (format: $KS_EXT)"

JKS_LOCAL="$OUT_DIR/superadmin.jks"
P12_LOCAL="$OUT_DIR/superadmin.p12"

if [ "$KS_EXT" = "p12" ]; then
    echo "==> Copying P12 directly to host: $P12_LOCAL"
    docker compose cp "ejbca:$KS_IN_CONTAINER" "$P12_LOCAL"
else
    echo "==> Copying JKS to host, then converting to P12"
    docker compose cp "ejbca:$KS_IN_CONTAINER" "$JKS_LOCAL"
    rm -f "$P12_LOCAL"
    keytool -importkeystore \
        -srckeystore "$JKS_LOCAL" -srcstoretype JKS -srcstorepass "$ADMIN_PASS" \
        -destkeystore "$P12_LOCAL" -deststoretype PKCS12 -deststorepass "$ADMIN_PASS" \
        -noprompt 2>&1 | grep -v '^$' || true
fi

if [ ! -s "$P12_LOCAL" ]; then
    echo "ERROR: P12 missing or empty after copy/convert" >&2
    exit 1
fi

# Also split to PEM for completeness — these were the admin.crt/admin.key/ca.crt
# files produced by the original 1.4 flow.
openssl pkcs12 -in "$P12_LOCAL" -nokeys -clcerts -passin "pass:$ADMIN_PASS" \
    -out "$OUT_DIR/admin.crt" 2>/dev/null
openssl pkcs12 -in "$P12_LOCAL" -nocerts  -nodes   -passin "pass:$ADMIN_PASS" \
    -out "$OUT_DIR/admin.key" 2>/dev/null
openssl pkcs12 -in "$P12_LOCAL" -cacerts  -nokeys  -passin "pass:$ADMIN_PASS" \
    -out "$OUT_DIR/ca.crt" 2>/dev/null

# Show cert subject so the user can confirm what got issued.
echo
echo "==> P12 contents (subject and validity):"
openssl pkcs12 -in "$P12_LOCAL" -nokeys -clcerts -passin "pass:$ADMIN_PASS" 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates 2>/dev/null

cat <<EOF

==================== 1.4 complete ====================
  P12 file:   $P12_LOCAL
  Password:   $ADMIN_PASS
  Username:   $ADMIN_USER

NOTE: this admin cert shares its subject DN with the EJBCA server cert.
That collision triggers mTLS failures in some clients. 1.4b's eltadmin
(CN=ELT-Admin) was created with a distinct DN to work around this.
======================================================
EOF

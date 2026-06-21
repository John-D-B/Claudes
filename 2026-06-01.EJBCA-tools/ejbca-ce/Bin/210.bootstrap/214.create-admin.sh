#!/usr/bin/env bash
# 214.create-admin.sh — create a distinct admin end entity + client P12.
#
# Why a new admin rather than re-using 32af9e1ba61a?
# The auto-bootstrapped admin EE shares the EJBCA *server* cert's subject DN
# (CN=32af9e1ba61a). With client and server presenting the same DN, some
# TLS stacks (including WildFly's mTLS handler here) drop the connection
# mid-response. A distinct DN avoids that entirely.
#
# What this does:
#   1. Creates EE 'eltadmin' with CN=ELT-Admin on ManagementCA
#   2. Adds the DN to the Super Administrator Role
#   3. Batch-generates the keystore (JKS, despite the CLI's 'P12' naming)
#   4. Copies the JKS to the host and converts to PKCS12 via keytool
#
# Idempotent — if the EE already exists, status is flipped back to NEW
# and the keystore is regenerated.

version='1.2.0'   # 1.2.0 — self-log to $logDir/B05-create-admin.log
                  # 1.1.0 — write straight to the out-of-repo $certsDir with the
                  #         friendly ELT-Admin.* names (no in-repo Creds/elt).

set -euo pipefail

# Self-log this run to $logDir (out-of-repo); trap drains tee so no false "hang".
logDir="${logDir:-/tmp/claude/demo/logs}"; mkdir -p "$logDir"
exec > >(tee "$logDir/B05-create-admin.log") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT
echo "=== logging to $logDir/B05-create-admin.log ==="

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/../../stack" && pwd)"
# Working certs go to the out-of-repo $certsDir (default /tmp/claude/demo/certs),
# never inside the cloned repo — they are per-install and not checked in.
certsDir="${certsDir:-/tmp/claude/demo/certs}"
OUT_DIR="$certsDir"

ADMIN_USER="eltadmin"           # EJBCA-side username (used inside container)
LOCAL_BASE="ELT-Admin"          # host-side filename base in $certsDir
                                # (ELT-Admin.crt / .key / .p12 / .password)
ADMIN_CN="ELT-Admin"
ADMIN_DN="CN=$ADMIN_CN"

# Password lives in $certsDir alongside the P12 it protects. Self-bootstraps
# with the dev default on first run.
PASSWORD_FILE="$certsDir/${LOCAL_BASE}.password"
if [ ! -f "$PASSWORD_FILE" ]; then
    mkdir -p "$(dirname "$PASSWORD_FILE")"
    echo "eltadmindev" > "$PASSWORD_FILE"
    chmod 600 "$PASSWORD_FILE"
    echo "Note: created $PASSWORD_FILE with the default dev password"
fi
ADMIN_PASS=$(tr -d '\n\r' < "$PASSWORD_FILE")
if [ ${#ADMIN_PASS} -lt 6 ]; then
    echo "ERROR: password in $PASSWORD_FILE must be >= 6 chars (keytool/PKCS12 requirement)" >&2
    exit 1
fi
CA_NAME="ManagementCA"
ROLE_NAME="Super Administrator Role"
EJBCA="/opt/keyfactor/bin/ejbca.sh"

mkdir -p "$OUT_DIR"
cd "$STACK_DIR"

# --- step 1: ensure the end entity exists with status NEW -----------------
echo "==> Ensuring end entity '$ADMIN_USER' exists and is NEW"
if docker compose exec -T ejbca "$EJBCA" ra findendentity --username "$ADMIN_USER" 2>&1 \
   | grep -q "Found end entity"; then
    echo "    Exists — resetting password and status"
    docker compose exec -T ejbca "$EJBCA" ra setclearpwd "$ADMIN_USER" "$ADMIN_PASS"
    docker compose exec -T ejbca "$EJBCA" ra setendentitystatus "$ADMIN_USER" 10
else
    echo "    Creating new end entity"
    docker compose exec -T ejbca "$EJBCA" ra addendentity \
        --username "$ADMIN_USER" \
        --dn "$ADMIN_DN" \
        --caname "$CA_NAME" \
        --type 1 \
        --token P12 \
        --password "$ADMIN_PASS" \
        --certprofile ENDUSER \
        --eeprofile EMPTY
    # addendentity stores the password hashed; batch needs a clear password.
    docker compose exec -T ejbca "$EJBCA" ra setclearpwd "$ADMIN_USER" "$ADMIN_PASS"
fi

# --- step 2: add to Super Administrator Role ------------------------------
echo "==> Adding $ADMIN_DN to '$ROLE_NAME'"
docker compose exec -T ejbca "$EJBCA" roles addrolemember \
    --role "$ROLE_NAME" \
    --caname "$CA_NAME" \
    --with WITH_COMMONNAME \
    --value "$ADMIN_CN" 2>&1 | grep -v "log4j\|FIPS" || true

# --- step 3: batch-generate the keystore ----------------------------------
echo "==> Running batch to generate keystore for $ADMIN_USER"
docker compose exec -T ejbca "$EJBCA" batch "$ADMIN_USER" 2>&1 \
    | grep -E "Generating|Created|generated|ERROR" \
    | grep -v "log4j\|FIPS" || true

# --- step 4: locate and copy the keystore ---------------------------------
KS_IN_CONTAINER=$(docker compose exec -T ejbca sh -c "
    for ext in p12 jks; do
        f=/opt/keyfactor/p12/${ADMIN_USER}.\$ext
        [ -f \"\$f\" ] && { echo \"\$f\"; exit 0; }
    done
" | tr -d '\r')

if [ -z "$KS_IN_CONTAINER" ]; then
    echo "ERROR: keystore not found in /opt/keyfactor/p12/" >&2
    exit 1
fi

KS_EXT="${KS_IN_CONTAINER##*.}"
echo "==> Found: $KS_IN_CONTAINER (format: $KS_EXT)"

JKS_LOCAL="$OUT_DIR/$LOCAL_BASE.jks"
P12_LOCAL="$OUT_DIR/$LOCAL_BASE.p12"

if [ "$KS_EXT" = "p12" ]; then
    docker compose cp "ejbca:$KS_IN_CONTAINER" "$P12_LOCAL"
else
    docker compose cp "ejbca:$KS_IN_CONTAINER" "$JKS_LOCAL"
    rm -f "$P12_LOCAL"
    keytool -importkeystore \
        -srckeystore "$JKS_LOCAL" -srcstoretype JKS -srcstorepass "$ADMIN_PASS" \
        -destkeystore "$P12_LOCAL" -deststoretype PKCS12 -deststorepass "$ADMIN_PASS" \
        -noprompt 2>&1 | grep -v '^$' || true
fi

# --- step 5: split to PEM for ELT / cert-manager use ----------------------
openssl pkcs12 -in "$P12_LOCAL" -nokeys -clcerts -passin "pass:$ADMIN_PASS" \
    -out "$OUT_DIR/$LOCAL_BASE.crt" 2>/dev/null
openssl pkcs12 -in "$P12_LOCAL" -nocerts -nodes -passin "pass:$ADMIN_PASS" \
    -out "$OUT_DIR/$LOCAL_BASE.key" 2>/dev/null
openssl pkcs12 -in "$P12_LOCAL" -cacerts -nokeys -passin "pass:$ADMIN_PASS" \
    -out "$OUT_DIR/ManagementCA.crt" 2>/dev/null

echo
echo "==> Verifying issued cert:"
openssl pkcs12 -in "$P12_LOCAL" -nokeys -clcerts -passin "pass:$ADMIN_PASS" 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates

cat <<EOF

==================== 1.4b complete ====================
  P12:       $P12_LOCAL  (password: $ADMIN_PASS)
  Cert PEM:  $OUT_DIR/$LOCAL_BASE.crt
  Key PEM:   $OUT_DIR/$LOCAL_BASE.key
  CA chain:  $OUT_DIR/ManagementCA.crt
  Username:  $ADMIN_USER  (CN=$ADMIN_CN)
=======================================================
EOF

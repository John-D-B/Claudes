#!/usr/bin/env bash
# 212.bootstrap-superadmin.sh — refresh the auto-bootstrapped SuperAdmin end
# entity (flip status to NEW + batch), and export its keystore to $certsDir as
# SuperAdmin.{jks,p12,password} for EJBCA admin work that needs SuperAdmin
# rather than the day-to-day ELT-Admin (214).
#
# Workflow context: the cert this regenerates is for the EE the image
# auto-bootstraps (CN = the container hostname), which the image also uses as
# its server cert — same DN on both sides. That collision triggers WildFly's
# mTLS handler to drop the connection, so day-to-day admin uses a distinct end
# entity (214, CN=ELT-Admin). The SuperAdmin keystore is still handy for some
# admin tasks, so it is kept in $certsDir — out-of-repo, never in the clone.
#
# Safe to re-run — flips the EE status back to NEW each time.

version='1.3.0'   # 1.3.0 — self-log to $logDir/B05-superadmin.log
                  # 1.2.0 — export SuperAdmin keystore to out-of-repo $certsDir
                  # 1.1.0 — drop the unused in-repo Creds/1.4 host copy

set -euo pipefail

# Self-log this run to $logDir (out-of-repo); trap drains tee so no false "hang".
logDir="${logDir:-/tmp/claude/demo/logs}"; mkdir -p "$logDir"
exec > >(tee "$logDir/B05-superadmin.log") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT
echo "=== logging to $logDir/B05-superadmin.log ==="

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/../../stack" && pwd)"
certsDir="${certsDir:-/tmp/claude/demo/certs}"   # out-of-repo; never inside the clone

ADMIN_PASS="ejbcadev"            # dev-only password (>= 6 chars for keytool/P12)
EJBCA="/opt/keyfactor/bin/ejbca.sh"

mkdir -p "$certsDir"
cd "$STACK_DIR"

# The admin end entity username is the EJBCA container's hostname.
# The minimal image lacks `hostname`/`cat`, so query from the host via inspect.
ADMIN_USER="$(docker inspect -f '{{.Config.Hostname}}' ejbca-ce)"
if [ -z "$ADMIN_USER" ]; then
    echo "ERROR: could not determine EJBCA container hostname" >&2
    exit 1
fi
echo "==> SuperAdmin end entity: $ADMIN_USER"

echo "==> Setting password (clear) and status=NEW"
docker compose exec -T ejbca "$EJBCA" ra setclearpwd "$ADMIN_USER" "$ADMIN_PASS"
docker compose exec -T ejbca "$EJBCA" ra setendentitystatus "$ADMIN_USER" 10

echo "==> Running ejbca.sh batch to regenerate the keystore"
docker compose exec -T ejbca "$EJBCA" batch "$ADMIN_USER" 2>&1 \
    | grep -E "Generating|Created|generated|ERROR" | grep -v "log4j\|FIPS" || true

# --- export the keystore to $certsDir as SuperAdmin.{jks,p12,password} ---
echo "==> Locating generated keystore inside container"
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
echo "==> Found keystore: $KS_IN_CONTAINER (format: $KS_EXT)"

JKS_OUT="$certsDir/SuperAdmin.jks"
P12_OUT="$certsDir/SuperAdmin.p12"
printf '%s' "$ADMIN_PASS" > "$certsDir/SuperAdmin.password"
chmod 600 "$certsDir/SuperAdmin.password"

# Copy the keystore in its native format, then emit the other format too, so
# both SuperAdmin.jks and SuperAdmin.p12 are available regardless of source.
if [ "$KS_EXT" = "p12" ]; then
    docker compose cp "ejbca:$KS_IN_CONTAINER" "$P12_OUT"
    rm -f "$JKS_OUT"
    keytool -importkeystore \
        -srckeystore  "$P12_OUT" -srcstoretype  PKCS12 -srcstorepass  "$ADMIN_PASS" \
        -destkeystore "$JKS_OUT" -deststoretype JKS    -deststorepass "$ADMIN_PASS" \
        -noprompt 2>&1 | grep -v '^$' || true
else
    docker compose cp "ejbca:$KS_IN_CONTAINER" "$JKS_OUT"
    rm -f "$P12_OUT"
    keytool -importkeystore \
        -srckeystore  "$JKS_OUT" -srcstoretype  JKS    -srcstorepass  "$ADMIN_PASS" \
        -destkeystore "$P12_OUT" -deststoretype PKCS12 -deststorepass "$ADMIN_PASS" \
        -noprompt 2>&1 | grep -v '^$' || true
fi

if [ ! -s "$P12_OUT" ] || [ ! -s "$JKS_OUT" ]; then
    echo "ERROR: SuperAdmin keystore export incomplete" >&2
    exit 1
fi

echo
echo "==================== 212 complete ===================="
echo "  SuperAdmin EE '$ADMIN_USER' refreshed (status NEW + batch)."
echo "  Keystore exported to \$certsDir:"
echo "    $JKS_OUT"
echo "    $P12_OUT"
echo "    $certsDir/SuperAdmin.password   (password: $ADMIN_PASS)"
echo "  Day-to-day admin remains 214's ELT-Admin."
echo "======================================================"

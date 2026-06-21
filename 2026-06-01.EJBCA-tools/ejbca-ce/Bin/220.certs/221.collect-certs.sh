#!/usr/bin/env bash
# 221.collect-certs.sh — collect the demo's working certs into $certsDir and
# write Bin/elt/ce-target.env, so ELT / curl / cert-grep authenticate against
# the local CE stack. This is the scripted form of storyboard step B06; the
# B06 "Manual" block is this script's transcript — keep the two in lockstep.
#
# The ELT-Admin client cert and ManagementCA are written straight into $certsDir
# by 214 (no in-repo Creds/elt staging). This script adds the server cert and the
# env file. The server cert lives only inside the container keystore (server.jks),
# so it is exported with keytool; the store password is generated per install and
# read from server.storepasswd at runtime (no openssl, no live handshake).
#
# Lives in Bin/220.certs/ — its own decade bucket, NOT Bin/210.bootstrap/ — so the
# B05 bootstrap glob (Bin/210.bootstrap/*.sh) does not run it. It is a B06-time,
# certsDir-dependent step, distinct from the one-time bootstrap.
#
# Usage: ./Bin/220.certs/221.collect-certs.sh [certs-dir]
#        certs-dir defaults to $certsDir, else /tmp/claude/demo/certs.
#        Afterwards:  source $localDir/ce-target.env   (path printed at the end)

version='1.3.0'   # 1.3.0 — self-log to $logDir/B06-collect-certs.log (the run book's named log).
                  # 1.2.0 — localDir defaults out-of-repo (/tmp/claude/demo/local), not $ROOT_DIR/local
                  # 1.1.0 — 214 writes friendly names to $certsDir; this no longer copies Creds/elt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

certsDir="${1:-${certsDir:-/tmp/claude/demo/certs}}"
localDir="${localDir:-/tmp/claude/demo/local}"   # out-of-repo, like certsDir (never $ROOT_DIR/local)
COMPOSE="./stack/docker-compose.yml"
ENV_FILE="$localDir/ce-target.env"

mkdir -p "$certsDir" "$localDir"

# Self-log this run to $logDir (out-of-repo); trap drains tee so no false "hang".
logDir="${logDir:-/tmp/claude/demo/logs}"; mkdir -p "$logDir"
exec > >(tee "$logDir/B06-collect-certs.log") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT
echo "=== logging to $logDir/B06-collect-certs.log ==="

echo "=== Finalising demo certs in $certsDir ==="

# 214 already wrote ELT-Admin.{crt,key,p12,password} + ManagementCA.crt straight
# into $certsDir (no in-repo staging). Here we add the server cert + the env file.

# 1. Server cert: export the leaf (alias host.k3d.internal) from the keystore.
echo "  exporting server cert via keytool (alias host.k3d.internal)"
docker compose -f "$COMPOSE" exec -T ejbca \
    sh -c 'keytool -exportcert -rfc -alias host.k3d.internal \
      -keystore /mnt/persistent/secrets/tls/ejbca-ce/server.jks \
      -storepass "$(cat /mnt/persistent/secrets/tls/ejbca-ce/server.storepasswd)"' \
    > "$certsDir/host.k3d.internal.crt" 2>/dev/null

# 3. Wire the shell config so ELT / curl / cert-grep authenticate.
cat > "$ENV_FILE" <<EOF
export ELT_HOST=host.k3d.internal
export ELT_PORT=8443
export ELT_CERT=$certsDir/ELT-Admin.crt
export ELT_KEY=$certsDir/ELT-Admin.key
export ELT_CA_CERT=$certsDir/ManagementCA.crt
EOF

echo
echo "  [done] certs in $certsDir ; wrote $ENV_FILE"
echo "  Next:  source $ENV_FILE"

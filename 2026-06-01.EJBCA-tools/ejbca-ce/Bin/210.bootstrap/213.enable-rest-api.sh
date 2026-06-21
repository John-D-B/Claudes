#!/usr/bin/env bash
# 213.enable-rest-api.sh — turn on EJBCA's REST protocols.
#
# CE ships with the REST API protocols disabled by default. Without this,
# every REST endpoint returns 'This service has been disabled.' (HTTP 403).
# ELT and the cert-manager issuer both need REST, so we enable the five
# protocols they exercise.
#
# Idempotent — re-enabling an already-enabled protocol is a no-op in EJBCA.

version='1.1.0'   # 1.1.0 — self-log to $logDir/B05-enable-rest.log
                  # 1.0.0 — prior

set -euo pipefail

# Self-log this run to $logDir (out-of-repo); trap drains tee so no false "hang".
logDir="${logDir:-/tmp/claude/demo/logs}"; mkdir -p "$logDir"
exec > >(tee "$logDir/B05-enable-rest.log") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT
echo "=== logging to $logDir/B05-enable-rest.log ==="

# Default to host.k3d.internal so localhost-ownership conflicts on the operator
# machine do not bite. Override with HOST=... on the command line. For local DEV,
# put `127.0.0.1 host.k3d.internal` in /etc/hosts so the FQDN resolves to loopback.
HOST="${HOST:-host.k3d.internal}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/../../stack" && pwd)"
cd "$STACK_DIR"

EJBCA="/opt/keyfactor/bin/ejbca.sh"

PROTOCOLS=(
    "REST CA Management"
    "REST Certificate Management"
    "REST Certificate Management V2"
    "REST End Entity Management"
    "REST End Entity Management V2"
)

echo "=== Current protocol status (before) ==="
docker compose exec -T ejbca "$EJBCA" config protocols status 2>&1 \
    | grep -E "REST|Status" || true

echo
echo "=== Enabling protocols ==="
for p in "${PROTOCOLS[@]}"; do
    echo "--- $p"
    docker compose exec -T ejbca "$EJBCA" config protocols enable --name "$p" 2>&1 \
        | grep -E "INFO|ERROR|enabled|disabled" \
        | grep -v "log4j\|FIPS" || true
done

echo
echo "=== Current protocol status (after) ==="
docker compose exec -T ejbca "$EJBCA" config protocols status 2>&1 \
    | grep -E "REST" || true

echo
echo "=== Probe (no client cert, just check 'disabled' is gone) ==="
status_body=$(curl -sk https://${HOST}:8443/ejbca/ejbca-rest-api/v1/ca/status)
if echo "$status_body" | grep -q "disabled"; then
    echo "FAIL: REST still shows 'disabled': $status_body"
    exit 1
fi
echo "  /v1/ca/status responds:  $status_body"
echo
echo "==================== 1.4a complete ===================="

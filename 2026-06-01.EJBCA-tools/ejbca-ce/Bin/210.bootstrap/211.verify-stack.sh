#!/usr/bin/env bash
# 211.verify-stack.sh — verify the EJBCA-CE local stack is up and reachable.
#
# Checks:
#   - both containers running
#   - MariaDB ejbca schema has tables
#   - EJBCA 8080 health endpoint (diagnostic only — IP-gated, never ALLOK
#     from the host; the real readiness gate is the HTTPS Admin GUI below)
#   - HTTPS Admin GUI handshake succeeds
#
# Idempotent and read-only. Safe to re-run any time.

version='1.3.0'   # 1.3.0 — self-log to $logDir/B05-verify-stack.log
                  # 1.2.0 — 8080 health probe fully non-fatal (handles 000 / missing body)

set -euo pipefail

# Self-log this run to $logDir (out-of-repo); trap drains tee so no false "hang".
logDir="${logDir:-/tmp/claude/demo/logs}"; mkdir -p "$logDir"
exec > >(tee "$logDir/B05-verify-stack.log") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT
echo "=== logging to $logDir/B05-verify-stack.log ==="

# Default to host.k3d.internal so localhost-ownership conflicts on the operator
# machine do not bite. Override with HOST=... on the command line. For local DEV,
# put `127.0.0.1 host.k3d.internal` in /etc/hosts so the FQDN resolves to loopback.
HOST="${HOST:-host.k3d.internal}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/../../stack" && pwd)"
cd "$STACK_DIR"

echo "=== Container status ==="
docker compose ps

echo
echo "=== MariaDB EJBCA schema (table count) ==="
docker compose exec -T mariadb mariadb -u ejbca -pejbca ejbca \
    -e "SELECT COUNT(*) AS ejbca_table_count FROM information_schema.tables WHERE table_schema='ejbca';"

echo
echo "=== Waiting for the EJBCA app to finish deploying (AdminWeb 200) ==="
# A fresh `up` brings WildFly's TLS listener up well before the EJBCA app is
# deployed, so probe the AdminWeb until it answers 200 before the checks below
# (and before the rest of the bootstrap) try to talk to the app.
for i in $(seq 1 120); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
            https://${HOST}:8443/ejbca/adminweb/ 2>/dev/null || true)
    if [ "$code" = 200 ] || [ "$code" = 302 ]; then
        echo "  AdminWeb up after ~$((i * 2))s"
        break
    fi
    if [ "$i" = 120 ]; then
        echo "ERROR: EJBCA app not deployed within ~240s" >&2
        exit 1
    fi
    sleep 2
done

echo
echo "=== EJBCA health endpoint (HTTP 8080) ==="
mkdir -p /tmp/claude/elt
curl -s --max-time 5 -o /tmp/claude/elt/ejbca-health -w "  HTTP %{http_code}  body=" \
    http://${HOST}:8080/ejbca/publicweb/healthcheck/ejbcahealth || true
cat /tmp/claude/elt/ejbca-health 2>/dev/null || printf '(no body — 8080 lags 8443, IP-gated)'
echo
rm -f /tmp/claude/elt/ejbca-health

echo
echo "=== HTTPS Admin GUI handshake (HTTPS 8443) ==="
curl -sk -o /dev/null -w "  HTTPS %{http_code}  tls=%{ssl_verify_result}\n" \
    https://${HOST}:8443/ejbca/adminweb/

echo
echo "=== EJBCA server cert (issuer chain) ==="
echo | openssl s_client -connect ${HOST}:8443 -servername ${HOST} 2>/dev/null \
    | openssl x509 -noout -subject -issuer

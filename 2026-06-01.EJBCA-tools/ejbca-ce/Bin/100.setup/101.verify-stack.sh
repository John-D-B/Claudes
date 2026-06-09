#!/usr/bin/env bash
# 101.verify-stack.sh — verify the EJBCA-CE local stack is up and reachable.
#
# Checks:
#   - both containers running
#   - MariaDB ejbca schema has tables
#   - EJBCA health endpoint returns ALLOK on HTTP
#   - HTTPS Admin GUI handshake succeeds
#
# Idempotent and read-only. Safe to re-run any time.

version='1.0.0'

set -euo pipefail

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
echo "=== EJBCA health endpoint (HTTP 8080) ==="
mkdir -p /tmp/claude/elt
curl -s -o /tmp/claude/elt/ejbca-health -w "  HTTP %{http_code}  body=" \
    http://${HOST}:8080/ejbca/publicweb/healthcheck/ejbcahealth
cat /tmp/claude/elt/ejbca-health; echo
rm -f /tmp/claude/elt/ejbca-health

echo
echo "=== HTTPS Admin GUI handshake (HTTPS 8443) ==="
curl -sk -o /dev/null -w "  HTTPS %{http_code}  tls=%{ssl_verify_result}\n" \
    https://${HOST}:8443/ejbca/adminweb/

echo
echo "=== EJBCA server cert (issuer chain) ==="
echo | openssl s_client -connect ${HOST}:8443 -servername ${HOST} 2>/dev/null \
    | openssl x509 -noout -subject -issuer

#!/usr/bin/env bash
# 132.probe-soap.sh — confirm EJBCA CE's SOAP Web Service is reachable
# with our admin mTLS cert, and save the WSDL for offline inspection.
#
# Phase 5 (ELT v4.0.0 SOAP backend) — first concrete step. See
# Docs/ejbca-ce-implementation-plan.md section 7 (Phase 5).
#
# EJBCA's SOAP endpoint convention:
#   WSDL:    https://<host>:8443/ejbca/ejbcaws/ejbcaws?wsdl
#   Service: https://<host>:8443/ejbca/ejbcaws/ejbcaws

version='1.0.0'

set -euo pipefail

# Default to host.k3d.internal so localhost-ownership conflicts on the operator
# machine do not bite. Override with HOST=... on the command line. For local DEV,
# put `127.0.0.1 host.k3d.internal` in /etc/hosts so the FQDN resolves to loopback.
HOST="${HOST:-host.k3d.internal}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CRED_DIR="$ROOT_DIR/Creds/elt"
OUT_DIR="$ROOT_DIR/elt/wsdl"     # lives with the ELT code that consumes it (via zeep)

CERT="$CRED_DIR/ce-eltadmin.crt"
KEY="$CRED_DIR/ce-eltadmin.key"
CA="$CRED_DIR/ce-managementca.crt"

WSDL_URL="https://${HOST}:8443/ejbca/ejbcaws/ejbcaws?wsdl"
WSDL_OUT="$OUT_DIR/ejbca-ws.wsdl"

mkdir -p "$OUT_DIR"

if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
    echo "ERROR: $CERT or $KEY missing — run 1.4b first" >&2
    exit 1
fi

echo "=== Probing $WSDL_URL ==="
code=$(curl -sk --cert "$CERT" --key "$KEY" --cacert "$CA" \
    -o "$WSDL_OUT" -w "%{http_code}" "$WSDL_URL")
echo "  HTTP $code   size=$(wc -c < "$WSDL_OUT" 2>/dev/null || echo 0) bytes   →  $WSDL_OUT"

if [ "$code" != "200" ]; then
    echo "ERROR: WSDL fetch failed; body:" >&2
    head -c 400 "$WSDL_OUT" >&2; echo >&2
    exit 1
fi

echo
echo "=== WSDL top-level shape ==="
head -10 "$WSDL_OUT" | sed 's/^/  /'

echo
echo "=== SOAP operations exposed (count + sample) ==="
op_count=$(grep -c 'wsdl:operation name=' "$WSDL_OUT" || true)
echo "  total <operation> elements: $op_count"
echo "  first 30 operation names:"
grep -oE 'wsdl:operation name="[^"]+"' "$WSDL_OUT" \
    | sed -E 's/wsdl:operation name="//; s/"$//' \
    | sort -u | head -30 | sed 's/^/    /'

echo
echo "=== End Entity-related operations (filtered) ==="
grep -oE 'wsdl:operation name="[^"]+"' "$WSDL_OUT" \
    | sed -E 's/wsdl:operation name="//; s/"$//' \
    | sort -u \
    | grep -iE 'user|endentity|finduser|edituser|deleteuser|revokeuser|setuserstatus|findcerts' \
    | sed 's/^/  /'

echo
echo "==================== 5.1 complete ===================="

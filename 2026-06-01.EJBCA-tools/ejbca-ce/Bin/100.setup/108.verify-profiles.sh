#!/usr/bin/env bash
# 108.verify-profiles.sh — confirm the profiles set up in step 1.5 are
# visible to ELT via the SOAP backend. Used after manually creating the
# profiles in the admin GUI (see Docs/ejbca-ce-task-1.5-profile-setup.md).

version='1.0.0'

set -euo pipefail

# Default to host.k3d.internal so localhost-ownership conflicts on the operator
# machine do not bite. Override with HOST=... on the command line. For local DEV,
# put `127.0.0.1 host.k3d.internal` in /etc/hosts so the FQDN resolves to loopback.
HOST="${HOST:-host.k3d.internal}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

EXPECTED_PROFILE="${1:-ELT-Server-End-Entity}"  ## "${1:-ELT-Server-Profile}"

VENV_PY="./.venv/bin/python"
ELT="./elt/ejbca-lifecycle-tool.py"
CERT="./Creds/elt/ce-eltadmin.crt"
KEY="./Creds/elt/ce-eltadmin.key"

function f_indent() { 
    local c="$1"
    local str
    if [[ -z "${c}" ]]; then
        c=4
    fi
    str=$(printf "%${c}s")
    sed -e "s/^/${str}/;"
}

echo "=== Listing authorised End Entity Profiles via SOAP backend ==="
out=$("$VENV_PY" "$ELT" list -d1 -v \
    -ejbca-host ${HOST} -ejbca-port 8443 \
    -client-cert "$CERT" -client-key "$KEY" \
    -no-verify-ssl 2>&1)
echo "$out" | tail -15

echo
if echo "$out" | grep -qE "(^|\\s)$EXPECTED_PROFILE(\\s|$)"; then
    echo "  [PASS] '$EXPECTED_PROFILE' is present in the authorised profile list"
    echo
    exit 0
else
    echo "  [FAIL] '$EXPECTED_PROFILE' not found in the listing above."
    echo "         Either the GUI walkthrough hasn't been done yet, or the"
    echo "         profile was created under a different name. See:"
    echo "         Docs/ejbca-ce-task-1.5-profile-setup.md"
    echo
    echo "-- ELT output --" | f_indent 4
    echo "$out"             | f_indent 4
    echo
    exit 1
fi

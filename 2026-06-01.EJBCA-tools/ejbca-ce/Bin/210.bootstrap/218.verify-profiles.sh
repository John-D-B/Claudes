#!/usr/bin/env bash
# 218.verify-profiles.sh — confirm BOTH ELT-Server profiles exist after
# 217.import-profiles.sh: the End Entity profile (via ELT's SOAP backend)
# AND the Certificate profile (via an exportprofiles round-trip). Fail-fast
# gate before 219.reissue-server-cert.sh, which uses both.

version='1.2.0'   # 1.2.0 — call ELT via PATH (bundle layout), not ./.venv/./elt.
                  # 1.1.0 — also verify the Certificate profile, not just the
                  #         End Entity profile (now that 107 imports both).

set -euo pipefail

HOST="${HOST:-host.k3d.internal}"
EE_PROFILE="${1:-ELT-Server-End-Entity}"
CERT_PROFILE="${CERT_PROFILE:-ELT-Server-profile}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

# Run ELT the way setup.sh + the storyboard document it: by name via $PATH
# (bin/ symlink), with the venv active. No DEV-relative ./.venv or ./elt paths.
ELT="ejbca-lifecycle-tool.py"
CERT="./Creds/elt/ce-eltadmin.crt"
KEY="./Creds/elt/ce-eltadmin.key"
COMPOSE="./stack/docker-compose.yml"
EJBCA="/opt/keyfactor/bin/ejbca.sh"
VDIR="/tmp/verify-profiles"

fail=0

# --- End Entity profile: via ELT SOAP backend (also exercises SOAP) ---
echo "=== End Entity profile '$EE_PROFILE' (ELT SOAP backend) ==="
out=$("$ELT" list -d1 -v \
    -ejbca-host ${HOST} -ejbca-port 8443 \
    -client-cert "$CERT" -client-key "$KEY" \
    -no-verify-ssl 2>&1) || true
if echo "$out" | grep -qE "(^|[[:space:]])$EE_PROFILE([[:space:]]|$)"; then
    echo "  [PASS] '$EE_PROFILE' present"
else
    echo "  [FAIL] '$EE_PROFILE' not found"
    fail=1
fi

# --- Certificate profile: via exportprofiles round-trip ---
echo "=== Certificate profile '$CERT_PROFILE' (exportprofiles round-trip) ==="
listing=$(docker compose -f "$COMPOSE" exec -T ejbca sh -c \
    "rm -rf $VDIR && mkdir -p $VDIR && $EJBCA ca exportprofiles -d $VDIR >/dev/null 2>&1; ls $VDIR")
if echo "$listing" | grep -q "certprofile_${CERT_PROFILE}-"; then
    echo "  [PASS] '$CERT_PROFILE' present"
else
    echo "  [FAIL] '$CERT_PROFILE' not found"
    fail=1
fi

echo
if [ "$fail" -ne 0 ]; then
    echo "  One or more profiles missing. Run 217.import-profiles.sh, or see"
    echo "  Docs/ejbca-ce-task-1.5-profile-setup.md for the manual setup."
    exit 1
fi
echo "  [done] both profiles present."
exit 0

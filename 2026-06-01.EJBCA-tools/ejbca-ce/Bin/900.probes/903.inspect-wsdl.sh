#!/usr/bin/env bash
# 903.inspect-wsdl.sh — catalogue End Entity SOAP operations for the
# upcoming ELT v4.0.0 backend.
#
# Loads the WSDL with zeep, maps each of ELT's seven End Entity REST calls
# to a SOAP operation, prints the signature for each, and surfaces any
# delete-related operations so the open question from 5.1 (does SOAP have
# an EE-delete equivalent?) can be answered.
#
# Uses zeep from the bundle venv — source bin/setup.sh first (per the
# storyboard), the same as every other tool here.

version='1.1.0'   # 1.1.0 — python3/zeep via active venv + WSDL resolved for
                  #         the bundle layout; no DEV-relative ./.venv/./elt.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
# WSDL: DEV keeps elt/ under ROOT_DIR; the bundle has it one level up (beside bin/).
WSDL=""
for c in "$ROOT_DIR/elt/wsdl/ejbca-ws.wsdl" "$ROOT_DIR/../elt/wsdl/ejbca-ws.wsdl"; do
    [ -s "$c" ] && WSDL="$c" && break
done
[ -n "$WSDL" ] || { echo "ERROR: ejbca-ws.wsdl not found under elt/wsdl/ — run 5.1 first" >&2; exit 1; }

# zeep comes from the active venv (source bin/setup.sh first, as the storyboard
# documents) — no DEV-relative self-bootstrapped ./.venv.
if ! python3 -c "import zeep" 2>/dev/null; then
    echo "ERROR: python module 'zeep' missing — source bin/setup.sh first" >&2
    exit 1
fi

# --- inspection ---
python3 - "$WSDL" <<'PY'
import sys, zeep

wsdl_path = sys.argv[1]

# ELT's seven End Entity REST calls and the candidate SOAP operation
# we expect each to map to (None where unresolved).
REST_TO_SOAP = [
    ("POST /v1/endentity/search",            "findUser"),
    ("POST /v2/endentity/search",            "findUser"),
    ("DELETE /v1/endentity/{name}",          None),                          # 5.1's open question
    ("PUT /v1/endentity/{name}/revoke",      "revokeUser"),
    ("POST /v1/endentity/{name}/setstatus",  "editUser"),                    # via status field
    ("GET /v2/endentity/profiles/authorized","getAuthorizedEndEntityProfiles"),
    ("GET /v2/endentity/profile/{name}",     "getProfile"),
]

client = zeep.Client(wsdl_path)

# Pull every operation out of every binding for lookup.
ops = {}
for service in client.wsdl.services.values():
    for port in service.ports.values():
        for op_name, op in port.binding._operations.items():
            ops[op_name] = op

print("=" * 72)
print("REST → SOAP mapping for ELT's End Entity operations")
print("=" * 72)
for rest, soap in REST_TO_SOAP:
    print(f"\n{rest}")
    if soap is None:
        print(f"  → SOAP: OPEN QUESTION (see delete-related list below)")
        continue
    if soap not in ops:
        print(f"  → SOAP: {soap}  ** NOT FOUND IN WSDL **")
        continue
    op = ops[soap]
    print(f"  → SOAP: {soap}")
    print(f"    input:  {op.input.signature()}")
    print(f"    output: {op.output.signature()}")

print("\n" + "=" * 72)
print("Delete- and remove-related SOAP operations (for the open question)")
print("=" * 72)
for name in sorted(ops):
    if 'delete' in name.lower() or 'remove' in name.lower():
        op = ops[name]
        print(f"\n{name}")
        print(f"  input:  {op.input.signature()}")
        print(f"  output: {op.output.signature()}")

print("\n" + "=" * 72)
print("Sanity check: zeep parsed the WSDL")
print("=" * 72)
print(f"  Service:    {list(client.wsdl.services.keys())}")
print(f"  Operations: {len(ops)} total")
PY

echo
echo "==================== 5.2 complete ===================="

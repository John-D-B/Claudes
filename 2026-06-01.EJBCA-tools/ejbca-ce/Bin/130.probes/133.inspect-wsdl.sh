#!/usr/bin/env bash
# 133.inspect-wsdl.sh — catalogue End Entity SOAP operations for the
# upcoming ELT v4.0.0 backend.
#
# Loads the WSDL with zeep, maps each of ELT's seven End Entity REST calls
# to a SOAP operation, prints the signature for each, and surfaces any
# delete-related operations so the open question from 5.1 (does SOAP have
# an EE-delete equivalent?) can be answered.
#
# Self-bootstraps a project-local venv at ./.venv/ on first run. The venv
# is gitignored by convention.

version='1.0.0'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="$ROOT_DIR/.venv"
WSDL="$ROOT_DIR/elt/wsdl/ejbca-ws.wsdl"

# --- venv bootstrap ---
if [ ! -d "$VENV" ]; then
    echo "==> Creating venv at $VENV"
    python3 -m venv "$VENV"
fi
if ! "$VENV/bin/python" -c "import zeep" 2>/dev/null; then
    echo "==> Installing zeep into venv"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet zeep
fi

if [ ! -s "$WSDL" ]; then
    echo "ERROR: $WSDL missing — run 5.1 first" >&2
    exit 1
fi

# --- inspection ---
"$VENV/bin/python" - "$WSDL" <<'PY'
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

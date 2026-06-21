#!/usr/bin/env bash
# 216.verify-mtls.sh — confirm mTLS REST access works with the new admin
# cert produced by 1.4b. Hits a couple of representative endpoints.
#
# Note: /v2/endentity/* probes are expected to 404 on EJBCA CE — see
# Docs/ejbca-ce-rest-endentity-gap.md. They're left in for visibility.
#
# Host: defaults to host.k3d.internal (NOT localhost). JohnB's Mac is a
# working machine, not a dedicated dev box — `localhost:8443` may
# collide with other services. Add this to /etc/hosts:
#     127.0.0.1   host.k3d.internal
# The server cert (1.4e) already includes host.k3d.internal in its SANs,
# so TLS verification works against this name out of the box.

version='1.3.0'
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Credentials live at repo-root ./Creds/elt/ — see 1.4b for rationale.
CRED_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/Creds/elt"

CERT="$CRED_DIR/ce-eltadmin.crt"
KEY="$CRED_DIR/ce-eltadmin.key"
CA="$CRED_DIR/ce-managementca.crt"
HOST="${HOST:-https://host.k3d.internal:8443}"
REST="$HOST/ejbca/ejbca-rest-api"
ADMINWEB="$HOST/ejbca/adminweb/"

if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
    echo "ERROR: $CERT or $KEY missing — run 1.4b first" >&2
    exit 1
fi

# - Formatting:
f_indent () { 
    local c="$1";
    local str;
    if [[ -z "${c}" ]]; then
        c=4;
    fi;
    str=$(printf "%${c}s");
    sed -e "s/^/${str}/;"
}

# probe URL with client cert — expect 200 on authenticated paths.
# Echoes the literal curl command before running, so the operator can copy-
# paste and iterate by hand.

probe() {
    local label="$1" url="$2"
    echo
    printf "  \$ curl -sk --cert \"\$CERT\" --key \"\$KEY\" --cacert \"\$CA\" '%s'\n" "$url"
    printf "    %s\n" "$label"
    set +e
    code=$(curl -sk --cert "$CERT" --key "$KEY" --cacert "$CA" \
        -o /tmp/claude/elt/probe.body -w "%{http_code}" "$url")
    set -e
    printf "    HTTP %s\n" "$code"
    if [ "$code" = "200" ] && [ -s /tmp/claude/elt/probe.body ]; then
        ## head -c 200 /tmp/claude/elt/probe.body | sed 's/^/      /'
        set +e
        out=$( jq -S . /tmp/claude/elt/probe.body 2>&1 )
        rc=$?
        set -e
        if [[ $rc -eq 0 ]]; then
            echo "${out}" | f_indent 4
        else
            head /tmp/claude/elt/probe.body | cut -c1-80 | f_indent 4
        fi
        ## echo
    fi
}

# probe URL with NO client cert — expect denial.
# Wrinkle: EJBCA's REST gate returns 403 (HTTP-layer), but adminweb's gate
# returns 200 with an "Authorization Denied" HTML body (application-layer).
# So we check status code AND body content, accepting either form of denial.

probe_nocert() {
    local label="$1" url="$2"
    echo
    printf "  %s\n" "$label"
    printf "  \$ curl -sk --cacert \"\$CA\" '%s'\n" "$url"
    printf "    %s\n" "$label"
    set +e
    code=$(curl -sk --cacert "$CA" \
        -o /tmp/claude/elt/probe.body -w "%{http_code}" "$url")
    set -e
    local denied=0
    [ "$code" != "200" ] && denied=1
    if grep -qE 'Authorization Denied|No client certificate|access.*denied' /tmp/claude/elt/probe.body 2>/dev/null; then
        denied=1
    fi
    if [ "$denied" -eq 1 ]; then
        if [ "$code" = "200" ]; then
            printf "    HTTP %s  (200 but body = access denied → mTLS gate working)\n" "$code"
        else
            printf "    HTTP %s  (denied — mTLS gate working)\n" "$code"
        fi
    else
        printf "    HTTP %s  (UNEXPECTED — body shows authenticated content; mTLS may be OPEN)\n" "$code"
    fi
}

mkdir -p /tmp/claude/elt
echo
echo "=== Environment for copy-paste curl ==="
echo "    export CERT='$CERT'"
echo "    export KEY='$KEY'"
echo "    export CA='$CA'"
echo "    # (host.k3d.internal must resolve — add to /etc/hosts: 127.0.0.1 host.k3d.internal)"

echo
echo "=== mTLS probes with admin client cert (expect 200s) ==="
probe "GET /ejbca/adminweb/"                                     "$ADMINWEB"
probe "GET /ejbca/ejbca-rest-api/v1/ca"                          "$REST/v1/ca"
probe "GET /ejbca/ejbca-rest-api/v1/ca/status"                   "$REST/v1/ca/status"
probe "GET /ejbca/ejbca-rest-api/v2/endentity/status"            "$REST/v2/endentity/status"
probe "GET /ejbca/ejbca-rest-api/v2/endentity/profiles/auth..."  "$REST/v2/endentity/profiles/authorized/"

echo
echo "=== mTLS negative probes — no client cert (expect non-200) ==="
probe_nocert "GET /ejbca/adminweb/                              " "$ADMINWEB"
probe_nocert "GET /ejbca/ejbca-rest-api/v1/ca                    " "$REST/v1/ca"

rm -f /tmp/claude/elt/probe.body
echo
echo "==================== 1.4d complete ===================="
echo

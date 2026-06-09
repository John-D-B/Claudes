#!/usr/bin/env bash
# 141.fix-26-integration-test.sh — exercises the new
# DELETE /v1/certificate/{issuer_dn}/{cert_serial_number} REST endpoint
# added in task 3.6, plus its 404 / 409 error branches.
#
# See Docs/ejbca-ce-task-3.7-fix-26-test-plan.md for full design.
#
# Prereqs:
#   - Stack is up (./stack/docker-compose.yml).
#   - Stack is running ejbca-ce:local-fixes (otherwise the DELETE endpoint
#     doesn't exist and T5 will fail).
#   - ./Creds/elt/ce-eltadmin.{crt,key} present (run 1.4b if not).
#   - ./Bin/elt/ce-target.env present (committed default).
#
# Exit 0 on full pass, 1 on any failure.

version='2.5.0'   # 2.5.0 — wait for the tee subprocess to flush before the
                  #         script exits, so the operator's bash prompt
                  #         appears immediately after the summary instead of
                  #         needing a return-key nudge. Caused by tee living
                  #         in a process substitution the shell doesn't
                  #         track as a job; fix is an EXIT trap that closes
                  #         our stdout/stderr and waits on tee's PID.
                  # 2.4.0 — full run output is now tee'd to $TMP_DIR/run.log
                  #         in real time. Operator sees the same output on
                  #         their terminal AND has a captured copy alongside
                  #         the per-call body/code artifacts for later review
                  #         or sharing.
                  # 2.3.0 — BYOC mode iterates over ALL R/r revoked certs
                  #         for the same EE, deleting each in turn (T5.N) and
                  #         verifying each is gone (T6.N). Previously it only
                  #         deleted the first revoked cert found. T9's active-
                  #         cert 409 test still picks the first 'A' cert.
                  # 2.2.0 — visibility polish: every echoed command appears
                  #         on its own line with a `$ ` prompt prefix, and
                  #         every curl call prints its HTTP code on the
                  #         next line, so operators see the request and
                  #         response status at a glance.
                  # 2.1.0 — BYOC mode: operator can target existing certs
                  #         created elsewhere (e.g. deploy_ejbca_k8s.py with
                  #         cert-manager) via --ee-username + --elt. Script
                  #         uses ELT to discover an Active serial (for T9/409)
                  #         and a Revoked serial (for T5/204), expands the
                  #         short CA name to the full DN via /v1/ca, and
                  #         prints elt-style before/after cert views around
                  #         each DELETE. Self-provision mode (no args) is
                  #         unchanged. --reaper-ok is required in BYOC mode
                  #         to acknowledge the DBMS Reaper service is INACTIVE
                  #         (so it doesn't sweep test certs out from under the
                  #         assertions). ELT path resolved via PATH lookup of
                  #         `ejbca-lifecycle-tool.py`, falling back to the
                  #         project's ./elt/ symlink. ELT_* env vars exported
                  #         to child processes via `set -a` in target-config load.
                  # 1.1.0 — write .password sibling for every .p12;
                  #         rename last-body.txt → last-body.json (REST returns JSON);
                  #         ensure trailing newlines on text writes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

VENV_PY="./.venv/bin/python"
STACK_DIR="./stack"
EJBCA="/opt/keyfactor/bin/ejbca.sh"

# ---------- CLI parsing ----------
BYOC_EE_USERNAME=""
BYOC_ELT_PATH=""
BYOC_REAPER_OK=""

usage() {
    cat <<EOF
Usage: ${0##*/} [OPTIONS]

Without options: enrolls fresh EEs in EJBCA, runs T1-T9 self-contained.

BYOC mode — target existing certs created by an operator workflow
(e.g. deploy_ejbca_k8s.py with cert-manager). Uses ELT to discover
which serial to delete and which serial to test for 409:

  --ee-username NAME       EE whose certs to test (required)
  -e, --elt [PATH]         ELT executable (default: ./elt/ejbca-lifecycle-tool.py)
                           When given, enables BYOC mode.
  --reaper-ok              Acknowledge that the DBMS Reaper service is
                           INACTIVE before running. Required in BYOC mode
                           so the Reaper doesn't sweep test certs out from
                           under the assertions.

Other:
  -h, --help               This message
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --ee-username)
            BYOC_EE_USERNAME="${2:-}"; shift 2 ;;
        -e|--elt)
            # Optional path argument: if the next arg doesn't start with -,
            # consume it as the path. Otherwise, resolve via PATH first
            # (operator's installed copy), falling back to the project's
            # ./elt/ symlink if PATH lookup misses.
            if [ "${2:-}" != "" ] && [ "${2:0:1}" != "-" ]; then
                BYOC_ELT_PATH="$2"; shift 2
            else
                if command -v ejbca-lifecycle-tool.py >/dev/null 2>&1; then
                    BYOC_ELT_PATH="$(command -v ejbca-lifecycle-tool.py)"
                else
                    BYOC_ELT_PATH="./elt/ejbca-lifecycle-tool.py"
                fi
                shift 1
            fi ;;
        --reaper-ok)
            BYOC_REAPER_OK="yes"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "ERROR: unrecognised argument: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

# Determine mode + validate flag combinations.
if [ -n "$BYOC_EE_USERNAME" ] || [ -n "$BYOC_ELT_PATH" ]; then
    MODE="BYOC"
    if [ -z "$BYOC_EE_USERNAME" ] || [ -z "$BYOC_ELT_PATH" ]; then
        echo "ERROR: BYOC mode requires BOTH --ee-username and --elt" >&2
        exit 2
    fi
    if [ ! -x "$BYOC_ELT_PATH" ] && [ ! -f "$BYOC_ELT_PATH" ]; then
        echo "ERROR: --elt $BYOC_ELT_PATH is not executable or does not exist" >&2
        exit 2
    fi
    if [ "$BYOC_REAPER_OK" != "yes" ]; then
        cat >&2 <<'EOF'
ERROR: BYOC mode requires --reaper-ok to acknowledge the DBMS Reaper
service is inactive. The Reaper would otherwise sweep test certs out
from under the assertions, producing flaky 404s on certs we expect
to still be present at T5.

Make the Reaper service "Active = false" in the admin GUI (or delete
it outright), then re-run with --reaper-ok.
EOF
        exit 4
    fi
else
    MODE="SELFPROV"
fi

# Per-run unique tag so successive runs don't collide on EE names / tmp dirs.
RUN_TAG="$(date +%Y%m%d-%H%M%S)"
EE_HAPPY="delete-happy-${RUN_TAG}"
EE_409="delete-409-${RUN_TAG}"
EE_PASSWORD="ittest$RUN_TAG"      # >= 6 chars, keytool-compatible
CA_NAME="ManagementCA"
TMP_DIR="/tmp/claude/elt/3.7-$RUN_TAG"
mkdir -p "$TMP_DIR"

# Capture the full run output to a log file in the run's temp dir,
# while still streaming to the operator's terminal in real time.
#
# `exec > >(tee ...) 2>&1` runs tee as a process substitution — a background
# process the shell does NOT track as a job. Without help, the script exits
# and the parent shell prints its next prompt before tee has flushed its
# last bytes; operator perceives a "hang" until they press Enter. The trap
# below captures tee's PID right after the exec, then on script exit closes
# our stdout/stderr (so tee sees EOF) and waits for tee to drain.
LOG_FILE="$TMP_DIR/run.log"
exec > >(tee "$LOG_FILE") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT

# ---------- result tracking ----------
PASS=0
FAIL=0
declare -a SUMMARY

record_pass() { PASS=$((PASS+1)); SUMMARY+=("$1  PASS  $2"); printf "  [PASS]\n"; }
record_fail() { FAIL=$((FAIL+1)); SUMMARY+=("$1  FAIL  $2"); printf "  [FAIL]\n"; }

# ---------- target config ----------
load_target_config() {
    local cfg="./Bin/elt/ce-target.env"
    if [ ! -f "$cfg" ]; then
        echo "ERROR: $cfg not present" >&2; exit 3
    fi
    unset ELT_HOST ELT_PORT ELT_CERT ELT_KEY ELT_CA_CERT ELT_VERIFY_SSL ELT_PROXY
    # shellcheck disable=SC1090
    # `set -a` auto-exports every var assigned in the sourced file, so
    # child processes (ELT subprocess invocations) inherit ELT_HOST etc.
    set +u; set -a; . "$cfg"; set +a; set -u
    if [ ! -f "$ELT_CERT" ] || [ ! -f "$ELT_KEY" ]; then
        echo "ERROR: client cert/key not found at $ELT_CERT / $ELT_KEY (run 1.4b)" >&2
        exit 3
    fi
}

# ---------- curl helper ----------
# curl_ejbca <method> <path-with-encoded-pathparams> [-d body]
# Writes HTTP code to $TMP_DIR/last-code.txt and body to $TMP_DIR/last-body.txt.
# Prints body to stdout. Callers read HTTP_CODE via http_code_last().
HTTP_CODE=""
curl_ejbca() {
    local method="$1" path="$2"; shift 2
    local verify=""
    [ "${ELT_VERIFY_SSL:-}" = "no" ] && verify="-k"
    local ca_arg=""
    [ -n "${ELT_CA_CERT:-}" ] && [ -z "$verify" ] && ca_arg="--cacert $ELT_CA_CERT"
    local url="https://${ELT_HOST}:${ELT_PORT:-443}/ejbca/ejbca-rest-api${path}"
    # REST endpoint returns JSON → suffix is .json, not .txt.
    local body_file="$TMP_DIR/last-body.json"
    local code_file="$TMP_DIR/last-code.txt"
    local code
    code=$(curl -sS -o "$body_file" -w "%{http_code}" \
        --cert "$ELT_CERT" --key "$ELT_KEY" \
        $verify $ca_arg \
        -X "$method" "$url" "$@" 2>/dev/null) || code="000"
    # Ensure trailing newlines on text artifacts.
    printf "%s\n" "$code" > "$code_file"
    [ -s "$body_file" ] && [ "$(tail -c 1 "$body_file" | od -An -c | tr -d ' ')" != '\n' ] \
        && printf "\n" >> "$body_file"
    # Visibility: echo the HTTP code on its own line right after curl runs,
    # so operators see request + response status inline in the test output.
    echo "  - http_code: $code" >&2
    cat "$body_file"
}
http_code_last() { cat "$TMP_DIR/last-code.txt" 2>/dev/null | tr -d '\n' || echo "000"; }

# ---------- EE / cert provisioning ----------
# Create EE + batch-generate a P12; copy out, extract cert.
provision_ee() {
    local user="$1"
    local p12_local="$TMP_DIR/${user}.p12"
    local pwd_local="$TMP_DIR/${user}.password"
    local crt_local="$TMP_DIR/${user}.crt"
    # DEV/TEST p12s are written with their cleartext password sibling so a
    # human looking at /tmp/claude/elt/... can open them without guessing.
    printf "%s\n" "$EE_PASSWORD" > "$pwd_local"
    pushd "$STACK_DIR" >/dev/null
    docker compose exec -T ejbca "$EJBCA" ra addendentity \
        --username "$user" \
        --dn "CN=$user" \
        --caname "$CA_NAME" \
        --type 1 \
        --token P12 \
        --password "$EE_PASSWORD" \
        --certprofile ENDUSER \
        --eeprofile EMPTY 2>&1 | grep -v "log4j\|FIPS" || true
    docker compose exec -T ejbca "$EJBCA" ra setclearpwd "$user" "$EE_PASSWORD" \
        2>&1 | grep -v "log4j\|FIPS" || true
    docker compose exec -T ejbca "$EJBCA" batch "$user" \
        2>&1 | grep -v "log4j\|FIPS" || true
    # Locate keystore (could be .p12 or .jks depending on EJBCA defaults).
    local ks_in
    ks_in=$(docker compose exec -T ejbca sh -c "
        for ext in p12 jks; do
            f=/opt/keyfactor/p12/${user}.\$ext
            [ -f \"\$f\" ] && { echo \"\$f\"; exit 0; }
        done" | tr -d '\r')
    if [ -z "$ks_in" ]; then
        popd >/dev/null
        return 1
    fi
    local ks_ext="${ks_in##*.}"
    if [ "$ks_ext" = "p12" ]; then
        docker compose cp "ejbca:$ks_in" "$p12_local"
    else
        local jks_local="$TMP_DIR/${user}.jks"
        docker compose cp "ejbca:$ks_in" "$jks_local"
        keytool -importkeystore \
            -srckeystore "$jks_local" -srcstoretype JKS -srcstorepass "$EE_PASSWORD" \
            -destkeystore "$p12_local" -deststoretype PKCS12 -deststorepass "$EE_PASSWORD" \
            -noprompt >/dev/null 2>&1
    fi
    popd >/dev/null
    openssl pkcs12 -in "$p12_local" -nokeys -clcerts -passin "pass:$EE_PASSWORD" \
        -out "$crt_local" 2>/dev/null
    [ -s "$crt_local" ]
}

# Extract issuer DN and serial-hex from a provisioned cert.
# Sets globals: ISSUER_DN, SERIAL_HEX
extract_cert_meta() {
    local user="$1"
    local crt="$TMP_DIR/${user}.crt"
    # Subject of the issuer = -issuer; format RFC2253 to match EJBCA storage.
    ISSUER_DN=$(openssl x509 -in "$crt" -noout -issuer -nameopt RFC2253 \
        | sed 's/^issuer=//')
    # Serial in hex, no colons, lower-case (matching EJBCA REST convention).
    SERIAL_HEX=$(openssl x509 -in "$crt" -noout -serial | sed 's/^serial=//' | tr 'A-F' 'a-f')
}

# URL-encode a string via Python (handles commas/spaces in the DN).
urlenc() {
    "$VENV_PY" -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"
}

# ---------- ELT helpers (BYOC mode) ----------

# Print one cert's full ELT view ("before"/"after" visibility around DELETE).
elt_show() {
    local label="$1" serial="$2"
    printf "  [%s]\n  \$ elt list4 -ee-username %s -cert-serial %s -c1\n" \
        "$label" "$BYOC_EE_USERNAME" "$serial"
    "$BYOC_ELT_PATH" list4 -ee-username "$BYOC_EE_USERNAME" \
        -cert-serial "$serial" -c1 2>&1 \
        | sed 's/^/    /'
}

# Discover {active, revoked} serials by parsing `elt list4 -F` table output.
# Sets:
#   ACTIVE_SERIAL    — first row whose status column is exactly "A" (one only)
#   REVOKED_SERIALS  — newline-separated list of every row whose status is "R" or "r"
# Empty string / empty list if none.
elt_discover_serials() {
    local listing
    if ! listing=$("$BYOC_ELT_PATH" list4 -ee-username "$BYOC_EE_USERNAME" -F 2>&1); then
        echo "ERROR: ELT invocation failed. Output below:" >&2
        echo "$listing" >&2
        exit 5
    fi
    # Table columns: [#] [S] [Serial] [Not Before...] [Not After...] [CN]
    ACTIVE_SERIAL=$(echo "$listing" | awk '$2=="A" && NF>=6 {print $3; exit}')
    REVOKED_SERIALS=$(echo "$listing" | awk '($2=="R" || $2=="r") && NF>=6 {print $3}')
}

# Extract issuer DN ("CN=ManagementCA") from `elt list4 -c1` detailed output.
# Returns ELT's friendly short form — needs ca_lookup_full_dn() to expand to
# the full DN for the REST API.
elt_extract_issuer_dn() {
    local serial="$1"
    "$BYOC_ELT_PATH" list4 -ee-username "$BYOC_EE_USERNAME" \
        -cert-serial "$serial" -c1 2>&1 \
        | awk -F'Issuer:' '/Issuer:/ {sub(/^[[:space:]]+/, "", $2); gsub(/ = /, "=", $2); print $2; exit}'
}

# Resolve a short CA name (e.g. "CN=ManagementCA") to its full subject DN
# (e.g. "O=EJBCA Container Quickstart,CN=ManagementCA,UID=c-03tcha4pt9vhqpew5")
# by listing all CAs via /v1/ca and matching on the CN component. The REST
# cert endpoints (/v1/certificate/{issuer_dn}/{serial}/...) need the full DN.
ca_lookup_full_dn() {
    local short_cn="$1"   # e.g. "CN=ManagementCA"
    local cn_value="${short_cn#CN=}"
    local body
    body=$(curl_ejbca GET "/v1/ca")
    if [ "$(http_code_last)" != "200" ]; then
        echo "ERROR: GET /v1/ca returned $(http_code_last)" >&2
        return 1
    fi
    # JSON-parse: find the CA object whose subject_dn contains "CN=<cn_value>".
    "$VENV_PY" -c "
import json, sys
data = json.loads('''$body''')
target = 'CN=$cn_value'
for ca in data.get('certificate_authorities', []) or []:
    if target in (ca.get('subject_dn') or ''):
        print(ca['subject_dn'])
        sys.exit(0)
sys.exit(1)
"
}

# ---------- test cases ----------
load_target_config

echo "==> 3.7 fix-26 integration test  v${version}   [mode: $MODE]"
echo "    Run tag: $RUN_TAG"
if [ "$MODE" = "BYOC" ]; then
    echo "    EE:       $BYOC_EE_USERNAME"
    echo "    ELT:      $BYOC_ELT_PATH"
else
    echo "    EE-happy: $EE_HAPPY"
    echo "    EE-409:   $EE_409"
fi
echo "    Tmp:      $TMP_DIR"
echo

if [ "$MODE" = "BYOC" ]; then
    # ===================== BYOC mode =====================
    # Discover serials via ELT, extract issuer from ELT detailed view.
    printf "\n--- B1 — Discover serials via ELT for EE %s ---\n" "$BYOC_EE_USERNAME"
    elt_discover_serials
    if [ -z "$REVOKED_SERIALS" ] && [ -z "$ACTIVE_SERIAL" ]; then
        echo "ERROR: ELT returned no Active and no Revoked certs for $BYOC_EE_USERNAME" >&2
        record_fail "B1" "ELT empty result"
    fi
    # Count revoked serials for the iteration label.
    REVOKED_COUNT=$(echo "$REVOKED_SERIALS" | grep -c .) || REVOKED_COUNT=0
    if [ -n "$REVOKED_SERIALS" ]; then
        echo "    Revoked serials (for T5.N/T6.N DELETE — $REVOKED_COUNT total):"
        echo "$REVOKED_SERIALS" | awk '{print "        " $0}'
        FIRST_REVOKED=$(echo "$REVOKED_SERIALS" | head -1)
        ISSUER_SHORT=$(elt_extract_issuer_dn "$FIRST_REVOKED")
    fi
    if [ -n "$ACTIVE_SERIAL" ]; then
        echo "    Active  serial (for T9 409):       $ACTIVE_SERIAL"
        [ -z "${ISSUER_SHORT:-}" ] && ISSUER_SHORT=$(elt_extract_issuer_dn "$ACTIVE_SERIAL")
    fi
    echo "    Issuer (ELT short form):           ${ISSUER_SHORT:-(unknown)}"
    # Expand the short form to the full DN that the REST cert endpoints expect.
    ISSUER_DN=$(ca_lookup_full_dn "${ISSUER_SHORT:-}") || ISSUER_DN=""
    echo "    Issuer (full DN, from /v1/ca):     ${ISSUER_DN:-(lookup failed)}"
    if [ -n "${REVOKED_SERIALS:-}" ] || [ -n "${ACTIVE_SERIAL:-}" ]; then
        if [ -n "$ISSUER_DN" ]; then
            record_pass "B1" "ELT discovery + CA full-DN lookup ($REVOKED_COUNT revoked + ${ACTIVE_SERIAL:+1} active)"
        else
            record_fail "B1" "CA full-DN lookup failed for $ISSUER_SHORT"
        fi
    fi
    ISSUER_ENC=$(urlenc "${ISSUER_DN:-}")

    if [ -n "$REVOKED_SERIALS" ]; then
        idx=0
        while IFS= read -r revoked_serial; do
            [ -z "$revoked_serial" ] && continue
            idx=$((idx + 1))
            CERT_PATH="/v1/certificate/${ISSUER_ENC}/${revoked_serial}"

            printf "\n--- B2.%d — ELT before T5.%d DELETE (revoked serial %s) ---\n" \
                "$idx" "$idx" "$revoked_serial"
            elt_show "before" "$revoked_serial"

            printf "\n--- T4.%d — GET revocationstatus, confirm revoked=true ---\n" "$idx"
            echo
            echo "  \$ curl -X GET ${CERT_PATH}/revocationstatus"
            BODY=$(curl_ejbca GET "${CERT_PATH}/revocationstatus")
            if [ "$(http_code_last)" = "200" ] && echo "$BODY" | grep -q '"revoked"[[:space:]]*:[[:space:]]*true'; then
                record_pass "T4.$idx" "revocationstatus revoked=true ($revoked_serial)"
            else
                record_fail "T4.$idx" "revocationstatus $revoked_serial (http=$(http_code_last) body=$BODY)"
            fi

            printf "\n--- T5.%d — DELETE the revoked cert (the NEW endpoint) ---\n" "$idx"
            echo
            echo "  \$ curl -X DELETE ${CERT_PATH}"
            BODY=$(curl_ejbca DELETE "${CERT_PATH}")
            if [ "$(http_code_last)" = "204" ]; then
                record_pass "T5.$idx" "DELETE 204 ($revoked_serial)"
            else
                record_fail "T5.$idx" "DELETE $revoked_serial (http=$(http_code_last) body=$BODY)"
            fi

            printf "\n--- T6.%d — GET revocationstatus on deleted cert, expect 404 ---\n" "$idx"
            echo
            echo "  \$ curl -X GET ${CERT_PATH}/revocationstatus"
            BODY=$(curl_ejbca GET "${CERT_PATH}/revocationstatus")
            if [ "$(http_code_last)" = "404" ]; then
                record_pass "T6.$idx" "post-delete 404 ($revoked_serial)"
            else
                record_fail "T6.$idx" "post-delete $revoked_serial (http=$(http_code_last) body=$BODY)"
            fi

            printf "\n--- B3.%d — ELT after T5.%d DELETE (%s should be gone) ---\n" \
                "$idx" "$idx" "$revoked_serial"
            elt_show "after" "$revoked_serial"
        done <<< "$REVOKED_SERIALS"
    else
        echo "[skip] T4/T5/T6 — no revoked cert found by ELT for $BYOC_EE_USERNAME"
    fi

    printf "\n--- T7 — DELETE on bogus serial, expect 404 ---\n"
    BOGUS_PATH="/v1/certificate/${ISSUER_ENC}/deadbeef00000000"
    echo
    echo "  \$ curl -X DELETE ${BOGUS_PATH}"
    BODY=$(curl_ejbca DELETE "$BOGUS_PATH")
    if [ "$(http_code_last)" = "404" ]; then
        record_pass "T7" "bogus-serial 404"
    else
        record_fail "T7" "bogus-serial (http=$(http_code_last) body=$BODY)"
    fi

    if [ -n "$ACTIVE_SERIAL" ]; then
        PATH_409="/v1/certificate/${ISSUER_ENC}/${ACTIVE_SERIAL}"

        printf "\n--- B4 — ELT before T9 DELETE (active serial %s) ---\n" "$ACTIVE_SERIAL"
        elt_show "before" "$ACTIVE_SERIAL"

        printf "\n--- T9 — DELETE unrevoked (active) cert, expect 409 ---\n"
        echo
        echo "  \$ curl -X DELETE ${PATH_409}"
        BODY=$(curl_ejbca DELETE "$PATH_409")
        if [ "$(http_code_last)" = "409" ]; then
            record_pass "T9" "unrevoked → 409"
        else
            record_fail "T9" "unrevoked (http=$(http_code_last) body=$BODY)"
        fi

        printf "\n--- B5 — ELT after T9 DELETE (active serial %s should still exist) ---\n" "$ACTIVE_SERIAL"
        elt_show "after" "$ACTIVE_SERIAL"
    else
        echo "[skip] T9 — no active cert found by ELT for $BYOC_EE_USERNAME"
    fi

else
    # ===================== Self-provision mode (v1 behavior) =====================
printf "\n--- T1 — Enroll happy-path EE %s ---\n" "$EE_HAPPY"
if provision_ee "$EE_HAPPY"; then record_pass "T1" "enroll $EE_HAPPY"; else record_fail "T1" "enroll $EE_HAPPY"; fi

extract_cert_meta "$EE_HAPPY"
ISSUER_ENC=$(urlenc "$ISSUER_DN")
PATH_HAPPY="/v1/certificate/${ISSUER_ENC}/${SERIAL_HEX}"

printf "\n--- T2 — GET revocationstatus, expect revoked=false ---\n"
BODY=$(curl_ejbca GET "${PATH_HAPPY}/revocationstatus")
if [ "$(http_code_last)" = "200" ] && echo "$BODY" | grep -q '"revoked"[[:space:]]*:[[:space:]]*false'; then
    record_pass "T2" "revocationstatus revoked=false"
else
    record_fail "T2" "revocationstatus (http=$(http_code_last) body=$BODY)"
fi

printf "\n--- T3 — PUT .../revoke?reason=SUPERSEDED ---\n"
BODY=$(curl_ejbca PUT "${PATH_HAPPY}/revoke?reason=SUPERSEDED")
if [ "$(http_code_last)" = "200" ] && echo "$BODY" | grep -q '"revoked"[[:space:]]*:[[:space:]]*true'; then
    record_pass "T3" "revoke 200"
else
    record_fail "T3" "revoke (http=$(http_code_last) body=$BODY)"
fi

printf "\n--- T4 — GET revocationstatus, expect revoked=true ---\n"
BODY=$(curl_ejbca GET "${PATH_HAPPY}/revocationstatus")
if [ "$(http_code_last)" = "200" ] && echo "$BODY" | grep -q '"revoked"[[:space:]]*:[[:space:]]*true'; then
    record_pass "T4" "revocationstatus revoked=true"
else
    record_fail "T4" "revocationstatus (http=$(http_code_last) body=$BODY)"
fi

printf "\n--- T5 — DELETE the revoked cert (the NEW endpoint) ---\n"
BODY=$(curl_ejbca DELETE "${PATH_HAPPY}")
if [ "$(http_code_last)" = "204" ]; then
    record_pass "T5" "DELETE 204"
else
    record_fail "T5" "DELETE (http=$(http_code_last) body=$BODY)"
fi

printf "\n--- T6 — GET revocationstatus on deleted cert, expect 404 ---\n"
BODY=$(curl_ejbca GET "${PATH_HAPPY}/revocationstatus")
if [ "$(http_code_last)" = "404" ]; then
    record_pass "T6" "post-delete 404"
else
    record_fail "T6" "post-delete (http=$(http_code_last) body=$BODY)"
fi

printf "\n--- T7 — DELETE on bogus serial, expect 404 ---\n"
BOGUS_PATH="/v1/certificate/${ISSUER_ENC}/deadbeef00000000"
BODY=$(curl_ejbca DELETE "$BOGUS_PATH")
if [ "$(http_code_last)" = "404" ]; then
    record_pass "T7" "bogus-serial 404"
else
    record_fail "T7" "bogus-serial (http=$(http_code_last) body=$BODY)"
fi

printf "\n--- T8 — Enroll 409-path EE %s (not revoked) ---\n" "$EE_409"
if provision_ee "$EE_409"; then record_pass "T8" "enroll $EE_409"; else record_fail "T8" "enroll $EE_409"; fi

extract_cert_meta "$EE_409"
PATH_409="/v1/certificate/$(urlenc "$ISSUER_DN")/${SERIAL_HEX}"

printf "\n--- T9 — DELETE unrevoked cert, expect 409 ---\n"
BODY=$(curl_ejbca DELETE "$PATH_409")
if [ "$(http_code_last)" = "409" ]; then
    record_pass "T9" "unrevoked → 409"
else
    record_fail "T9" "unrevoked (http=$(http_code_last) body=$BODY)"
fi
fi   # end of MODE branch

# ---------- summary ----------
echo
echo "==================== 3.7 summary ===================="
for line in "${SUMMARY[@]}"; do echo "  $line"; done
echo
printf "  Totals: PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
echo "====================================================="
echo
echo "  Run log: $LOG_FILE"

[ "$FAIL" -eq 0 ]

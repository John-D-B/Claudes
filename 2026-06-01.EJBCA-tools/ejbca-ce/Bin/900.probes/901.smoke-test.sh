#!/usr/bin/env bash
# 901.smoke-test.sh — automated runner for the v4.0.0 smoke test plan
# defined in Docs/ejbca-ce-task-5.7-smoke-test-plan.md.
#
# Usage:
#   ./Bin/900.probes/901.smoke-test.sh                  # default: --target ce
#   ./Bin/900.probes/901.smoke-test.sh --target ce
#   ./Bin/900.probes/901.smoke-test.sh --target ee
#
# For --target ee, the EE coordinates must come from one of:
#   1. Shell environment (CLI use case):
#        export ELT_HOST=... ELT_CERT=... ELT_KEY=... [ELT_PORT=...] [ELT_CA_CERT=...]
#   2. Sourceable config file (Desktop App use case):
#        ./Bin/elt/ee-target.env       (see ee-target.env.example)
#
# CE target uses ./Creds/elt/ce-eltadmin.{crt,key} (the canonical layout
# produced by step 1.4b).
#
# Exit code: 0 if all automated PASS, 1 if any FAIL or HUMAN-review needed.

version='2.0.0'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

VENV_PY="./.venv/bin/python"
ELT="./elt/ejbca-lifecycle-tool.py"

# ---------- arg parsing ----------
TARGET="ce"
while [ $# -gt 0 ]; do
    case "$1" in
        --target)   TARGET="$2"; shift 2;;
        --target=*) TARGET="${1#--target=}"; shift;;
        -h|--help)  sed -n '2,20p' "$0"; exit 0;;
        *)          echo "Unknown arg: $1" >&2; exit 2;;
    esac
done
if [ "$TARGET" != "ce" ] && [ "$TARGET" != "ee" ]; then
    echo "ERROR: --target must be 'ce' or 'ee' (got: $TARGET)" >&2
    exit 2
fi

# ---------- result tracking ----------
PASS=0
FAIL=0
REVIEW=0
declare -a SUMMARY

# run_test <id> <description> <command> <grep_pattern_for_pass>
#   PASS if pattern matches in combined output; FAIL otherwise.
run_test() {
    local id="$1" desc="$2" cmd="$3" pattern="$4"
    printf "\n--- %s — %s ---\n" "$id" "$desc"
    local out rc=0
    out=$(eval "$cmd" 2>&1) || rc=$?
    if echo "$out" | grep -qE "$pattern"; then
        printf "  [PASS]\n"
        PASS=$((PASS+1)); SUMMARY+=("$id  PASS  $desc")
    else
        printf "  [FAIL] (exit %d, pattern not found: %s)\n" "$rc" "$pattern"
        FAIL=$((FAIL+1)); SUMMARY+=("$id  FAIL  $desc")
        echo "$out" | tail -10 | sed 's/^/  | /'
    fi
}

# run_review <id> <description> <command>
#   Always marked HUMAN-REVIEW; full output printed for grading.
run_review() {
    local id="$1" desc="$2" cmd="$3"
    printf "\n--- %s — %s [HUMAN REVIEW] ---\n" "$id" "$desc"
    eval "$cmd" 2>&1 | sed 's/^/  | /'
    REVIEW=$((REVIEW+1)); SUMMARY+=("$id  REVIEW  $desc")
}

# ---------- Target config loader ----------
# Sources $localDir/<target>-target.env (default ./local) if it exists — the
# env file is the per-target source of truth, and pre-existing shell ELT_*
# vars (eg. leaked in from a prior session) must NOT silently override it.
# Falls back to shell env only when no file is present (CLI use case for
# 5.7 EE-side when ee-target.env hasn't been created).
load_target_config() {
    local target="$1"
    local cfg="${localDir:-./local}/${target}-target.env"
    if [ -f "$cfg" ]; then
        echo "Sourcing $target target from $cfg"
        # Clear any inherited ELT_* vars so the file's values are authoritative.
        unset ELT_HOST ELT_PORT ELT_CERT ELT_KEY ELT_CA_CERT ELT_VERIFY_SSL ELT_PROXY
        # shellcheck disable=SC1090
        set +u; . "$cfg"; set -u
    fi
    if [ -z "${ELT_HOST:-}" ] || [ -z "${ELT_CERT:-}" ] || [ -z "${ELT_KEY:-}" ]; then
        echo "ERROR: $target target not configured. Either create $cfg" >&2
        if [ "$target" = "ee" ]; then
            echo "       (copy Bin/elt/ee-target.env.example to ${localDir:-./local}/ee-target.env)," >&2
        fi
        echo "       or export ELT_HOST, ELT_CERT, ELT_KEY in your shell." >&2
        exit 3
    fi
    if [ ! -f "$ELT_CERT" ] || [ ! -f "$ELT_KEY" ]; then
        echo "ERROR: client cert/key not found at $ELT_CERT / $ELT_KEY" >&2
        [ "$target" = "ce" ] && echo "       (run 1.4b to generate)" >&2
        exit 3
    fi
}

# Build the base ELT invocation from env vars set by load_target_config.
build_base_cmd() {
    local port="${ELT_PORT:-443}"
    local verify_flag=""
    [ "${ELT_VERIFY_SSL:-}" = "no" ] && verify_flag="-no-verify-ssl"
    local ca_arg=""
    [ -n "${ELT_CA_CERT:-}" ] && ca_arg="-ca-cert $ELT_CA_CERT"
    echo "$VENV_PY $ELT list -d1 -v -ejbca-host $ELT_HOST -ejbca-port $port -client-cert $ELT_CERT -client-key $ELT_KEY $verify_flag $ca_arg"
}

# Build a non-list ELT subcommand (count, ping) with the same connection args.
build_subcmd() {
    local subcmd="$1"
    local port="${ELT_PORT:-443}"
    local verify_flag=""
    [ "${ELT_VERIFY_SSL:-}" = "no" ] && verify_flag="-no-verify-ssl"
    local ca_arg=""
    [ -n "${ELT_CA_CERT:-}" ] && ca_arg="-ca-cert $ELT_CA_CERT"
    echo "$VENV_PY $ELT $subcmd -v -ejbca-host $ELT_HOST -ejbca-port $port -client-cert $ELT_CERT -client-key $ELT_KEY $verify_flag $ca_arg"
}

# ---------- CE tests ----------
ce_tests() {
    load_target_config ce
    local base; base=$(build_base_cmd)

    run_test "C1" "Auto-detect picks SOAP (CE)" \
        "$base" \
        "Auto-detect: .*SOAP backend"

    run_test "C2" "--zeep forces SOAP" \
        "$base --zeep" \
        "SOAP backend active"

    run_test "C3" "ELT_BACKEND=soap env var" \
        "ELT_BACKEND=soap $base" \
        "SOAP backend active"

    run_test "C4" "--rest forces REST (expected REST-side failure on CE)" \
        "$base --rest" \
        "Could not retrieve authorized profiles"

    # C5: mutex check. Expect ELT to exit non-zero.
    run_test "C5" "--zeep --rest rejected (mutually exclusive)" \
        "! $VENV_PY $ELT list --zeep --rest" \
        ".*"
}

# ---------- EE tests ----------
ee_tests() {
    load_target_config ee
    local base; base=$(build_base_cmd)

    run_test "E1" "Auto-detect picks REST (EE)" \
        "$base" \
        "Management REST OK|REST backend"

    run_test "E2" "--rest forces REST" \
        "$base --rest" \
        "EE Profile Name|Total: .* profiles"

    # E3 vs E1: REST and SOAP outputs need human review for logical equivalence.
    run_review "E3" "--zeep forces SOAP (compare logical equivalence vs E1)" \
        "$base --zeep"

    run_review "E4" "count -v (REST default — compare to v3.15.0 baseline)" \
        "$(build_subcmd count)"

    run_review "E5" "ping -v (REST-specific diagnostic)" \
        "$(build_subcmd ping)"

    run_review "E6" "list -d3 (REST default — compare to v3.15.0 baseline)" \
        "$(build_subcmd 'list -d3')"
}

# ---------- main ----------
echo "================================================================"
echo "ELT v4.0.0 smoke test — target: $TARGET"
echo "================================================================"

case "$TARGET" in
    ce) ce_tests;;
    ee) ee_tests;;
esac

echo
echo "================================================================"
echo "SUMMARY"
echo "================================================================"
for line in "${SUMMARY[@]}"; do echo "  $line"; done
printf "\n  Totals: %d PASS, %d FAIL, %d HUMAN-REVIEW\n" "$PASS" "$FAIL" "$REVIEW"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
if [ "$REVIEW" -gt 0 ]; then
    echo "  (HUMAN-REVIEW items printed above need grading — see test plan §4)"
fi
echo
exit 0

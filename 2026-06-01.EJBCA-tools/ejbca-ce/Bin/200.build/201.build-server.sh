#!/usr/bin/env bash
# 201.build-server.sh — build the EJBCA-CE server from scratch (storyboard
# B01-B06): wipe the stack + DB volume, recreate the containers, wait for the
# app to deploy, run the bootstrap (Bin/210.bootstrap/*.sh), then collect the
# working certs (Bin/220.certs/221.collect-certs.sh).
#
# Lives in Bin/200.build/ so it sits OUTSIDE the 210.bootstrap glob it drives.
# Destructive: `docker compose down -v` wipes the running server + database.
# "From scratch" includes the image: the compose image: line is reset to the
# upstream base before boot, undoing any prior 232 swap to ejbca-ce:local-fixes.
#
# Self-completing by design: a fresh bootstrap mints a NEW ManagementCA, so the
# cert collect (step 5) MUST follow it in the same run — otherwise the collected
# certs go stale and `ejbca-lifecycle-tool.py count` fails TLS verification.

version='1.3.0'   # 1.3.0 — self-log the run to $logDir/B01-build-server.log (the run book's named log).
                  # 1.2.0 — collect certs (221) as the final build step, so the
                  #         result is immediately usable (no stale-CA gap).
                  # 1.1.0 — reset compose image to upstream base on wipe.

set -euo pipefail

HOST="${HOST:-host.k3d.internal}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"
COMPOSE="stack/docker-compose.yml"
BASE_IMAGE="${BASE_IMAGE:-keyfactor/ejbca-ce:latest}"   # 232 may have swapped this to local-fixes

# Self-log: tee this run to $logDir (out-of-repo), so the run book's reader gets
# his own named log. The trap waits for tee to flush so the shell doesn't "hang".
logDir="${logDir:-/tmp/claude/demo/logs}"
mkdir -p "$logDir"
exec > >(tee "$logDir/B01-build-server.log") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT
echo "=== logging to $logDir/B01-build-server.log ==="

echo "=== [1/5] Wipe: docker compose down -v + reset image to upstream base ==="
docker compose -f "$COMPOSE" down -v
# Reset the ejbca service's image: line to the upstream base, so re-running this
# orchestrator after a 232 swap really does start from scratch (awk scopes the
# match to the ejbca block and preserves any trailing comment).
awk -v new="$BASE_IMAGE" '
    /^  ejbca:/   { in_ejbca = 1 }
    /^  [a-zA-Z]/ && !/^  ejbca:/ { in_ejbca = 0 }
    in_ejbca && /^    image:/ { sub(/image:[[:space:]]+[^[:space:]#]+/, "image: " new) }
    { print }
' "$COMPOSE" > "$COMPOSE.tmp" && mv "$COMPOSE.tmp" "$COMPOSE"
echo "  compose image reset to: $BASE_IMAGE"

echo "=== [2/5] Create: docker compose up -d ==="
docker compose -f "$COMPOSE" up -d

echo "=== [3/5] Wait for the EJBCA app (AdminWeb 200) on ${HOST}:8443 ==="
for i in $(seq 1 150); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
            https://${HOST}:8443/ejbca/adminweb/ 2>/dev/null || true)
    if [ "$code" = 200 ] || [ "$code" = 302 ]; then
        echo "  app ready: AdminWeb $code after ~$((i * 2))s"
        break
    fi
    if [ "$i" = 150 ]; then
        echo "ERROR: EJBCA app not ready within ~300s" >&2
        exit 1
    fi
    sleep 2
done

echo "=== [4/5] Bootstrap: Bin/210.bootstrap/*.sh ==="
for s in ./Bin/210.bootstrap/*.sh; do
    echo "----- $s -----"
    "$s" || { echo "!! bootstrap FAILED at $s" >&2; exit 1; }
done

echo "=== [5/5] Collect certs: Bin/220.certs/221.collect-certs.sh ==="
./Bin/220.certs/221.collect-certs.sh || { echo "!! cert collection FAILED" >&2; exit 1; }

echo "=== server built, bootstrapped, and certs collected — ready. ==="
echo "    source the ce-target.env printed above, then: ejbca-lifecycle-tool.py count"

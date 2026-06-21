#!/usr/bin/env bash
# 201.build-server.sh — build the EJBCA-CE server from scratch (storyboard
# B01-B05): wipe the stack + DB volume, recreate the containers, wait for the
# app to deploy, then run the bootstrap (Bin/210.bootstrap/*.sh).
#
# Lives in Bin/200.build/ so it sits OUTSIDE the 210.bootstrap glob it drives.
# Destructive: `docker compose down -v` wipes the running server + database.

version='1.0.0'

set -euo pipefail

HOST="${HOST:-host.k3d.internal}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"
COMPOSE="stack/docker-compose.yml"

echo "=== [1/4] Wipe: docker compose down -v ==="
docker compose -f "$COMPOSE" down -v

echo "=== [2/4] Create: docker compose up -d ==="
docker compose -f "$COMPOSE" up -d

echo "=== [3/4] Wait for the EJBCA app (AdminWeb 200) on ${HOST}:8443 ==="
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

echo "=== [4/4] Bootstrap: Bin/210.bootstrap/*.sh ==="
for s in ./Bin/210.bootstrap/*.sh; do
    echo "----- $s -----"
    "$s" || { echo "!! bootstrap FAILED at $s" >&2; exit 1; }
done

echo "=== server built + bootstrapped — next: 221.collect-certs.sh (B06) ==="

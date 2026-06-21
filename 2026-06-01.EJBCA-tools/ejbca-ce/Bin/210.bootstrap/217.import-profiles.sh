#!/usr/bin/env bash
# 217.import-profiles.sh — recreate the ELT-Server certificate + end-entity
# profiles from the checked-in seed XML, so a from-scratch rebuild
# (docker compose down -v) has the profiles that 108 (verify), 109
# (reissue-server-cert), and the k8s cert-manager enrollment depend on.
#
# This is the scripted, one-shot equivalent of the manual admin-GUI
# walkthrough in Docs/ejbca-ce-task-1.5-profile-setup.md. EJBCA CE 9.3.7's
# `ejbca.sh ca importprofiles` recreates both profiles; --caname rebinds the
# end-entity profile's CA reference to the CURRENT ManagementCA, whose caid
# is volatile across fresh installs (its subject DN carries a random UID).
#
# Idempotent: re-importing over existing profiles updates them in place.
# After a GUI edit, re-capture the seed with:
#   ./Bin/210.bootstrap/profiles/export-profiles.sh

version='1.1.0'   # 1.1.0 — self-log to $logDir/B05-import-profiles.log
                  # 1.0.0 — prior

set -euo pipefail

# Self-log this run to $logDir (out-of-repo); trap drains tee so no false "hang".
logDir="${logDir:-/tmp/claude/demo/logs}"; mkdir -p "$logDir"
exec > >(tee "$logDir/B05-import-profiles.log") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT
echo "=== logging to $logDir/B05-import-profiles.log ==="

CA_NAME="${CA_NAME:-ManagementCA}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

COMPOSE="./stack/docker-compose.yml"
EJBCA="/opt/keyfactor/bin/ejbca.sh"
SEED_DIR="$ROOT_DIR/Bin/210.bootstrap/profiles"
CONTAINER_DIR="/tmp/profile-seed"

echo "=== Importing ELT-Server profiles from seed ==="
echo "  seed dir : $SEED_DIR"
echo "  CA name  : $CA_NAME"
echo

# 1. Stage the seed XML inside the ejbca container.
echo "\$ docker compose cp ./Bin/210.bootstrap/profiles/. ejbca:$CONTAINER_DIR/"
docker compose -f "$COMPOSE" exec -T ejbca sh -c "rm -rf $CONTAINER_DIR && mkdir -p $CONTAINER_DIR"
docker compose -f "$COMPOSE" cp "$SEED_DIR/." "ejbca:$CONTAINER_DIR/"

# 2. Import; --caname self-heals the volatile CA reference on a fresh install.
echo "\$ ejbca.sh ca importprofiles -d $CONTAINER_DIR --caname $CA_NAME"
docker compose -f "$COMPOSE" exec -T ejbca \
    "$EJBCA" ca importprofiles -d "$CONTAINER_DIR" --caname "$CA_NAME" 2>&1 \
    | grep -v "log4j\|FIPS" || true

echo
echo "  [done] profiles imported — confirm with 218.verify-profiles.sh"

#!/usr/bin/env bash
# profiles/export-profiles.sh — re-capture the ELT-Server profile seed XML
# from the live EJBCA stack. Run this AFTER editing the profiles in the admin
# GUI, to refresh the checked-in seed that ../217.import-profiles.sh consumes.
#
# Companion to ../217.import-profiles.sh. NOT run by the 210.bootstrap loop: that
# loop globs ./Bin/210.bootstrap/*.sh, which does not descend into this profiles/
# sub-directory.

version='1.0.0'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"            # .../Bin/210.bootstrap/profiles
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$ROOT_DIR"

COMPOSE="./stack/docker-compose.yml"
EJBCA="/opt/keyfactor/bin/ejbca.sh"
SEED_DIR="$SCRIPT_DIR"
EXPORT_DIR="/tmp/profile-export"
STAGE="/tmp/claude/profile-export"

echo "=== Re-exporting ELT-Server profiles to the seed dir ==="
echo "  seed dir : $SEED_DIR"
echo

echo "\$ ejbca.sh ca exportprofiles -d $EXPORT_DIR"
docker compose -f "$COMPOSE" exec -T ejbca sh -c \
    "rm -rf $EXPORT_DIR && mkdir -p $EXPORT_DIR && $EJBCA ca exportprofiles -d $EXPORT_DIR" 2>&1 \
    | grep -i ELT-Server || true

# Pull the full export to a host staging dir, then refresh only the
# ELT-Server seed files (clearing stale XML first, in case a profile was
# recreated under a new id).
rm -rf "$STAGE" && mkdir -p "$STAGE"
docker compose -f "$COMPOSE" cp "ejbca:$EXPORT_DIR/." "$STAGE/"

rm -f "$SEED_DIR"/*.xml
cp "$STAGE"/*ELT-Server* "$SEED_DIR/"

echo
echo "  refreshed seed files:"
ls "$SEED_DIR"/*.xml | sed 's,^,    ,'
echo
echo "  [done] seed refreshed — review and commit the updated XML."

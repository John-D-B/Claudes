#!/usr/bin/env bash
# 122.swap-stack-image.sh — swap the EJBCA container's image and recreate it.
#
# Replaces the manual two-step (edit stack/docker-compose.yml, then
# docker compose up -d --force-recreate ejbca) that the docs used to ask
# the user to do by hand.
#
# Usage:
#   ./Bin/120.rebuild/122.swap-stack-image.sh ejbca-ce:local-fixes
#       Switch to the locally-built patched image (run 3.3 first).
#
#   ./Bin/120.rebuild/122.swap-stack-image.sh keyfactor/ejbca-ce:latest
#       Roll back to the upstream stock image.
#
# Idempotent — if the image in docker-compose.yml already matches the
# target, the file isn't edited; only the container is recreated. Useful
# when an earlier edit put the right image tag in the file but the running
# container is still on something else (typical after 3.3 builds and the
# user wants to load the just-built image without re-touching the file).
#
# What persists across swaps:
#   - mariadb volume (DB state: EEs, certs, roles, ghost-cert corpus)
#   - persistent EJBCA keystore (server cert from 1.4e)
#   - everything outside the EJBCA container
#
# What changes:
#   - The EJBCA service's image: line in stack/docker-compose.yml (only if
#     it doesn't already match the target).
#   - The running EJBCA container (recreated either way).
#
# Backup:
#   When the script edits docker-compose.yml, a timestamped backup
#   `docker-compose.yml.bak.<unix-time>` is written alongside the file.

version='1.0.0'

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
STACK_DIR="$ROOT_DIR/stack"
COMPOSE="$STACK_DIR/docker-compose.yml"
HEALTHCHECK_URL="${HEALTHCHECK_URL:-https://host.k3d.internal:8443/ejbca/adminweb/}"
HEALTHCHECK_TIMEOUT="${HEALTHCHECK_TIMEOUT:-90}"

NEW_IMAGE="${1:-}"
if [ -z "$NEW_IMAGE" ] || [ "$NEW_IMAGE" = "-h" ] || [ "$NEW_IMAGE" = "--help" ]; then
    sed -n '2,30p' "$0"
    exit 0
fi

test -f "$COMPOSE" || { echo "ERROR: $COMPOSE not found" >&2; exit 1; }

# --- read current image ---
# Match the `image:` line inside the `ejbca:` service block. Awk scopes
# the match to the ejbca block to avoid colliding with other services'
# image lines (e.g. mariadb).
CURRENT_IMAGE=$(awk '
    /^  ejbca:/        { in_ejbca = 1; next }
    /^  [a-zA-Z]/      { in_ejbca = 0 }
    in_ejbca && /image:/ { print $2; exit }
' "$COMPOSE")

if [ -z "$CURRENT_IMAGE" ]; then
    echo "ERROR: couldn't find ejbca.image in $COMPOSE" >&2
    exit 1
fi

echo "================================================================"
echo " 3.4 — swap EJBCA stack image"
echo "================================================================"
echo "  Current image (in $COMPOSE): $CURRENT_IMAGE"
echo "  Target image:                $NEW_IMAGE"
echo "================================================================"
echo

# --- edit file if needed ---
if [ "$CURRENT_IMAGE" = "$NEW_IMAGE" ]; then
    echo "[edit] docker-compose.yml already on $NEW_IMAGE — no file change needed."
else
    TS=$(date +%s)
    BACKUP="$COMPOSE.bak.$TS"
    cp "$COMPOSE" "$BACKUP"
    echo "[edit] backup written: $BACKUP"

    # Replace the image VALUE in the ejbca block. Preserve any trailing
    # comment on the same line.
    awk -v new="$NEW_IMAGE" '
        /^  ejbca:/   { in_ejbca = 1 }
        /^  [a-zA-Z]/ && !/^  ejbca:/ { in_ejbca = 0 }
        in_ejbca && /^    image:/ {
            sub(/image:[[:space:]]+[^[:space:]#]+/, "image: " new)
        }
        { print }
    ' "$BACKUP" > "$COMPOSE"

    # Sanity-check the result.
    NEW_LINE=$(awk '
        /^  ejbca:/        { in_ejbca = 1; next }
        /^  [a-zA-Z]/      { in_ejbca = 0 }
        in_ejbca && /image:/ { print; exit }
    ' "$COMPOSE")
    echo "[edit] new ejbca.image line in compose: $NEW_LINE"
fi

# --- recreate the container ---
echo
echo "[recreate] docker compose up -d --force-recreate ejbca"
( cd "$STACK_DIR" && docker compose up -d --force-recreate ejbca )

# --- wait for adminweb to respond ---
echo
echo "[wait] polling $HEALTHCHECK_URL (max ${HEALTHCHECK_TIMEOUT}s)..."
deadline=$(( $(date +%s) + HEALTHCHECK_TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$HEALTHCHECK_URL" || echo "000")
    if echo "$code" | grep -qE '^(200|302|401|403)$'; then
        echo "[wait] EJBCA responding: HTTP $code"
        echo
        echo "================================================================"
        echo " Stack now running: $NEW_IMAGE"
        echo "================================================================"
        exit 0
    fi
    printf "[wait] HTTP %s — retrying...\n" "$code"
    sleep 3
done

echo "ERROR: adminweb not responding after ${HEALTHCHECK_TIMEOUT}s." >&2
echo "       The container may still be coming up; check 'docker compose logs ejbca'." >&2
exit 1

#!/usr/bin/env bash
# 231.build-local-image.sh — build the local ejbca-ce:local-fixes image.
#
# Three steps:
#   0. Fetch the upstream EJBCA-CE source (Keyfactor/ejbca-ce @ EJBCA_REF) into
#      a cache, then apply the bundled PR patches (patches/*.patch), skipping
#      any that are already present upstream (so this keeps working once
#      Keyfactor merges the PRs).
#   1. Gradle build of that source — produces build/libs/ejbca.ear with the fixes.
#   2. Docker build using stack/Dockerfile.local-fixes — overlays that EAR on
#      top of the upstream keyfactor/ejbca-ce:latest base image.
#
# Source location and version are override-able:
#   EJBCA_SRC=/path/to/ejbca-ce   default /tmp/claude/GitHub/ejbca-ce — managed
#                                 here (cloned, checked out at EJBCA_REF, reset).
#                                 A caller-supplied path is used as-is (not reset);
#                                 the bundled patches are applied if not already there.
#   EJBCA_REF=r9.3.7              upstream tag the patches target / base image matches.
#
# Does NOT touch the running stack. Swapping is 232.swap-stack-image.sh.
#
# Usage:
#   ./Bin/230.rebuild/231.build-local-image.sh             # full build (fetch + gradle + docker)
#   ./Bin/230.rebuild/231.build-local-image.sh --skip-ear  # docker step only (reuse last EAR)
#
# Exit 0 on success.

version='1.1.0'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

DEFAULT_SRC="/tmp/claude/GitHub/ejbca-ce"
EJBCA_SRC="${EJBCA_SRC:-$DEFAULT_SRC}"
EJBCA_REF="${EJBCA_REF:-r9.3.7}"

IMAGE_TAG="ejbca-ce:local-fixes"
EAR_PATH="$EJBCA_SRC/build/libs/ejbca.ear"
EAR_EXPLODED="build/ejbca.ear.exploded"     # relative to ROOT_DIR = docker build context

SKIP_EAR=0
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-ear) SKIP_EAR=1; shift;;
        -h|--help)  sed -n '2,30p' "$0"; exit 0;;
        *)          echo "Unknown arg: $1" >&2; exit 2;;
    esac
done

# ---------- step 0: fetch upstream source + apply bundled PR patches ----------
if [ "$SKIP_EAR" -eq 0 ]; then
    if [ "$EJBCA_SRC" = "$DEFAULT_SRC" ]; then
        # managed cache: clone once, else fetch; pin to EJBCA_REF; reset pristine.
        if [ ! -d "$EJBCA_SRC/.git" ]; then
            echo "==> Cloning upstream EJBCA-CE source -> $EJBCA_SRC"
            git clone https://github.com/Keyfactor/ejbca-ce "$EJBCA_SRC"
        else
            echo "==> Fetching upstream EJBCA-CE source in $EJBCA_SRC"
            git -C "$EJBCA_SRC" fetch --tags --quiet || true
        fi
        git -C "$EJBCA_SRC" checkout --quiet "$EJBCA_REF"
        git -C "$EJBCA_SRC" reset --hard --quiet "$EJBCA_REF"
        git -C "$EJBCA_SRC" clean -fdq
    else
        echo "==> Using caller-supplied EJBCA source at $EJBCA_SRC (not reset)"
        [ -d "$EJBCA_SRC" ] || { echo "ERROR: EJBCA_SRC '$EJBCA_SRC' not found" >&2; exit 1; }
    fi

    echo "==> Applying bundled PR patches (skipping any already upstream)"
    for p in "$ROOT_DIR"/patches/*.patch; do
        [ -f "$p" ] || continue
        if   git -C "$EJBCA_SRC" apply -R --check "$p" 2>/dev/null; then
            echo "    already merged upstream, skipping: ${p##*/}"
        elif git -C "$EJBCA_SRC" apply    --check "$p" 2>/dev/null; then
            git -C "$EJBCA_SRC" apply "$p"; echo "    applied: ${p##*/}"
        else
            echo "    !! cannot apply ${p##*/} (conflict) — aborting" >&2; exit 1
        fi
    done
fi

# ---------- step 1: gradle build ----------
# The container runs JDK 17; pin bytecode to release-17 via the init script.
# Build via JDK 21 LTS if available, else fall back to whatever's on PATH.
if [ -d /opt/homebrew/opt/openjdk@21 ]; then
    export JAVA_HOME="/opt/homebrew/opt/openjdk@21"
    export PATH="$JAVA_HOME/bin:$PATH"
    echo "==> Using JDK at $JAVA_HOME"
fi
if [ "$SKIP_EAR" -eq 0 ]; then
    echo "==> Gradle build (CE edition, production mode, skipping tests, --release 17)"
    ( cd "$EJBCA_SRC" && ./gradlew \
        -I "$ROOT_DIR/stack/init-release17.gradle.kts" \
        -Pedition=ce -Pejbca.productionmode=true -x test \
        clean build )
else
    echo "==> Skipping gradle build (--skip-ear)"
fi

if [ ! -f "$EAR_PATH" ]; then
    echo "ERROR: $EAR_PATH not present — did the gradle build succeed?" >&2
    exit 1
fi

ear_size=$(wc -c < "$EAR_PATH")
echo "    EAR: $EAR_PATH (${ear_size} bytes)"

# ---------- step 1.5: explode the EAR + rename datasource JNDI ----------
# The upstream image's clientToolBox/lib/*.jar are symlinks into an exploded
# EAR directory at /opt/keyfactor/ejbca/dist/ejbca.ear/lib/. To preserve
# those, ship the EAR as a directory, not a file.
#
# Separately, the upstream image's standalone.xml configures the JDBC
# datasource at JNDI name 'java:/AppDS' (a product-agnostic name shared
# with SignServer), but the EJBCA source tree uses 'java:/EjbcaDS' for
# its persistence.xml. Patch our EAR to use 'AppDS' so it binds to the
# datasource the image actually configures.
#
# Uses python3 (stdlib zipfile only) — works from any venv or system python.
echo
echo "==> Exploding EAR + patching JNDI name into $EAR_EXPLODED"
rm -rf "$EAR_EXPLODED"
mkdir -p "$EAR_EXPLODED"
python3 <<PYEOF
import os, sys, zipfile, io, shutil

src = "$EAR_PATH"
dst = "$EAR_EXPLODED"

# Step 1: extract EAR
with zipfile.ZipFile(src) as z:
    z.extractall(dst)
    total = len(z.namelist())
print(f"  extracted {total} entries into {dst}")

# Step 2: patch each jar that references EjbcaDS, swap to AppDS, rewrite.
def patch_jar_inplace(jar_path: str, name_substring: str, fix_fn):
    with open(jar_path, "rb") as f:
        buf = io.BytesIO(f.read())
    src_zip = zipfile.ZipFile(buf, "r")
    out_buf = io.BytesIO()
    out_zip = zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED)
    patched = False
    for item in src_zip.infolist():
        data = src_zip.read(item.filename)
        if name_substring in item.filename:
            new_data = fix_fn(data)
            if new_data != data:
                patched = True
                data = new_data
        out_zip.writestr(item, data)
    out_zip.close()
    if patched:
        with open(jar_path, "wb") as f:
            f.write(out_buf.getvalue())
        return True
    return False

def fix_persistence(b: bytes) -> bytes:
    return b.replace(b"java:/EjbcaDS", b"java:/AppDS")

def fix_defaultvalues(b: bytes) -> bytes:
    return b.replace(b"datasource.jndi-name=EjbcaDS", b"datasource.jndi-name=AppDS")

ent = os.path.join(dst, "lib", "ejbca-entity.jar")
if patch_jar_inplace(ent, "persistence.xml", fix_persistence):
    print(f"  patched {ent} (persistence.xml: EjbcaDS -> AppDS)")

cc = os.path.join(dst, "lib", "cesecore-common.jar")
if patch_jar_inplace(cc, "defaultvalues.properties", fix_defaultvalues):
    print(f"  patched {cc} (defaultvalues.properties: EjbcaDS -> AppDS)")
PYEOF

# ---------- step 2: docker build ----------
echo
echo "==> Docker build: $IMAGE_TAG"
docker build \
    -f stack/Dockerfile.local-fixes \
    -t "$IMAGE_TAG" \
    --build-arg "EAR_EXPLODED=$EAR_EXPLODED" \
    .

echo
echo "==> Image details"
docker image inspect "$IMAGE_TAG" --format \
    'Tag:     {{ index .RepoTags 0 }}{{"\n"}}Created: {{ .Created }}{{"\n"}}Size:    {{ .Size }} bytes' \
    || true

cat <<EOF

==================== 231 build-local-image complete ====================
  Built: $IMAGE_TAG
  Source: $EJBCA_SRC @ $EJBCA_REF + bundled patches
  Stack swap NOT performed — running stack still on upstream image.

  To swap to this image:
    ./Bin/230.rebuild/232.swap-stack-image.sh $IMAGE_TAG

  To roll back to upstream:
    ./Bin/230.rebuild/232.swap-stack-image.sh keyfactor/ejbca-ce:latest

  Integration tests (once swapped):
    ./Bin/500.verify-PR/502.fix-27-integration-test.sh
    ./Bin/500.verify-PR/501.fix-26-integration-test.sh
========================================================================
EOF

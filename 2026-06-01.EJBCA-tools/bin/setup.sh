# setup.sh — one-shot setup for the EJBCA tool bundle + demo:
#   certs/local dirs, Python venv, requirements, $PATH, and cd into the bundle.
#
# SOURCE it from your working directory (the dir you cloned into) — it sets
# env vars, activates the venv, and cds into the bundle in your CURRENT shell,
# so running it in a subshell (./setup.sh) would not persist:
#
#     $ git clone https://github.com/John-D-B/Claudes.git
#     $ source ./Claudes/2026-06-01.EJBCA-tools/bin/setup.sh
#
# The clone (storyboard A01-A02) is unavoidable manual prep — there is no
# script to run before it exists.

setup_version='1.0.0'

# certs/local dirs — relative to the current dir (the working/demo dir),
# set BEFORE we cd into the bundle:
export certsDir="$PWD/certs"
export localDir="$PWD/local"
mkdir -p "$certsDir" "$localDir"

# cd into the bundle root (this script lives in <bundle>/bin/), anchor topDir:
export topDir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$topDir"

# venv + requirements + PATH (relative to the bundle root):
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python3 -m pip install -q -r ./cg/requirements.txt -r ./elt/requirements.txt
export PATH="$topDir/bin:$PATH"

echo "=== tool locations ==="
for _t in deploy_ejbca_k8s.py ejbca-lifecycle-tool.py cert-grep.py ssl-grep.py \
          docker kubectl k3d helm keytool jq openssl python3 git; do
    if command -v "$_t" >/dev/null 2>&1; then
        printf "  ok       %s\n" "$_t"
    else
        printf "  MISSING  %s\n" "$_t"
    fi
done
unset _t

#!/usr/bin/env bash
# 301.build-cluster.sh — build the local k3d cluster for K8s cert-manager
# (storyboard C01-C04): create the cluster, map host.k3d.internal to the host
# gateway via the coredns-custom override, and roll coredns so it takes effect.
#
# Re-runnable: deletes any existing cluster of the same name first.

version='1.1.0'   # 1.1.0 — self-log to $logDir/C01-build-cluster.log (the run book's named log).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"
CLUSTER="${CLUSTER:-ejbca-test}"

# Self-log this run to $logDir (out-of-repo); trap drains tee so no false "hang".
logDir="${logDir:-/tmp/claude/demo/logs}"; mkdir -p "$logDir"
exec > >(tee "$logDir/C01-build-cluster.log") 2>&1
TEE_PID=$!
trap 'exec 1>&- 2>&-; wait "$TEE_PID" 2>/dev/null || true' EXIT
echo "=== logging to $logDir/C01-build-cluster.log ==="

echo "=== [1/3] Create the k3d cluster '$CLUSTER' ==="
k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
k3d cluster create "$CLUSTER"
kubectl config use-context "k3d-$CLUSTER" >/dev/null 2>&1 || true

echo "=== [2/3] Map host.k3d.internal to the host gateway (coredns-custom) ==="
kubectl apply -f stack/coredns-custom.yaml

echo "=== [3/3] Roll coredns so the override takes effect ==="
kubectl -n kube-system rollout restart deployment/coredns
kubectl -n kube-system rollout status deployment/coredns --timeout=90s

echo "=== cluster ready — next: deploy_ejbca_k8s.py set/show/do (C05) ==="

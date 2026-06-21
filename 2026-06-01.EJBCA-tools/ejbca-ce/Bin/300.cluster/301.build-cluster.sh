#!/usr/bin/env bash
# 301.build-cluster.sh — build the local k3d cluster for K8s cert-manager
# (storyboard C01-C04): create the cluster, map host.k3d.internal to the host
# gateway via the coredns-custom override, and roll coredns so it takes effect.
#
# Re-runnable: deletes any existing cluster of the same name first.

version='1.0.0'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"
CLUSTER="${CLUSTER:-ejbca-test}"

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

#!/usr/bin/env bash

set -euxo pipefail

K8S_VERSION=${K8S_VERSION:-v1.16.4}

# Detect IP to use as API server
API_IP=$(ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
if [ -z "$API_IP" ]; then
  echo "Error detecting machine IP to use as API server"
  exit 1
fi

sed -i "s/apiServerAddress.*/apiServerAddress: ${API_IP}/" kind.yaml

# Create KIND cluster
kind create cluster --name ovn --kubeconfig ${HOME}/admin.conf --image kindest/node:${K8S_VERSION} --config=./kind.yaml
export KUBECONFIG=${HOME}/admin.conf
mkdir -p /tmp/kind
sudo chmod 777 /tmp/kind
count=0
until kubectl get secrets -o jsonpath='{.items[].data.ca\.crt}'
do
  if [ $count -gt 10 ]; then
    echo "Failed to get k8s crt/token"
    exit 1
  fi
  count=$((count+1))
  echo "secrets not availble on attempt $count"
  sleep 5
done
kubectl get secrets -o jsonpath='{.items[].data.ca\.crt}' > /tmp/kind/ca.crt
kubectl get secrets -o jsonpath='{.items[].data.token}' > /tmp/kind/token
pushd ../go-controller
make
popd
pushd ../dist/images
sudo cp -f ../../go-controller/_output/go/bin/* .
echo "ref: $(git rev-parse  --symbolic-full-name HEAD)  commit: $(git rev-parse  HEAD)" > git_info
docker build -t ovn-daemonset-f:dev -f Dockerfile.fedora .
./daemonset.sh --image=docker.io/library/ovn-daemonset-f:dev --net-cidr=10.244.0.0/16 --svc-cidr=10.96.0.0/12 --gateway-mode="local" --k8s-apiserver=https://${API_IP}:11337
popd
kind load docker-image ovn-daemonset-f:dev --name ovn
pushd ../dist/yaml
kubectl create -f ovn-setup.yaml
kubectl create -f ovnkube-db.yaml
kubectl create -f ovnkube-master.yaml
kubectl create -f ovnkube-node.yaml
popd




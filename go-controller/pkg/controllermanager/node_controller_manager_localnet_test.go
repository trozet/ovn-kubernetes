// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package controllermanager

import (
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"

	ovncnitypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/node"
	ovntypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

type localnetGatewayRecorder struct {
	node.Gateway
	networkName         string
	physicalNetworkName string
}

func (r *localnetGatewayRecorder) ReconcileLocalnetNetwork(networkName, physicalNetworkName string) {
	r.networkName = networkName
	r.physicalNetworkName = physicalNetworkName
}

func TestNodeControllerManagerReconcilesLocalnetBridgeAssociation(t *testing.T) {
	recorder := &localnetGatewayRecorder{}
	ncm := &NodeControllerManager{
		defaultNodeNetworkController: &node.DefaultNodeNetworkController{Gateway: recorder},
	}

	localnet, err := util.NewNetInfo(&ovncnitypes.NetConf{
		NetConf:             cnitypes.NetConf{Name: "localnet-a"},
		Topology:            ovntypes.LocalnetTopology,
		PhysicalNetworkName: "physnet-a",
	})
	if err != nil {
		t.Fatalf("failed to create localnet network info: %v", err)
	}
	if err := ncm.Reconcile("localnet-a", nil, localnet); err != nil {
		t.Fatalf("failed to reconcile localnet network: %v", err)
	}
	if recorder.networkName != "localnet-a" || recorder.physicalNetworkName != "physnet-a" {
		t.Fatalf("expected localnet-a on physnet-a, got %q on %q",
			recorder.networkName, recorder.physicalNetworkName)
	}

	if err := ncm.Reconcile("localnet-a", nil, nil); err != nil {
		t.Fatalf("failed to reconcile localnet deletion: %v", err)
	}
	if recorder.networkName != "localnet-a" || recorder.physicalNetworkName != "" {
		t.Fatalf("expected localnet-a association to be removed, got %q on %q",
			recorder.networkName, recorder.physicalNetworkName)
	}

	defaultedLocalnet, err := util.NewNetInfo(&ovncnitypes.NetConf{
		NetConf:  cnitypes.NetConf{Name: "localnet-defaulted"},
		Topology: ovntypes.LocalnetTopology,
	})
	if err != nil {
		t.Fatalf("failed to create defaulted localnet network info: %v", err)
	}
	if err := ncm.Reconcile("localnet-defaulted", nil, defaultedLocalnet); err != nil {
		t.Fatalf("failed to reconcile defaulted localnet network: %v", err)
	}
	if recorder.physicalNetworkName != "localnet-defaulted" {
		t.Fatalf("expected omitted physical network to default to the network name, got %q",
			recorder.physicalNetworkName)
	}
}

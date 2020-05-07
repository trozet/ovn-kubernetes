package controller

import (
	"fmt"
	"net"
	"reflect"

	"github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/types"
	houtil "github.com/ovn-org/ovn-kubernetes/go-controller/hybrid-overlay/pkg/util"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/klog"
)

// StartNode creates and starts the hybrid overlay node controller
func StartNode(nodeName string, kube kube.Interface, wf *factory.WatchFactory, stopChan <-chan struct{}) error {
	klog.Infof("Starting hybrid overlay node...")
	node, err := NewNode(kube, nodeName, stopChan)
	if err != nil {
		return err
	}
	return node.Start(wf)
}

// nodeChanged returns true if any relevant node attributes changed
func nodeChanged(node1 *kapi.Node, node2 *kapi.Node) bool {
	cidr1, nodeIP1, drMAC1, drIP1, _ := getNodeDetails(node1)
	cidr2, nodeIP2, drMAC2, drIP2, _ := getNodeDetails(node2)
	return !reflect.DeepEqual(cidr1, cidr2) || !reflect.DeepEqual(nodeIP1, nodeIP2) ||
		!reflect.DeepEqual(drMAC1, drMAC2) || !reflect.DeepEqual(drIP1, drIP2)
}

// getNodeSubnetAndIP returns the node's hybrid overlay subnet and the node's
// first InternalIP, or nil if the subnet or node IP is invalid
func getNodeSubnetAndIP(node *kapi.Node) (*net.IPNet, net.IP) {
	// Parse Linux node OVN hostsubnet annotation first
	cidr, _ := util.ParseNodeHostSubnetAnnotation(node)
	if cidr == nil {
		// Otherwise parse the hybrid overlay node subnet annotation
		subnet, ok := node.Annotations[types.HybridOverlayNodeSubnet]
		if !ok {

			klog.V(5).Infof("missing node %q node subnet annotation", node.Name)
			return nil, nil
		}
		var err error
		_, cidr, err = net.ParseCIDR(subnet)
		if err != nil {
			klog.Errorf("error parsing node %q subnet %q: %v", node.Name, subnet, err)
			return nil, nil
		}
	}

	nodeIP, err := houtil.GetNodeInternalIP(node)
	if err != nil {
		klog.Errorf("error getting node %q internal IP: %v", node.Name, err)
		return nil, nil
	}

	return cidr, net.ParseIP(nodeIP)
}

// getNodeDetails returns the node's hybrid overlay subnet, first InternalIP,
// and the distributed router MAC (DRMAC), or nil if any of the addresses are
// missing or invalid.
func getNodeDetails(node *kapi.Node) (*net.IPNet, net.IP, net.HardwareAddr, net.IP, error) {
	cidr, ip := getNodeSubnetAndIP(node)
	if cidr == nil || ip == nil {
		return nil, nil, nil, nil, fmt.Errorf("missing node subnet and/or node IP")
	}

	drMACString, ok := node.Annotations[types.HybridOverlayDRMAC]
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("missing distributed router MAC annotation")
	}
	drMAC, err := net.ParseMAC(drMACString)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid distributed router MAC %q: %v", drMACString, err)
	}

	drIPString, ok := node.Annotations[types.HybridOverlayDRIP]
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("missing distributed router MAC annotation")
	}
	drIP := net.ParseIP(drIPString)
	if drIP == nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse DRIP: %s", drIPString)
	}

	return cidr, ip, drMAC, drIP, nil
}

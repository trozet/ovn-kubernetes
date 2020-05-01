package node

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"k8s.io/klog"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

// bridgedGatewayNodeSetup makes the bridge's MAC address permanent (if needed), sets up
// the physical network name mappings for the bridge, and returns an ifaceID
// created from the bridge name and the node name
func bridgedGatewayNodeSetup(nodeName, bridgeName, bridgeInterface string, syncBridgeMAC bool) (string, net.HardwareAddr, error) {
	// A OVS bridge's mac address can change when ports are added to it.
	// We cannot let that happen, so make the bridge mac address permanent.
	macAddress, err := util.GetOVSPortMACAddress(bridgeInterface)
	if err != nil {
		return "", nil, err
	}
	if syncBridgeMAC {
		var err error

		stdout, stderr, err := util.RunOVSVsctl("set", "bridge",
			bridgeName, "other-config:hwaddr="+macAddress.String())
		if err != nil {
			return "", nil, fmt.Errorf("Failed to set bridge, stdout: %q, stderr: %q, "+
				"error: %v", stdout, stderr, err)
		}
	}

	// ovn-bridge-mappings maps a physical network name to a local ovs bridge
	// that provides connectivity to that network.
	bridgeMappings := fmt.Sprintf("%s:%s", util.PhysicalNetworkName, bridgeName)
	if config.HybridOverlay.Enabled && config.HybridOverlay.NsGwModeEnabled {
		bridgeMappings += fmt.Sprintf(",%s:%s", util.HybridGatewayNetworkName, "br-ext")
	}
	_, stderr, err := util.RunOVSVsctl("set", "Open_vSwitch", ".",
		fmt.Sprintf("external_ids:ovn-bridge-mappings=%s", bridgeMappings))
	if err != nil {
		return "", nil, fmt.Errorf("Failed to set ovn-bridge-mappings for ovs bridge %s"+
			", stderr:%s (%v)", bridgeName, stderr, err)
	}

	ifaceID := bridgeName + "_" + nodeName
	return ifaceID, macAddress, nil
}

// getIPv4Address returns the ipv4 address for the network interface 'iface'.
func getIPv4Address(iface string) (*net.IPNet, error) {
	intf, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}

	addrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		switch ip := addr.(type) {
		case *net.IPNet:
			if !utilnet.IsIPv6CIDR(ip) {
				return ip, nil
			}
		}
	}
	return nil, nil
}

func (n *OvnNode) initGateway(subnet *net.IPNet, nodeAnnotator kube.Annotator,
	waiter *startupWaiter) error {

	if config.Gateway.NodeportEnable {
		err := initLoadBalancerHealthChecker(n.name, n.watchFactory)
		if err != nil {
			return err
		}
	}

	var err error
	var prFn postWaitFunc
	switch config.Gateway.Mode {
	case config.GatewayModeLocal:
		err = initLocalnetGateway(n.name, subnet, n.watchFactory, nodeAnnotator)
	case config.GatewayModeShared:
		gatewayNextHop := net.ParseIP(config.Gateway.NextHop)
		gatewayIntf := config.Gateway.Interface
		if gatewayNextHop == nil || gatewayIntf == "" {
			// We need to get the interface details from the default gateway.
			defaultGatewayIntf, defaultGatewayNextHop, err := getDefaultGatewayInterfaceDetails()
			if err != nil {
				return err
			}

			if gatewayNextHop == nil {
				gatewayNextHop = defaultGatewayNextHop
			}

			if gatewayIntf == "" {
				gatewayIntf = defaultGatewayIntf
			}
		}
		prFn, err = n.initSharedGateway(subnet, gatewayNextHop, gatewayIntf, nodeAnnotator)
	case config.GatewayModeDisabled:
		err = util.SetL3GatewayConfig(nodeAnnotator, &util.L3GatewayConfig{
			Mode: config.GatewayModeDisabled,
		})
	}
	if err != nil {
		return err
	}

	// Wait for gateway resources to be created by the master
	waiter.AddWait(gatewayReady, prFn)
	return nil
}

// CleanupClusterNode cleans up OVS resources on the k8s node on ovnkube-node daemonset deletion.
// This is going to be a best effort cleanup.
func CleanupClusterNode(name string) error {
	var err error

	klog.V(5).Infof("Cleaning up gateway resources on node: %q", name)
	switch config.Gateway.Mode {
	case config.GatewayModeLocal:
		err = cleanupLocalnetGateway()
	case config.GatewayModeShared:
		err = cleanupSharedGateway()
	}
	if err != nil {
		klog.Errorf("Failed to cleanup Gateway, error: %v", err)
	}

	// Delete iptable rules for management port on Linux.
	if runtime.GOOS != "windows" {
		DelMgtPortIptRules()
	}

	return nil
}

// GatewayReady will check to see if we have successfully added SNAT OpenFlow rules in the L3Gateway Routers
func gatewayReady() (bool, error) {
	// OpenFlow table 41 performs SNATing of packets that are heading to physical network from
	// logical network.
	for _, clusterSubnet := range config.Default.ClusterSubnets {
		var cidr, match string
		cidr = clusterSubnet.CIDR.String()
		if strings.Contains(cidr, ":") {
			match = "ipv6,ipv6_src=" + cidr
		} else {
			match = "ip,nw_src=" + cidr
		}
		stdout, _, err := util.RunOVSOfctl("--no-stats", "--no-names", "dump-flows", "br-int",
			"table=41,"+match)
		if err != nil {
			return false, nil
		}
		if !strings.Contains(stdout, cidr) {
			return false, nil
		}
	}
	return true, nil
}

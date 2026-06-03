// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux
// +build linux

package managementport

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	utilnet "k8s.io/utils/net"
	"sigs.k8s.io/knftables"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	nodenft "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/node/nftables"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

const nftDPUHostKAPISNATChain = "dpu-host-kapi-snat"

func setupDPUHostKubeAPISNATRules(node *corev1.Node, interfaceName string, podCIDRs []*net.IPNet) error {
	if !config.IsModeDPUHost() || config.Gateway.Mode != config.GatewayModeShared {
		return nil
	}
	if node == nil {
		return fmt.Errorf("missing node while configuring DPU host kube API SNAT")
	}

	gatewayConfig, err := util.ParseNodeL3GatewayAnnotation(node)
	if err != nil {
		return fmt.Errorf("failed to get L3 gateway annotation for node %s: %v", node.Name, err)
	}
	hostCIDRs, err := dpuHostKubeAPISNATHostCIDRs(node, gatewayConfig)
	if err != nil {
		return err
	}

	return updateDPUHostKubeAPISNATRules(interfaceName, podCIDRs, hostCIDRs)
}

// SyncDPUHostKubeAPISNATHostCIDRs refreshes the host CIDR nft sets used for
// DPU host kube API masquerade.
func SyncDPUHostKubeAPISNATHostCIDRs(node *corev1.Node) error {
	if !config.IsModeDPUHost() || config.Gateway.Mode != config.GatewayModeShared {
		return nil
	}
	gatewayConfig, err := util.ParseNodeL3GatewayAnnotation(node)
	if err != nil {
		if util.IsAnnotationNotSetError(err) {
			return nil
		}
		return fmt.Errorf("failed to get L3 gateway annotation for node %s: %v", node.Name, err)
	}
	hostCIDRs, err := dpuHostKubeAPISNATHostCIDRs(node, gatewayConfig)
	if err != nil {
		return err
	}
	if err := ensureDPUHostKubeAPISNATNFTables(); err != nil {
		return err
	}
	return syncDPUHostKubeAPISNATHostCIDRSets(hostCIDRs)
}

func dpuHostKubeAPISNATHostCIDRs(node *corev1.Node, gatewayConfig *util.L3GatewayConfig) ([]string, error) {
	hostCIDRs, err := util.GetNodeHostCIDRsForSplitDPUKAPI(node, gatewayConfig.IPAddresses)
	if err != nil {
		return nil, fmt.Errorf("failed to get split DPU host CIDRs for node %s: %v", node.Name, err)
	}
	return hostCIDRs, nil
}

func updateDPUHostKubeAPISNATRules(interfaceName string, podCIDRs []*net.IPNet, hostCIDRs []string) error {
	if err := ensureDPUHostKubeAPISNATNFTables(); err != nil {
		return err
	}
	if err := syncDPUHostKubeAPISNATHostCIDRSets(hostCIDRs); err != nil {
		return err
	}
	if len(hostCIDRs) == 0 {
		return nil
	}

	return nodenft.UpdateNFTElements(dpuHostKubeAPISNATElements(interfaceName, podCIDRs))
}

func deleteDPUHostKubeAPISNATRules(interfaceName string, podCIDRs []*net.IPNet) error {
	if !config.IsModeDPUHost() || config.Gateway.Mode != config.GatewayModeShared {
		return nil
	}
	return nodenft.DeleteNFTElements(dpuHostKubeAPISNATElements(interfaceName, podCIDRs))
}

func syncDPUHostKubeAPISNATHostCIDRSets(hostCIDRs []string) error {
	v4HostCIDRs := make([]*knftables.Element, 0, len(hostCIDRs))
	v6HostCIDRs := make([]*knftables.Element, 0, len(hostCIDRs))
	for _, hostCIDR := range hostCIDRs {
		_, cidr, err := net.ParseCIDR(hostCIDR)
		if err != nil {
			return fmt.Errorf("failed to parse DPU host kube API CIDR %q: %v", hostCIDR, err)
		}
		if utilnet.IsIPv6CIDR(cidr) {
			v6HostCIDRs = append(v6HostCIDRs, &knftables.Element{
				Set: types.NFTDPUHostKAPICIDRsV6,
				Key: []string{cidr.String()},
			})
		} else {
			v4HostCIDRs = append(v4HostCIDRs, &knftables.Element{
				Set: types.NFTDPUHostKAPICIDRsV4,
				Key: []string{cidr.String()},
			})
		}
	}

	nft, err := nodenft.GetNFTablesHelper()
	if err != nil {
		return err
	}
	tx := nft.NewTransaction()
	tx.Flush(&knftables.Set{Name: types.NFTDPUHostKAPICIDRsV4})
	tx.Flush(&knftables.Set{Name: types.NFTDPUHostKAPICIDRsV6})
	for _, elem := range v4HostCIDRs {
		tx.Add(elem)
	}
	for _, elem := range v6HostCIDRs {
		tx.Add(elem)
	}
	return nft.Run(context.TODO(), tx)
}

func dpuHostKubeAPISNATElements(interfaceName string, podCIDRs []*net.IPNet) []*knftables.Element {
	elements := []*knftables.Element{
		{
			Set: types.NFTDPUHostKAPIMgmtPorts,
			Key: []string{interfaceName},
		},
	}

	for _, podCIDR := range podCIDRs {
		if utilnet.IsIPv6CIDR(podCIDR) {
			elements = append(elements, &knftables.Element{
				Set: types.NFTDPUHostKAPIPodCIDRsV6,
				Key: []string{podCIDR.String()},
			})
		} else {
			elements = append(elements, &knftables.Element{
				Set: types.NFTDPUHostKAPIPodCIDRsV4,
				Key: []string{podCIDR.String()},
			})
		}
	}

	return elements
}

func ensureDPUHostKubeAPISNATNFTables() error {
	nft, err := nodenft.GetNFTablesHelper()
	if err != nil {
		return err
	}

	tx := nft.NewTransaction()
	tx.Add(&knftables.Set{
		Name: types.NFTDPUHostKAPIMgmtPorts,
		Type: "ifname",
	})
	tx.Add(&knftables.Set{
		Name:  types.NFTDPUHostKAPICIDRsV4,
		Type:  "ipv4_addr",
		Flags: []knftables.SetFlag{knftables.IntervalFlag},
	})
	tx.Add(&knftables.Set{
		Name:  types.NFTDPUHostKAPICIDRsV6,
		Type:  "ipv6_addr",
		Flags: []knftables.SetFlag{knftables.IntervalFlag},
	})
	tx.Add(&knftables.Set{
		Name:  types.NFTDPUHostKAPIPodCIDRsV4,
		Type:  "ipv4_addr",
		Flags: []knftables.SetFlag{knftables.IntervalFlag},
	})
	tx.Add(&knftables.Set{
		Name:  types.NFTDPUHostKAPIPodCIDRsV6,
		Type:  "ipv6_addr",
		Flags: []knftables.SetFlag{knftables.IntervalFlag},
	})
	tx.Add(&knftables.Chain{
		Name:     nftDPUHostKAPISNATChain,
		Comment:  knftables.PtrTo("OVN DPU host kube API SNAT"),
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(knftables.PostroutingHook),
		Priority: knftables.PtrTo(knftables.SNATPriority),
	})
	tx.Flush(&knftables.Chain{Name: nftDPUHostKAPISNATChain})
	tx.Add(&knftables.Rule{
		Chain: nftDPUHostKAPISNATChain,
		Rule: knftables.Concat(
			"iifname", "@", types.NFTDPUHostKAPIMgmtPorts,
			"ip", "saddr", "@", types.NFTDPUHostKAPIPodCIDRsV4,
			"ip", "daddr", "@", types.NFTDPUHostKAPICIDRsV4,
			"masquerade",
		),
	})
	tx.Add(&knftables.Rule{
		Chain: nftDPUHostKAPISNATChain,
		Rule: knftables.Concat(
			"iifname", "@", types.NFTDPUHostKAPIMgmtPorts,
			"ip6", "saddr", "@", types.NFTDPUHostKAPIPodCIDRsV6,
			"ip6", "daddr", "@", types.NFTDPUHostKAPICIDRsV6,
			"masquerade",
		),
	})

	return nft.Run(context.TODO(), tx)
}

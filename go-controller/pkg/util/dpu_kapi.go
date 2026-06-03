// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"net"

	corev1 "k8s.io/api/core/v1"
	utilnet "k8s.io/utils/net"
)

// GetNodeHostCIDRsForSplitDPUKAPI returns host CIDRs that are not on the
// node's shared gateway subnet. In DPU deployments these CIDRs need explicit
// routing through the host management path so pods can reach host services,
// including kube-apiserver, when the host and gateway networks are split.
func GetNodeHostCIDRsForSplitDPUKAPI(node *corev1.Node, gatewayIPs []*net.IPNet) ([]string, error) {
	hostCIDRStrings, err := ParseNodeHostCIDRsList(node)
	if err != nil {
		if IsAnnotationNotSetError(err) {
			return nil, nil
		}
		return nil, err
	}

	hostCIDRs := make([]string, 0, len(hostCIDRStrings))
	for _, hostCIDRString := range hostCIDRStrings {
		_, hostCIDR, err := net.ParseCIDR(hostCIDRString)
		if err != nil {
			return nil, err
		}

		if containsIPNetFamily(gatewayIPs, hostCIDR) && !cidrContainsAnyIP(hostCIDR, gatewayIPs) {
			hostCIDRs = append(hostCIDRs, hostCIDR.String())
		}
	}

	return hostCIDRs, nil
}

func containsIPNetFamily(ipNets []*net.IPNet, cidr *net.IPNet) bool {
	for _, ipNet := range ipNets {
		if ipNet == nil {
			continue
		}
		if utilnet.IsIPv6CIDR(ipNet) == utilnet.IsIPv6CIDR(cidr) {
			return true
		}
	}
	return false
}

func cidrContainsAnyIP(cidr *net.IPNet, ipNets []*net.IPNet) bool {
	for _, ipNet := range ipNets {
		if ipNet == nil {
			continue
		}
		if cidr.Contains(ipNet.IP) {
			return true
		}
	}
	return false
}

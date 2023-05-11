package util

import (
	"fmt"
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

const (
	// Annotation used to enable/disable multicast in the namespace
	NsMulticastAnnotation = "k8s.ovn.org/multicast-enabled"
	// Annotations used by multiple external gateways feature
	RoutingExternalGWsAnnotation = "k8s.ovn.org/routing-external-gws"
	RoutingNamespaceAnnotation   = "k8s.ovn.org/routing-namespaces"
	RoutingNetworkAnnotation     = "k8s.ovn.org/routing-network"
	BfdAnnotation                = "k8s.ovn.org/bfd-enabled"
	// Annotation for enabling ACL logging to controller's log file
	AclLoggingAnnotation = "k8s.ovn.org/acl-logging"
)

func ParseRoutingExternalGWAnnotation(annotation string) (sets.Set[string], error) {
	ipTracker := sets.New[string]()
	for _, v := range strings.Split(annotation, ",") {
		parsedAnnotation := net.ParseIP(v)
		if parsedAnnotation == nil {
			return nil, fmt.Errorf("could not parse routing external gw annotation value %s", v)
		}
		if ipTracker.Has(parsedAnnotation.String()) {
			klog.Warningf("Duplicate IP detected in routing external gw annotation: %s", annotation)
			continue
		}
		ipTracker.Insert(parsedAnnotation.String())
	}
	return ipTracker, nil
}

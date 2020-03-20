package ovn

import (
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	kapi "k8s.io/api/core/v1"
	knet "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

type namespacePolicy struct {
	sync.Mutex
	name            string
	namespace       string
	ingressPolicies []*gressPolicy
	egressPolicies  []*gressPolicy
	podHandlerList  []*factory.Handler
	nsHandlerList   []*factory.Handler
	localPods       map[string]*lpInfo //pods effected by this policy
	portGroupUUID   string             //uuid for OVN port_group
	portGroupName   string
	deleted         bool //deleted policy
}

func NewNamespacePolicy(policy *knet.NetworkPolicy) *namespacePolicy {
	np := &namespacePolicy{
		name:            policy.Name,
		namespace:       policy.Namespace,
		ingressPolicies: make([]*gressPolicy, 0),
		egressPolicies:  make([]*gressPolicy, 0),
		podHandlerList:  make([]*factory.Handler, 0),
		nsHandlerList:   make([]*factory.Handler, 0),
		localPods:       make(map[string]*lpInfo),
	}
	return np
}

type gressPolicy struct {
	policyType knet.PolicyType
	idx        int

	// peerAddressSets points to all the addressSets that hold
	// the peer pod's IP addresses. We will have one addressSet for
	// local pods and multiple addressSets that each represent a
	// peer namespace
	peerAddressSets map[string]bool

	// sortedPeerAddressSets has the sorted peerAddressSets
	sortedPeerAddressSets []string

	// portPolicies represents all the ports to which traffic is allowed for
	// the rule in question.
	portPolicies []*portPolicy

	// ipBlockCidr represents the CIDR from which traffic is allowed
	// except the IP block in the except, which should be dropped.
	ipBlockCidr   []string
	ipBlockExcept []string

	hashedLocalAddressSet string
	peerPodAddressMap     map[string]bool
	clauses               []*clause
}

type clause struct {
	namespaceSelector *metav1.LabelSelector
	podSelector       *metav1.LabelSelector
}

type portPolicy struct {
	protocol string
	port     int32
}

func (pp *portPolicy) getL4Match() (string, error) {
	if pp.protocol == TCP {
		return fmt.Sprintf("tcp && tcp.dst==%d", pp.port), nil
	} else if pp.protocol == UDP {
		return fmt.Sprintf("udp && udp.dst==%d", pp.port), nil
	} else if pp.protocol == SCTP {
		return fmt.Sprintf("sctp && sctp.dst==%d", pp.port), nil
	}
	return "", fmt.Errorf("unknown port protocol %v", pp.protocol)
}

func newGressPolicy(policyType knet.PolicyType, idx int) *gressPolicy {
	return &gressPolicy{
		policyType:            policyType,
		idx:                   idx,
		peerAddressSets:       make(map[string]bool),
		sortedPeerAddressSets: make([]string, 0),
		portPolicies:          make([]*portPolicy, 0),
		ipBlockCidr:           make([]string, 0),
		ipBlockExcept:         make([]string, 0),
	}
}

func (gp *gressPolicy) addPortPolicy(portJSON *knet.NetworkPolicyPort) {
	gp.portPolicies = append(gp.portPolicies, &portPolicy{
		protocol: string(*portJSON.Protocol),
		port:     portJSON.Port.IntVal,
	})
}

func (gp *gressPolicy) addIPBlock(ipblockJSON *knet.IPBlock) {
	gp.ipBlockCidr = append(gp.ipBlockCidr, ipblockJSON.CIDR)
	gp.ipBlockExcept = append(gp.ipBlockExcept, ipblockJSON.Except...)
}

func ipMatch() string {
	if config.IPv6Mode {
		return "ip6"
	}
	return "ip4"
}

func (gp *gressPolicy) getL3MatchFromAddressSet() string {
	var l3Match, addresses string
	for _, addressSet := range gp.sortedPeerAddressSets {
		if addresses == "" {
			addresses = fmt.Sprintf("$%s", addressSet)
			continue
		}
		addresses = fmt.Sprintf("%s, $%s", addresses, addressSet)
	}
	if addresses == "" {
		l3Match = ipMatch()
	} else {
		if gp.policyType == knet.PolicyTypeIngress {
			l3Match = fmt.Sprintf("%s.src == {%s}", ipMatch(), addresses)
		} else {
			l3Match = fmt.Sprintf("%s.dst == {%s}", ipMatch(), addresses)
		}
	}
	return l3Match
}

func (gp *gressPolicy) getMatchFromIPBlock(lportMatch, l4Match string) string {
	var match string
	ipBlockCidr := fmt.Sprintf("{%s}", strings.Join(gp.ipBlockCidr, ", "))
	if gp.policyType == knet.PolicyTypeIngress {
		if l4Match == noneMatch {
			match = fmt.Sprintf("match=\"%s.src == %s && %s\"",
				ipMatch(), ipBlockCidr, lportMatch)
		} else {
			match = fmt.Sprintf("match=\"%s.src == %s && %s && %s\"",
				ipMatch(), ipBlockCidr, l4Match, lportMatch)
		}
	} else {
		if l4Match == noneMatch {
			match = fmt.Sprintf("match=\"%s.dst == %s && %s\"",
				ipMatch(), ipBlockCidr, lportMatch)
		} else {
			match = fmt.Sprintf("match=\"%s.dst == %s && %s && %s\"",
				ipMatch(), ipBlockCidr, l4Match, lportMatch)
		}
	}
	return match
}

func (gp *gressPolicy) addAddressSet(hashedAddressSet string) (string, string, bool) {
	if gp.peerAddressSets[hashedAddressSet] {
		return "", "", false
	}

	oldL3Match := gp.getL3MatchFromAddressSet()

	gp.sortedPeerAddressSets = append(gp.sortedPeerAddressSets, hashedAddressSet)
	sort.Strings(gp.sortedPeerAddressSets)
	gp.peerAddressSets[hashedAddressSet] = true

	return oldL3Match, gp.getL3MatchFromAddressSet(), true
}

func (gp *gressPolicy) delAddressSet(hashedAddressSet string) (string, string, bool) {
	if !gp.peerAddressSets[hashedAddressSet] {
		return "", "", false
	}

	oldL3Match := gp.getL3MatchFromAddressSet()

	for i, addressSet := range gp.sortedPeerAddressSets {
		if addressSet == hashedAddressSet {
			gp.sortedPeerAddressSets = append(
				gp.sortedPeerAddressSets[:i],
				gp.sortedPeerAddressSets[i+1:]...)
			break
		}
	}
	delete(gp.peerAddressSets, hashedAddressSet)

	return oldL3Match, gp.getL3MatchFromAddressSet(), true
}

// handlePeerPodSelectorAddUpdate adds the IP address of a pod that has been
// selected as a peer by a NetworkPolicy's ingress/egress section to that
// ingress/egress address set
func (oc *Controller) handlePeerPodSelectorAddUpdate(np *namespacePolicy,
	addressMap map[string]bool, addressSet string, obj interface{}) {

	pod := obj.(*kapi.Pod)
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations)
	if err != nil {
		return
	}
	ipAddress := podAnnotation.IP.IP.String()
	if addressMap[ipAddress] {
		return
	}

	np.Lock()
	defer np.Unlock()
	if np.deleted {
		return
	}

	addressMap[ipAddress] = true
	addToAddressSet(addressSet, ipAddress)
}

func (oc *Controller) handlePeerPodSelectorDeleteACLRules(obj interface{}, gress *gressPolicy) {
	pod := obj.(*kapi.Pod)
	logicalPort := podLogicalPortName(pod)

	oc.lspMutex.Lock()
	delete(oc.lspIngressDenyCache, logicalPort)
	delete(oc.lspEgressDenyCache, logicalPort)
	oc.lspMutex.Unlock()

	if !oc.portGroupSupport {
		if gress.policyType == knet.PolicyTypeIngress {
			deleteACLDenyOld(pod.Namespace, pod.Spec.NodeName, logicalPort, "Ingress")
		} else {
			deleteACLDenyOld(pod.Namespace, pod.Spec.NodeName, logicalPort, "Egress")
		}
	}
}

// handlePeerPodSelectorDelete removes the IP address of a pod that no longer
// matches a NetworkPolicy ingress/egress section's selectors from that
// ingress/egress address set
func (oc *Controller) handlePeerPodSelectorDelete(np *namespacePolicy,
	addressMap map[string]bool, addressSet string, obj interface{}) {

	pod := obj.(*kapi.Pod)
	podAnnotation, err := util.UnmarshalPodAnnotation(pod.Annotations)
	if err != nil {
		return
	}
	ipAddress := podAnnotation.IP.IP.String()

	np.Lock()
	defer np.Unlock()
	if np.deleted {
		return
	}

	if !addressMap[ipAddress] {
		return
	}

	delete(addressMap, ipAddress)
	removeFromAddressSet(addressSet, ipAddress)
}

type peerNamespaceSelectorModifyFn func(*gressPolicy, *namespacePolicy, string, string)

func (oc *Controller) matchNamespaceSelectorAndPodSelector(obj interface{}, podSelector, namespaceSelector *metav1.LabelSelector) (bool, error) {
	pod := obj.(*kapi.Pod)
	namespace, err := oc.watchFactory.GetNamespace(pod.Namespace)
	if err != nil {
		return false, fmt.Errorf("failed to get k8s namespace %s of pod %s: %v", pod.Namespace, pod.Name, err)
	}
	namespaceSel, err := metav1.LabelSelectorAsSelector(namespaceSelector)
	if err != nil {
		return false, fmt.Errorf("error creating label selector: %v", err)
	}
	podSel, err := metav1.LabelSelectorAsSelector(podSelector)
	if err != nil {
		klog.Errorf("error creating label selector %v", err)
	}
	if namespaceSel.Matches(labels.Set(namespace.Labels)) && podSel.Matches(labels.Set(pod.Labels)) {
		return true, nil
	}
	return false, nil
}

func (oc *Controller) watchPods(policy *knet.NetworkPolicy, np *namespacePolicy, gressPolicies []*gressPolicy) {
	_, err := oc.watchFactory.AddPodHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			for _, gress := range gressPolicies {
				for _, clause := range gress.clauses {
					if clause.namespaceSelector != nil && clause.podSelector != nil {
						//pod and namespace selector are being used
						match, err := oc.matchNamespaceSelectorAndPodSelector(obj, clause.podSelector, clause.namespaceSelector)
						if err != nil {
							klog.Errorf("%v", err)
							continue
						}
						if match {
							oc.handlePeerPodSelectorAddUpdate(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, obj)
						}
					} else if clause.namespaceSelector != nil {
						// Changes to a pod should not affect policies that only select on namespaces
						continue
					} else if clause.podSelector != nil {
						//podSelector only
						podSel, err := metav1.LabelSelectorAsSelector(clause.podSelector)
						if err != nil {
							klog.Errorf("error creating label selector %v", err)
						}
						if policy.Namespace == pod.Namespace && podSel.Matches(labels.Set(pod.Labels)) {
							oc.handlePeerPodSelectorAddUpdate(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, obj)
						}
					}
				}
			}

		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			for _, gress := range gressPolicies {
				for _, clause := range gress.clauses {
					if clause.namespaceSelector != nil && clause.podSelector != nil {
						//pod and namespace selector are being used
						match, err := oc.matchNamespaceSelectorAndPodSelector(obj, clause.podSelector, clause.namespaceSelector)
						if err != nil {
							klog.Errorf("%v", err)
							continue
						}
						if match {
							oc.handlePeerPodSelectorDelete(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, obj)
							oc.handlePeerPodSelectorDeleteACLRules(obj, gress)
						}

					} else if clause.namespaceSelector != nil {
						// Changes to a pod should not affect policies that only select on namespaces
						continue
					} else if clause.podSelector != nil {
						//podSelector only
						podSel, err := metav1.LabelSelectorAsSelector(clause.podSelector)
						if err != nil {
							klog.Errorf("error creating label selector %v", err)
						}
						if policy.Namespace == pod.Namespace && podSel.Matches(labels.Set(pod.Labels)) {
							oc.handlePeerPodSelectorDelete(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, obj)
						}
					}
				}

			}

		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newPod := newObj.(*kapi.Pod)
			oldPod := oldObj.(*kapi.Pod)
			if reflect.DeepEqual(newPod.Labels, oldPod.Labels) {
				//the pods labels have not changed so nothing regarding networkpolicy will
				return
			}

			for _, gress := range gressPolicies {
				for _, clause := range gress.clauses {
					if clause.namespaceSelector != nil && clause.podSelector != nil {
						//pod and namespace selector are being used
						newMatch, err := oc.matchNamespaceSelectorAndPodSelector(newObj, clause.podSelector, clause.namespaceSelector)
						if err != nil {
							klog.Errorf("%v", err)
							continue
						}
						oldMatch, err := oc.matchNamespaceSelectorAndPodSelector(oldObj, clause.podSelector, clause.namespaceSelector)
						if err != nil {
							klog.Errorf("%v", err)
						}
						if newMatch && !oldMatch {
							oc.handlePeerPodSelectorAddUpdate(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, newObj)
						}
						if !newMatch && oldMatch {
							oc.handlePeerPodSelectorDelete(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, oldObj)
						}
					} else if clause.namespaceSelector != nil {
						// Changes to a pod should not affect policies that only select on namespaces
						continue
					} else if clause.podSelector != nil {
						//podSelector only
						podSel, err := metav1.LabelSelectorAsSelector(clause.podSelector)
						if err != nil {
							klog.Errorf("error creating label selector %v", err)
						}
						if policy.Namespace == newPod.Namespace && podSel.Matches(labels.Set(newPod.Labels)) && !podSel.Matches(labels.Set(oldPod.Labels)) {
							oc.handlePeerPodSelectorAddUpdate(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, newObj)
						}
						if policy.Namespace == newPod.Namespace &&
							!podSel.Matches(labels.Set(newPod.Labels)) && podSel.Matches(labels.Set(oldPod.Labels)) {
							oc.handlePeerPodSelectorDelete(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, oldObj)
						}
					}
				}

			}

		},
	}, nil)

	if err != nil {
		klog.Errorf("error watching pods for policy %s in namespace %s: %v", policy.Name, policy.Namespace, err)
	}

}

func (oc *Controller) watchNamespaces(policy *knet.NetworkPolicy, np *namespacePolicy, gressPolicies []*gressPolicy, modifyFn peerNamespaceSelectorModifyFn) {
	_, err := oc.watchFactory.AddNamespaceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			for _, gress := range gressPolicies {
				for _, clause := range gress.clauses {
					if clause.namespaceSelector != nil && clause.podSelector != nil {
						namespace := obj.(*kapi.Namespace)
						namespaceSel, err := metav1.LabelSelectorAsSelector(clause.namespaceSelector)
						if err != nil {
							klog.Errorf("Error creating label selector")
						}
						if namespaceSel.Matches(labels.Set(namespace.Labels)) {

							pods, err := oc.watchFactory.GetPods(namespace.Name)
							if err != nil {
								klog.Errorf("Error grabbing pods for namespace:%s: %v", namespace.Name, err)
							}
							for _, pod := range pods {
								podSel, err := metav1.LabelSelectorAsSelector(clause.podSelector)
								if err != nil {
									klog.Errorf("Error creating label selector")
								}
								if podSel.Matches(labels.Set(pod.Labels)) {
									oc.handlePeerPodSelectorAddUpdate(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, pod)
								}
							}
						}

					} else if clause.namespaceSelector != nil {
						namespace := obj.(*kapi.Namespace)
						namespaceSel, err := metav1.LabelSelectorAsSelector(clause.namespaceSelector)
						if err != nil {
							klog.Errorf("error creating label selector")
							continue
						}
						if namespaceSel.Matches(labels.Set(namespace.Labels)) {
							np.Lock()
							if np.deleted {
								np.Unlock()
								continue
							}
							hashedAddressSet := hashedAddressSet(namespace.Name)
							oldL3Match, newL3Match, added := gress.addAddressSet(hashedAddressSet)
							if added {
								modifyFn(gress, np, oldL3Match, newL3Match)
							}
							np.Unlock()
						}
					} else if clause.podSelector != nil {
						// changes to a namespace will not affect clause that only selects on pods
						continue
					}
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			for _, gress := range gressPolicies {
				for _, clause := range gress.clauses {
					if clause.namespaceSelector != nil && clause.podSelector != nil {
						namespace := obj.(*kapi.Namespace)
						namespaceSel, err := metav1.LabelSelectorAsSelector(clause.namespaceSelector)
						if err != nil {
							klog.Errorf("Error creating label selector")
						}
						if namespaceSel.Matches(labels.Set(namespace.Labels)) {
							//get all pods
							pods, err := oc.watchFactory.GetPods(namespace.Name)
							if err != nil {
								klog.Errorf("Error grabbing pods for namespace: %s: %v", namespace.Name, err)
							}
							for _, pod := range pods {
								podSel, err := metav1.LabelSelectorAsSelector(clause.podSelector)
								if err != nil {
									klog.Errorf("Error creating label selector")
									continue
								}
								if podSel.Matches(labels.Set(pod.Labels)) {
									oc.handlePeerPodSelectorDelete(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, pod)
									oc.handlePeerPodSelectorDeleteACLRules(pod, gress)

								}
							}
						}
					} else if clause.namespaceSelector != nil {
						namespace := obj.(*kapi.Namespace)
						namespaceSel, err := metav1.LabelSelectorAsSelector(clause.namespaceSelector)
						if err != nil {
							klog.Errorf("error creating label selector")
						}
						if namespaceSel.Matches(labels.Set(namespace.Labels)) {
							np.Lock()
							if np.deleted {
								np.Unlock()
								continue
							}
							hashedAddressSet := hashedAddressSet(namespace.Name)
							oldL3Match, newL3Match, removed := gress.delAddressSet(hashedAddressSet)
							if removed {
								modifyFn(gress, np, oldL3Match, newL3Match)
							}
						}
					} else if clause.podSelector != nil {
						// changes to a namespace will not affect clause that only selects on pods
						continue
					}
				}
			}
		},
		UpdateFunc: func(old, newer interface{}) {
			oldNamespace := old.(*kapi.Namespace)
			newNamespace := newer.(*kapi.Namespace)
			if reflect.DeepEqual(oldNamespace.Labels, newNamespace.Labels) {
				//the labels did not change so nothing needs to happen
				return
			}
			for _, gress := range gressPolicies {
				for _, clause := range gress.clauses {
					if clause.namespaceSelector != nil && clause.podSelector != nil {
						namespaceSel, err := metav1.LabelSelectorAsSelector(clause.namespaceSelector)
						if err != nil {
							klog.Errorf("error creating label selector")
							continue
						}
						if namespaceSel.Matches(labels.Set(newNamespace.Labels)) &&
							!namespaceSel.Matches(labels.Set(oldNamespace.Labels)) {
							//get all pods
							pods, err := oc.watchFactory.GetPods(newNamespace.Name)
							if err != nil {
								klog.Errorf("Error grabbing pods for namespace %s: %v", newNamespace.Name, err)
							}
							podSel, err := metav1.LabelSelectorAsSelector(clause.podSelector)
							if err != nil {
								klog.Errorf("error creating labelSelector")
								continue
							}
							for _, pod := range pods {
								if podSel.Matches(labels.Set(pod.Labels)) {
									oc.handlePeerPodSelectorAddUpdate(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, pod)
								}
							}

						}
						if !namespaceSel.Matches(labels.Set(newNamespace.Labels)) &&
							namespaceSel.Matches(labels.Set(oldNamespace.Labels)) {
							//get all pods
							pods, err := oc.watchFactory.GetPods(newNamespace.Name)
							if err != nil {
								klog.Errorf("Error grabbing pods for namespace %s: %v", newNamespace.Name, err)
							}
							podSel, err := metav1.LabelSelectorAsSelector(clause.podSelector)
							if err != nil {
								klog.Errorf("error creating labelSelector")
								continue
							}
							for _, pod := range pods {
								if podSel.Matches(labels.Set(pod.Labels)) {
									oc.handlePeerPodSelectorDelete(np, gress.peerPodAddressMap, gress.hashedLocalAddressSet, pod)
									oc.handlePeerPodSelectorDeleteACLRules(pod, gress)
								}
							}
						}
					} else if clause.namespaceSelector != nil {

						namespaceSel, err := metav1.LabelSelectorAsSelector(clause.namespaceSelector)
						if err != nil {
							klog.Errorf("error creating label selector")
						}
						if namespaceSel.Matches(labels.Set(newNamespace.Labels)) &&
							!namespaceSel.Matches(labels.Set(oldNamespace.Labels)) {
							np.Lock()
							if np.deleted {
								np.Unlock()
								continue
							}
							hashedAddressSet := hashedAddressSet(newNamespace.Name)
							oldL3Match, newL3Match, added := gress.addAddressSet(hashedAddressSet)
							if added {
								modifyFn(gress, np, oldL3Match, newL3Match)
							}
							np.Unlock()
						} else if !namespaceSel.Matches(labels.Set(newNamespace.Labels)) &&
							namespaceSel.Matches(labels.Set(oldNamespace.Labels)) {
							np.Lock()
							if np.deleted {
								np.Unlock()
								continue
							}
							hashedAddressSet := hashedAddressSet(oldNamespace.Name)
							oldL3Match, newL3Match, removed := gress.delAddressSet(hashedAddressSet)
							if removed {
								modifyFn(gress, np, oldL3Match, newL3Match)
							}
						}
						np.Unlock()
					} else if clause.podSelector != nil {
						// changes to a namespace will not affect clause that only selects on pods
						continue
					}
				}
			}
		},
	}, nil)
	if err != nil {
		klog.Errorf("error watching namespaces for policy %s: %v",
			policy.Name, err)
	}

}

const (
	toLport   = "to-lport"
	fromLport = "from-lport"
	addACL    = "add"
	deleteACL = "delete"
	noneMatch = "None"
	// Default deny acl rule priority
	defaultDenyPriority = "1000"
	// Default allow acl rule priority
	defaultAllowPriority = "1001"
	// IP Block except deny acl rule priority
	ipBlockDenyPriority = "1010"
	// Default multicast deny acl rule priority
	defaultMcastDenyPriority = "1011"
	// Default multicast allow acl rule priority
	defaultMcastAllowPriority = "1012"
)

func addAllowACLFromNode(logicalSwitch string, mgmtPortIP net.IP) error {
	match := fmt.Sprintf("%s.src==%s", ipMatch(), mgmtPortIP.String())
	_, stderr, err := util.RunOVNNbctl("--may-exist", "acl-add", logicalSwitch,
		"to-lport", defaultAllowPriority, match, "allow-related")
	if err != nil {
		return fmt.Errorf("failed to create the node acl for "+
			"logical_switch=%s, stderr: %q (%v)", logicalSwitch, stderr, err)
	}

	return nil
}

func (oc *Controller) syncNetworkPolicies(networkPolicies []interface{}) {
	if oc.portGroupSupport {
		oc.syncNetworkPoliciesPortGroup(networkPolicies)
	} else {
		oc.syncNetworkPoliciesOld(networkPolicies)
	}
}

// AddNetworkPolicy creates and applies OVN ACLs to pod logical switch ports
// from Kubernetes NetworkPolicy objects
func (oc *Controller) addNetworkPolicy(policy *knet.NetworkPolicy) {
	if oc.portGroupSupport {
		oc.addNetworkPolicyPortGroup(policy)
	} else {
		oc.addNetworkPolicyOld(policy)
	}
}

func (oc *Controller) deleteNetworkPolicy(
	policy *knet.NetworkPolicy) {
	if oc.portGroupSupport {
		oc.deleteNetworkPolicyPortGroup(policy)
	} else {
		oc.deleteNetworkPolicyOld(policy)
	}

}

func (oc *Controller) shutdownHandlers(np *namespacePolicy) {
	for _, handler := range np.podHandlerList {
		_ = oc.watchFactory.RemovePodHandler(handler)
	}
	for _, handler := range np.nsHandlerList {
		_ = oc.watchFactory.RemoveNamespaceHandler(handler)
	}
}

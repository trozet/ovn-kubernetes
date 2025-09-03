package ovn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	nadlisters "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/listers/k8s.cni.cncf.io/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/controller"
	ratypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1"
	ralisters "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/listers/routeadvertisements/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/node"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/syncmap"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

func NewNodeNetworkController(name, zone, node string, cm networkmanager.ControllerManager, wf factory.NodeWatchFactory) networkmanager.UDNController {
	nc := &NodeNetworkController{
		name:                 fmt.Sprintf("[%s network Controller]", name),
		node:                 node,
		zone:                 zone,
		cm:                   cm,
		networkInformerCache: map[string]util.MutableNetInfo{},
		networkState:         syncmap.NewSyncMap[*networkControllerState](),
		watchFactory:         wf,
	}

	// this Controller does not feed from an informer, networkInformerCache are manually
	// added to the queue for processing
	networkConfig := &controller.ReconcilerConfig{
		RateLimiter: workqueue.DefaultTypedControllerRateLimiter[string](),
		Reconcile:   nc.syncNetwork,
		Threadiness: 15,
		MaxAttempts: controller.InfiniteAttempts,
	}
	nc.networkReconciler = controller.NewReconciler(
		nc.name,
		networkConfig,
	)

	// we don't care about route advertisements in cluster manager
	if nc.hasRouteAdvertisements() {
		nc.nadLister = wf.NADInformer().Lister()
		nc.raLister = wf.RouteAdvertisementsInformer().Lister()
		nc.nodeLister = wf.NodeCoreInformer().Lister()

		// ra Controller
		raConfig := &controller.ControllerConfig[ratypes.RouteAdvertisements]{
			RateLimiter:    workqueue.DefaultTypedControllerRateLimiter[string](),
			Informer:       wf.RouteAdvertisementsInformer().Informer(),
			Lister:         nc.raLister.List,
			Reconcile:      func(string) error { return nc.syncRunningNetworks() },
			ObjNeedsUpdate: raNeedsUpdate,
			Threadiness:    1,
		}
		nc.raController = controller.NewController(
			nc.name,
			raConfig,
		)

		// node Controller
		nodeConfig := &controller.ControllerConfig[corev1.Node]{
			RateLimiter:    workqueue.DefaultTypedControllerRateLimiter[string](),
			Informer:       wf.NodeCoreInformer().Informer(),
			Lister:         nc.nodeLister.List,
			Reconcile:      func(string) error { return nc.syncRunningNetworks() },
			ObjNeedsUpdate: nodeNeedsUpdate,
			Threadiness:    1,
		}
		nc.nodeController = controller.NewController(
			nc.name,
			nodeConfig,
		)
	}

	return nc
}

type NodeNetworkController struct {
	BaseUserDefinedNetworkController
	node.BaseNodeNetworkController
	sync.RWMutex

	name string
	zone string
	node string

	nadLister  nadlisters.NetworkAttachmentDefinitionLister
	raLister   ralisters.RouteAdvertisementsLister
	nodeLister corelisters.NodeLister

	networkReconciler controller.Reconciler
	raController      controller.Controller
	nodeController    controller.Controller

	cm                   networkmanager.ControllerManager
	networkInformerCache map[string]util.MutableNetInfo
	networkState         *syncmap.SyncMap[*networkControllerState]

	watchFactory factory.NodeWatchFactory
}

// Reconcile is called with the network key locked
func (c *NodeNetworkController) Reconcile(netInfo util.NetInfo) error {
	state, loaded := c.networkState.Load(netInfo.GetNetworkName())
	if !loaded {
		panic("network controller does not exist during Reconcile. This should never happen")
	}
	if state.stoppedAndDeleting {
		return nil
	}
	return state.controller.Reconcile(netInfo)
}

// Start will cleanup stale networkInformerCache that have not been ensured via
// EnsuredNetwork before this call
func (c *NodeNetworkController) Start(_ context.Context) error {
	controllers := []controller.Reconciler{c.networkReconciler}
	if c.raController != nil {
		controllers = append(controllers, c.raController)
	}
	if c.nodeController != nil {
		controllers = append(controllers, c.nodeController)
	}
	err := controller.StartWithInitialSync(c.syncAll, controllers...)
	if err != nil {
		return fmt.Errorf("error starting network controller: %w", err)
	}

	return nil
}

func (c *NodeNetworkController) Stop() {
	controllers := []controller.Reconciler{c.networkReconciler}
	if c.raController != nil {
		controllers = append(controllers, c.raController)
	}
	if c.nodeController != nil {
		controllers = append(controllers, c.nodeController)
	}
	controller.Stop(controllers...)
}

// setNetwork updates the "informer cache" for networks with the latest version of the network, informed by NAD controller
func (c *NodeNetworkController) setNetwork(network string, netInfo util.MutableNetInfo) {
	c.Lock()
	defer c.Unlock()
	if netInfo == nil {
		delete(c.networkInformerCache, network)
		return
	}
	c.networkInformerCache[network] = netInfo
}

// GetNetworkFromInformer retrieves the network from the network informer cache
func (c *NodeNetworkController) GetNetworkFromInformer(network string) util.MutableNetInfo {
	c.RLock()
	defer c.RUnlock()
	return c.networkInformerCache[network]
}

func (c *NodeNetworkController) getAllNetworksFromInformer() []util.NetInfo {
	c.RLock()
	defer c.RUnlock()
	networks := make([]util.NetInfo, 0, len(c.networkInformerCache))
	for _, network := range c.networkInformerCache {
		networks = append(networks, network)
	}
	return networks
}

func (c *NodeNetworkController) GetNetworkFromCurrentState(network string) util.NetInfo {
	var netInfo util.NetInfo
	_ = c.networkState.DoWithLock(network, func(key string) error {
		state, _ := c.networkState.Load(key)
		netInfo = state.controller
		return nil
	})

	return netInfo
}

// EnsureNetwork enqueues network key to workqueue and updates network informer cache
func (c *NodeNetworkController) EnsureNetwork(network util.MutableNetInfo) {
	c.setNetwork(network.GetNetworkName(), network)
	c.networkReconciler.Reconcile(network.GetNetworkName())
}

// DeleteNetwork removes the network from the network informer cache, and enqueues the network
func (c *NodeNetworkController) DeleteNetwork(network string) {
	switch network {
	case types.DefaultNetworkName:
		// for the default network however ensure it runs with the default
		// config
		c.setNetwork(network, &util.DefaultNetInfo{})
	default:
		c.setNetwork(network, nil)
	}
	c.networkReconciler.Reconcile(network)
}

// getNetworkState requires locked key for active cache
func (c *NodeNetworkController) getNetworkState(network string) *networkControllerState {
	state, exists := c.networkState.Load(network)
	if exists && state != nil {
		return state
	}
	return &networkControllerState{}
}

// getReconcilableNetworkState returns the controller responsible for the network if it is currently being tracked
// assumes locked key for active cache
func (c *NodeNetworkController) getReconcilableNetworkState(network string) (networkmanager.ReconcilableNetworkController, bool) {
	if network == types.DefaultNetworkName {
		return c.cm.GetDefaultNetworkController(), false
	}
	state := c.getNetworkState(network)
	return state.controller, state.stoppedAndDeleting
}

// syncAll is not called with mutex protection. Should not call this other than during initial startup,
// before any handlers/controllers are running
func (c *NodeNetworkController) syncAll() error {
	// as we sync upon start, consider networkInformerCache that have not been ensured as
	// stale and clean them up
	validNetworks := c.getAllNetworksFromInformer()
	if err := c.cm.CleanupStaleNetworks(validNetworks...); err != nil {
		return err
	}

	// sync all known networkInformerCache. There is no informer for networkInformerCache. Keys are added by NAD Controller.
	// Certain downstream controllers that handle configuration for multiple networkInformerCache depend on being
	// aware of all the existing networkInformerCache on initialization. To achieve that, we need to start existing
	// networkInformerCache synchronously. Otherwise, these controllers might incorrectly assess valid configuration
	// as stale.
	start := time.Now()
	klog.Infof("%s: syncing all networkInformerCache", c.name)
	for _, network := range validNetworks {
		err := c.syncNetwork(network.GetNetworkName())
		if errors.Is(err, networkmanager.ErrNetworkControllerTopologyNotManaged) {
			klog.V(5).Infof("Ignoring network %q since %q does not manage it", network.GetNetworkName(), c.name)
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to sync network %s: %w", network.GetNetworkName(), err)
		}
	}
	klog.Infof("%s: finished syncing all networkInformerCache. Time taken: %s", c.name, time.Since(start))
	return nil
}

func (c *NodeNetworkController) syncRunningNetworks() error {
	c.networkReconciler.Reconcile(types.DefaultNetworkName)
	for _, network := range c.networkState.GetKeys() {
		c.networkReconciler.Reconcile(network)
	}

	return nil
}

// syncNetwork must be called with nm mutex locked
func (c *NodeNetworkController) syncNetwork(network string) error {
	startTime := time.Now()
	klog.V(5).Infof("%s: sync network %s", c.name, network)
	defer func() {
		klog.V(4).Infof("%s: finished syncing network %s, took %v", c.name, network, time.Since(startTime))
	}()

	want := c.GetNetworkFromInformer(network)

	err := c.networkState.DoWithLock(network, func(network string) error {
		have, stoppedAndDeleting := c.getReconcilableNetworkState(network)
		compatible := util.AreNetworksCompatible(have, want)

		// we will dispose of the old network if deletion is in progress or if
		// non-reconcilable configuration changed
		dispose := stoppedAndDeleting || !compatible
		if dispose {
			err := c.deleteNetwork(network)
			if err != nil {
				return err
			}
			have = nil
		}

		// fetch other relevant network information
		err := c.gatherNetwork(want)
		if err != nil {
			return fmt.Errorf("failed to fetch other network information for network %s: %w", network, err)
		}

		ensureNetwork := !compatible || util.DoesNetworkNeedReconciliation(have, want)
		if !ensureNetwork {
			// no network changes
			return nil
		}

		// inform Controller manager of upcoming changes so other controllers are
		// aware
		err = c.cm.Reconcile(network, have, want)
		if err != nil {
			return fmt.Errorf("failed to reconcile Controller manager for network %s: %w", network, err)
		}

		// ensure the network
		err = c.ensureNetwork(want)
		if err != nil {
			return fmt.Errorf("%s: failed to ensure network %s: %w", c.name, network, err)
		}
		return nil
	})

	return err
}

// ensureNetwork should be called with a locked key for network cache
func (c *NodeNetworkController) ensureNetwork(network util.MutableNetInfo) error {
	if network == nil {
		return nil
	}

	networkName := network.GetNetworkName()
	reconcilable, _ := c.getReconcilableNetworkState(networkName)

	// this might just be an update of reconcilable network configuration
	if reconcilable != nil {
		err := reconcilable.Reconcile(network)
		if err != nil {
			return fmt.Errorf("failed to reconcile Controller for network %s: %w", networkName, err)
		}
		return nil
	}

	// otherwise set up the new network
	nc, err := c.cm.NewNetworkController(network)
	if err != nil {
		return fmt.Errorf("failed to create network %s: %w", networkName, err)
	}
	// Start only starts controllers that are not migrated over yet to a single controller
	err = nc.Start(context.Background())
	if err != nil {
		return fmt.Errorf("failed to start network %s: %w", networkName, err)
	}

	c.networkState.Store(networkName, &networkControllerState{nc, false})

	return nil
}

// deleteNetwork should be called with a locked key for network cache
func (c *NodeNetworkController) deleteNetwork(network string) error {
	have := c.getNetworkState(network)
	if have.controller == nil {
		return nil
	}

	if !have.stoppedAndDeleting {
		have.controller.Stop()
	}
	have.stoppedAndDeleting = true

	err := have.controller.Cleanup()
	if err != nil {
		return fmt.Errorf("%s: failed to cleanup network %s: %w", c.name, network, err)
	}

	c.networkState.Delete(network)
	return nil
}

// Cleanup is not used for NetworkController, cleanup is dispatched right now to sub controllers
func (c *NodeNetworkController) Cleanup() error {
	return nil
}

func (c *NodeNetworkController) gatherNetwork(network util.MutableNetInfo) error {
	if network == nil {
		return nil
	}
	return c.setAdvertisements(network)
}

func (c *NodeNetworkController) setAdvertisements(network util.MutableNetInfo) error {
	if !network.IsDefault() && !network.IsPrimaryNetwork() {
		return nil
	}
	if !c.hasRouteAdvertisements() {
		return nil
	}

	raNames := sets.New[string]()
	for _, nadNamespacedName := range network.GetNADs() {
		namespace, name, err := cache.SplitMetaNamespaceKey(nadNamespacedName)
		if err != nil {
			return err
		}

		nad, err := c.nadLister.NetworkAttachmentDefinitions(namespace).Get(name)
		if err != nil {
			return err
		}

		var nadRANames []string
		if nad.Annotations[types.OvnRouteAdvertisementsKey] != "" {
			err = json.Unmarshal([]byte(nad.Annotations[types.OvnRouteAdvertisementsKey]), &nadRANames)
			if err != nil {
				return err
			}
		}

		raNames.Insert(nadRANames...)
	}

	podAdvertisements := map[string][]string{}
	eipAdvertisements := map[string][]string{}
	for raName := range raNames {
		ra, err := c.raLister.Get(raName)
		if err != nil {
			return err
		}

		advertisements := sets.New(ra.Spec.Advertisements...)
		if !advertisements.Has(ratypes.PodNetwork) {
			continue
		}

		accepted := meta.FindStatusCondition(ra.Status.Conditions, "Accepted")
		if accepted == nil {
			// if there is no status we can safely ignore
			continue
		}
		if accepted.Status != metav1.ConditionTrue || accepted.ObservedGeneration != ra.Generation {
			// if the RA is not accepted, we commit to no change, best to
			// preserve the old config while we can't validate new config
			return fmt.Errorf("failed to reconcile network %q: RouteAdvertisements %q not in accepted status", network.GetNetworkName(), ra.Name)
		}

		nodeSelector, err := metav1.LabelSelectorAsSelector(&ra.Spec.NodeSelector)
		if err != nil {
			return err
		}

		nodes, err := c.nodeLister.List(nodeSelector)
		if err != nil {
			return err
		}

		vrf := ra.Spec.TargetVRF
		if vrf == "" {
			vrf = types.DefaultNetworkName
		}

		for _, node := range nodes {
			if !c.isNodeManaged(node) {
				continue
			}
			if advertisements.Has(ratypes.PodNetwork) {
				podAdvertisements[node.Name] = append(podAdvertisements[node.Name], vrf)
			}
			if advertisements.Has(ratypes.EgressIP) {
				eipAdvertisements[node.Name] = append(eipAdvertisements[node.Name], vrf)
			}
		}
	}
	network.SetPodNetworkAdvertisedVRFs(podAdvertisements)
	network.SetEgressIPAdvertisedVRFs(eipAdvertisements)
	return nil
}

func (c *NodeNetworkController) hasRouteAdvertisements() bool {
	return util.IsRouteAdvertisementsEnabled()
}

func (c *NodeNetworkController) isNodeManaged(node *corev1.Node) bool {
	switch {
	case c.node == "" && c.zone == "":
		// cluster manager manages all nodes
		return true
	case util.GetNodeZone(node) == c.zone:
		// ovnkube-Controller manages nodes of its zone
		return true
	case node.Name == c.node:
		// ovnkube-node only manages a specific node
		return true
	}
	return false
}

func (c *NodeNetworkController) GetRunningNetwork(id int) string {
	if id == types.DefaultNetworkID {
		return types.DefaultNetworkName
	}
	networkNames := c.networkState.GetKeys()
	var foundNetworkName string
	for _, networkName := range networkNames {
		_ = c.networkState.DoWithLock(networkName, func(key string) error {
			state, _ := c.networkState.Load(key)
			if state != nil && state.controller != nil && state.controller.GetNetworkID() == id {
				foundNetworkName = key
			}
			return nil
		})

		if foundNetworkName != "" {
			return foundNetworkName
		}
	}

	return ""
}

func (c *NodeNetworkController) GetAllNetworks() []string {
	return c.networkState.GetKeys()
}

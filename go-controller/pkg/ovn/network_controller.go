package ovn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/controller"
	ratypes "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1"
	ralisters "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/routeadvertisements/v1/apis/listers/routeadvertisements/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/retry"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/syncmap"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	utilerrors "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util/errors"
)

func NewNetworkController(name, zone, node string, cm networkmanager.ControllerManager, wf *factory.WatchFactory) networkmanager.UDNController {
	nc := &NetworkController{
		name:                 fmt.Sprintf("[%s network Controller]", name),
		node:                 node,
		zone:                 zone,
		cm:                   cm,
		networkInformerCache: map[string]util.MutableNetInfo{},
		networkState:         syncmap.NewSyncMap[*networkControllerState](),
		watchFactory:         wf,
		BaseUserDefinedNetworkController: BaseUserDefinedNetworkController{
			BaseNetworkController: BaseNetworkController{
				controllerName: name,
				stopChan:       make(chan struct{}),
				wg:             &sync.WaitGroup{},
				cancelableCtx:  util.NewCancelableContext(),
			},
		},
	}
	nc.initRetryFramework()

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

type networkControllerState struct {
	controller         networkmanager.NetworkController
	stoppedAndDeleting bool
}

type NetworkController struct {
	BaseUserDefinedNetworkController
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

	watchFactory *factory.WatchFactory
}

// Reconcile is called with the network key locked
func (c *NetworkController) Reconcile(netInfo util.NetInfo) error {
	state, loaded := c.networkState.Load(netInfo.GetNetworkName())
	if !loaded {
		panic("network controller does not exist during Reconcile. This should never happen")
	}
	if state.stoppedAndDeleting {
		return nil
	}
	switch netInfo.TopologyType() {
	case types.Layer3Topology:
		oc := state.controller.(*Layer3UserDefinedNetworkController)
		return oc.BaseNetworkController.reconcile(
			netInfo,
			func(node string) {
				oc.addNodeFailed.Store(node, true)
				oc.gatewaysFailed.Store(node, true)
			},
		)
	case types.Layer2Topology:
		oc := state.controller.(*Layer2UserDefinedNetworkController)
		return oc.BaseNetworkController.reconcile(
			netInfo,
			func(node string) { oc.gatewaysFailed.Store(node, true) },
		)
	case types.LocalnetTopology:
		oc := state.controller.(*LocalnetUserDefinedNetworkController)
		return oc.BaseNetworkController.reconcile(
			netInfo,
			func(_ string) {},
		)
	default:
		return fmt.Errorf("unknown network type: %v", netInfo.TopologyType())
	}
}

// Start will cleanup stale networkInformerCache that have not been ensured via
// EnsuredNetwork before this call
func (c *NetworkController) Start(_ context.Context) error {
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

	klog.Infof("Starting all the Watchers for Network Controller")
	start := time.Now()

	// WatchNamespaces() should be started first because it has no other
	// dependencies, and WatchNodes() depends on it
	if err := c.WatchNamespacesForce(); err != nil {
		return err
	}

	if err := c.WatchNodes(); err != nil {
		return err
	}

	if config.OVNKubernetesFeature.EnablePersistentIPs {
		// WatchIPAMClaims should be started before WatchPods to prevent OVN-K
		// master assigning IPs to pods without taking into account the persistent
		// IPs set aside for the IPAMClaims
		if err := c.WatchIPAMClaims(); err != nil {
			return err
		}
	}

	if err := c.WatchPods(); err != nil {
		return err
	}

	if util.IsMultiNetworkPoliciesSupportEnabled() {
		// WatchMultiNetworkPolicy depends on WatchPods and WatchNamespaces
		if err := c.WatchMultiNetworkPolicy(); err != nil {
			return err
		}
	}
	if err := c.WatchNetworkPolicy(); err != nil {
		return err
	}

	klog.Infof("Completing all the Watchers for Network Controller took %v", time.Since(start))

	return nil
}

func (c *NetworkController) Stop() {
	controllers := []controller.Reconciler{c.networkReconciler}
	if c.raController != nil {
		controllers = append(controllers, c.raController)
	}
	if c.nodeController != nil {
		controllers = append(controllers, c.nodeController)
	}
	controller.Stop(controllers...)

	klog.Info("Stopping Network Controller")
	close(c.stopChan)
	c.cancelableCtx.Cancel()
	c.wg.Wait()

	if c.netPolicyHandler != nil {
		c.watchFactory.RemovePolicyHandler(c.netPolicyHandler)
	}
	if c.multiNetPolicyHandler != nil {
		c.watchFactory.RemoveMultiNetworkPolicyHandler(c.multiNetPolicyHandler)
	}
	if c.podHandler != nil {
		c.watchFactory.RemovePodHandler(c.podHandler)
	}
	if c.nodeHandler != nil {
		c.watchFactory.RemoveNodeHandler(c.nodeHandler)
	}
	if c.namespaceHandler != nil {
		c.watchFactory.RemoveNamespaceHandler(c.namespaceHandler)
	}
}

// setNetwork updates the "informer cache" for networks with the latest version of the network, informed by NAD controller
func (c *NetworkController) setNetwork(network string, netInfo util.MutableNetInfo) {
	c.Lock()
	defer c.Unlock()
	if netInfo == nil {
		delete(c.networkInformerCache, network)
		return
	}
	c.networkInformerCache[network] = netInfo
}

// GetNetworkFromInformer retrieves the network from the network informer cache
func (c *NetworkController) GetNetworkFromInformer(network string) util.MutableNetInfo {
	c.RLock()
	defer c.RUnlock()
	return c.networkInformerCache[network]
}

func (c *NetworkController) getAllNetworksFromInformer() []util.NetInfo {
	c.RLock()
	defer c.RUnlock()
	networks := make([]util.NetInfo, 0, len(c.networkInformerCache))
	for _, network := range c.networkInformerCache {
		networks = append(networks, network)
	}
	return networks
}

func (c *NetworkController) GetNetworkFromCurrentState(network string) util.NetInfo {
	var netInfo util.NetInfo
	_ = c.networkState.DoWithLock(network, func(key string) error {
		state, _ := c.networkState.Load(key)
		netInfo = state.controller
		return nil
	})

	return netInfo
}

// EnsureNetwork enqueues network key to workqueue and updates network informer cache
func (c *NetworkController) EnsureNetwork(network util.MutableNetInfo) {
	c.setNetwork(network.GetNetworkName(), network)
	c.networkReconciler.Reconcile(network.GetNetworkName())
}

// DeleteNetwork removes the network from the network informer cache, and enqueues the network
func (c *NetworkController) DeleteNetwork(network string) {
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
func (c *NetworkController) getNetworkState(network string) *networkControllerState {
	state, exists := c.networkState.Load(network)
	if exists && state != nil {
		return state
	}
	return &networkControllerState{}
}

// getReconcilableNetworkState returns the controller responsible for the network if it is currently being tracked
// assumes locked key for active cache
func (c *NetworkController) getReconcilableNetworkState(network string) (networkmanager.ReconcilableNetworkController, bool) {
	if network == types.DefaultNetworkName {
		return c.cm.GetDefaultNetworkController(), false
	}
	state := c.getNetworkState(network)
	return state.controller, state.stoppedAndDeleting
}

// syncAll is not called with mutex protection. Should not call this other than during initial startup,
// before any handlers/controllers are running
func (c *NetworkController) syncAll() error {
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

func (c *NetworkController) syncRunningNetworks() error {
	c.networkReconciler.Reconcile(types.DefaultNetworkName)
	for _, network := range c.networkState.GetKeys() {
		c.networkReconciler.Reconcile(network)
	}

	return nil
}

// syncNetwork must be called with nm mutex locked
func (c *NetworkController) syncNetwork(network string) error {
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
func (c *NetworkController) ensureNetwork(network util.MutableNetInfo) error {
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
func (c *NetworkController) deleteNetwork(network string) error {
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
func (c *NetworkController) Cleanup() error {
	return nil
}

func (c *NetworkController) gatherNetwork(network util.MutableNetInfo) error {
	if network == nil {
		return nil
	}
	return c.setAdvertisements(network)
}

func (c *NetworkController) setAdvertisements(network util.MutableNetInfo) error {
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

func (c *NetworkController) hasRouteAdvertisements() bool {
	return util.IsRouteAdvertisementsEnabled()
}

func (c *NetworkController) isNodeManaged(node *corev1.Node) bool {
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

func raNeedsUpdate(oldRA, newRA *ratypes.RouteAdvertisements) bool {
	if oldRA == nil || newRA == nil {
		// handle RA add/delete through the NAD annotation update
		return false
	}

	// don't process resync or objects that are marked for deletion
	if oldRA.ResourceVersion == newRA.ResourceVersion ||
		!newRA.GetDeletionTimestamp().IsZero() {
		return false
	}

	// the RA needs to be accepted on its current generation, otherwise we
	// commit to no change
	newCondition := meta.FindStatusCondition(newRA.Status.Conditions, "Accepted")
	if newCondition == nil {
		return false
	}
	if newCondition.Status != metav1.ConditionTrue {
		return false
	}
	if newCondition.ObservedGeneration != newRA.Generation {
		return false
	}
	// there had to be a change on observed generation or status, otherwise we
	// already processed this RA in its current form
	oldCondition := meta.FindStatusCondition(oldRA.Status.Conditions, "Accepted")
	if oldCondition == nil {
		return true
	}
	return oldCondition.ObservedGeneration != newCondition.ObservedGeneration || oldCondition.Status != newCondition.Status
}

func nodeNeedsUpdate(oldNode, newNode *corev1.Node) bool {
	if oldNode == nil || newNode == nil {
		return true
	}

	// don't process resync or objects that are marked for deletion
	if oldNode.ResourceVersion == newNode.ResourceVersion ||
		!newNode.GetDeletionTimestamp().IsZero() {
		return false
	}

	return !reflect.DeepEqual(oldNode.Labels, newNode.Labels) || oldNode.Annotations[util.OvnNodeZoneName] != newNode.Annotations[util.OvnNodeZoneName]
}

func (c *NetworkController) GetRunningNetwork(id int) string {
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

func (c *NetworkController) GetAllNetworks() []string {
	return c.networkState.GetKeys()
}

type NetworkControllerEventHandler struct {
	baseHandler  baseNetworkControllerEventHandler
	watchFactory *factory.WatchFactory
	objType      reflect.Type
	oc           *NetworkController
	syncFunc     func([]interface{}) error
	subHandlers  sync.Map
}

// SyncFunc fires only on start up. Happens before watchFactory is started and after NetworkController workers start
// NetworkController will clean up stale networks, but for active networks, we need to clean up stale objects in that
// network.
func (h *NetworkControllerEventHandler) SyncFunc(objs []interface{}) error {
	// get all active networks, dispatch handling for each object
	activeNetworks := h.oc.networkState.GetKeys()
	var errs []error
	for _, network := range activeNetworks {
		err := h.oc.networkState.DoWithLock(network, func(key string) error {
			state, exists := h.oc.networkState.Load(key)
			if !exists || state.stoppedAndDeleting {
				return nil
			}
			switch state.controller.TopologyType() {
			case types.Layer3Topology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&Layer3UserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*Layer3UserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*Layer3UserDefinedNetworkControllerEventHandler).SyncFunc(objs)
				if err != nil {
					return err
				}
			case types.Layer2Topology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&layer2UserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*Layer2UserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*layer2UserDefinedNetworkControllerEventHandler).SyncFunc(objs)
				if err != nil {
					return err
				}
			case types.LocalnetTopology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&LocalnetUserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*LocalnetUserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*LocalnetUserDefinedNetworkControllerEventHandler).SyncFunc(objs)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unhandled topology type: %s for add event handling", state.controller.TopologyType())
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.Join(errs...)
}

// GetResourceFromInformerCache returns the latest state of the object, given an object key and its type.
// from the informers cache.
func (h *NetworkControllerEventHandler) GetResourceFromInformerCache(key string) (interface{}, error) {
	return h.baseHandler.getResourceFromInformerCache(h.objType, h.watchFactory, key)
}

// AreResourcesEqual returns true if, given two objects of a known resource type, the update logic for this resource
// type considers them equal and therefore no update is needed. It returns false when the two objects are not considered
// equal and an update needs be executed. This is regardless of how the update is carried out (whether with a dedicated update
// function or with a delete on the old obj followed by an add on the new obj).
func (h *NetworkControllerEventHandler) AreResourcesEqual(obj1, obj2 interface{}) (bool, error) {
	return h.baseHandler.areResourcesEqual(h.objType, obj1, obj2)
}

// GetInternalCacheEntry returns the internal cache entry for this object, given an object and its type.
// This is now used only for pods, which will get their the logical port cache entry.
func (h *NetworkControllerEventHandler) GetInternalCacheEntry(obj interface{}) interface{} {
	switch h.objType {
	case factory.PodType:
		// we store internal cache entry as a map[network]portMap for NetworkController
		// Then during delete handling, we look up which portMap matches the network we are looping through
		cachedEntry := make(map[string]interface{})
		activeNetworks := h.oc.networkState.GetKeys()
		for _, network := range activeNetworks {
			err := h.oc.networkState.DoWithLock(network, func(key string) error {
				state, exists := h.oc.networkState.Load(key)
				if !exists || state.stoppedAndDeleting {
					return nil
				}
				var entry interface{}
				switch state.controller.TopologyType() {
				case types.Layer3Topology:
					entry = state.controller.(*Layer3UserDefinedNetworkController).GetInternalCacheEntryForUserDefinedNetwork(factory.PodType, obj)
				case types.Layer2Topology:
					entry = state.controller.(*Layer2UserDefinedNetworkController).GetInternalCacheEntryForUserDefinedNetwork(factory.PodType, obj)
				case types.LocalnetTopology:
					entry = state.controller.(*LocalnetUserDefinedNetworkController).GetInternalCacheEntryForUserDefinedNetwork(factory.PodType, obj)
				default:
					return fmt.Errorf("unhandled topology type: %s for add event handling", state.controller.TopologyType())
				}
				if entry != nil {
					cachedEntry[network] = entry
				}
				return nil
			})
			pod := obj.(*corev1.Pod)
			if err != nil {
				klog.Errorf("Failed to get cached entry for pod %s/%s with error: %v", pod.Namespace, pod.Name, err)
			}
		}
		return cachedEntry
	default:
		return nil
	}
}

// IsResourceScheduled returns true if the given object has been scheduled.
// Only applied to pods for now. Returns true for all other types.
func (h *NetworkControllerEventHandler) IsResourceScheduled(obj interface{}) bool {
	return h.baseHandler.isResourceScheduled(h.objType, obj)
}

// IsObjectInTerminalState returns true if the given object is a in terminal state.
// This is used now for pods that are either in a PodSucceeded or in a PodFailed state.
func (h *NetworkControllerEventHandler) IsObjectInTerminalState(obj interface{}) bool {
	return h.baseHandler.isObjectInTerminalState(h.objType, obj)
}

// RecordAddEvent records the add event on this given object.
func (h *NetworkControllerEventHandler) RecordAddEvent(obj interface{}) {
	h.baseHandler.recordAddEvent(h.objType, obj)
}

// RecordUpdateEvent records the update event on this given object.
func (h *NetworkControllerEventHandler) RecordUpdateEvent(obj interface{}) {
	h.baseHandler.recordUpdateEvent(h.objType, obj)
}

// RecordDeleteEvent records the delete event on this given object.
func (h *NetworkControllerEventHandler) RecordDeleteEvent(obj interface{}) {
	h.baseHandler.recordDeleteEvent(h.objType, obj)
}

// RecordSuccessEvent records the success event on this given object.
func (h *NetworkControllerEventHandler) RecordSuccessEvent(obj interface{}) {
	h.baseHandler.recordSuccessEvent(h.objType, obj)
}

// RecordErrorEvent records the error event on this given object.
func (h *NetworkControllerEventHandler) RecordErrorEvent(_ interface{}, _ string, _ error) {
	// TODO(trozet): implement me
}

func (h *NetworkControllerEventHandler) FilterOutResource(_ interface{}) bool {
	// we don't want to filter out any resource as this controller is handling all networks
	return false
}

// AddResource adds the specified object to the cluster according to its type and returns the error,
// if any, yielded during object creation.
// Given an object to add and a boolean specifying if the function was executed from iterateRetryResources
func (h *NetworkControllerEventHandler) AddResource(obj interface{}, fromRetryLoop bool) error {
	// get all active networks, dispatch handling for each object
	// TODO(trozet): there is some overhead for each UDN controller doing AddResource
	// like annotation comparisons, etc. Can optimize this in the future
	activeNetworks := h.oc.networkState.GetKeys()
	var errs []error
	for _, network := range activeNetworks {
		err := h.oc.networkState.DoWithLock(network, func(key string) error {
			state, exists := h.oc.networkState.Load(key)
			if !exists || state.stoppedAndDeleting {
				return nil
			}
			switch state.controller.TopologyType() {
			case types.Layer3Topology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&Layer3UserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*Layer3UserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*Layer3UserDefinedNetworkControllerEventHandler).AddResource(obj, fromRetryLoop)
				if err != nil {
					return err
				}
			case types.Layer2Topology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&layer2UserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*Layer2UserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*layer2UserDefinedNetworkControllerEventHandler).AddResource(obj, fromRetryLoop)
				if err != nil {
					return err
				}
			case types.LocalnetTopology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&LocalnetUserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*LocalnetUserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*LocalnetUserDefinedNetworkControllerEventHandler).AddResource(obj, fromRetryLoop)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unhandled topology type: %s for add event handling", state.controller.TopologyType())
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.Join(errs...)
}

// UpdateResource updates the specified object in the cluster to its version in newObj according to its
// type and returns the error, if any, yielded during the object update.
// Given an old and a new object; The inRetryCache boolean argument is to indicate if the given resource
// is in the retryCache or not.
func (h *NetworkControllerEventHandler) UpdateResource(oldObj, newObj interface{}, inRetryCache bool) error {
	// get all active networks, dispatch handling for each object
	// TODO(trozet): there is some overhead for each UDN controller doing UpdateResource
	// like annotation comparisons, etc. Can optimize this in the future
	activeNetworks := h.oc.networkState.GetKeys()
	var errs []error
	for _, network := range activeNetworks {
		err := h.oc.networkState.DoWithLock(network, func(key string) error {
			state, exists := h.oc.networkState.Load(key)
			if !exists || state.stoppedAndDeleting {
				return nil
			}
			// Since we lock the controller, it is not possible that the NAD/Network Controller has been removed.
			// We feed add events back to the retry framework on controller creation with the networkState locked.
			// Although the controller and the event feed is protected, it is still possible that an update event for
			// this resource type triggers an Update event instead of Add. Like if:
			// 1. A resource had already failed to be updated and is in retry queue
			// 2. A new network comes up, requeues the resource
			// 3. retry framework fires for an update and this resource has update function
			// Therefore we allow for sub-handler to be created during Update as well if it is missing
			switch state.controller.TopologyType() {
			case types.Layer3Topology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&Layer3UserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*Layer3UserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*Layer3UserDefinedNetworkControllerEventHandler).UpdateResource(oldObj, newObj, inRetryCache)
				if err != nil {
					return err
				}
			case types.Layer2Topology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&layer2UserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*Layer2UserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*layer2UserDefinedNetworkControllerEventHandler).UpdateResource(oldObj, newObj, inRetryCache)
				if err != nil {
					return err
				}
			case types.LocalnetTopology:
				eventHandler, _ := h.subHandlers.LoadOrStore(network,
					&LocalnetUserDefinedNetworkControllerEventHandler{
						baseHandler:  baseNetworkControllerEventHandler{},
						objType:      h.objType,
						watchFactory: h.watchFactory,
						oc:           state.controller.(*LocalnetUserDefinedNetworkController),
						syncFunc:     nil,
					})
				err := eventHandler.(*LocalnetUserDefinedNetworkControllerEventHandler).UpdateResource(oldObj, newObj, inRetryCache)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unhandled topology type: %s for update event handling", state.controller.TopologyType())
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.Join(errs...)
}

// DeleteResource deletes the object from the cluster according to the delete logic of its resource type.
// Given an object and optionally a cachedObj; cachedObj is the internal cache entry for this object,
// used for now for pods and network policies.
func (h *NetworkControllerEventHandler) DeleteResource(obj, cachedObj interface{}) error {
	// get all active networks, dispatch handling for each object
	// TODO(trozet): there is some overhead for each UDN controller doing DeleteResource
	// like annotation comparisons, etc. Can optimize this in the future
	activeNetworks := h.oc.networkState.GetKeys()
	var errs []error
	for _, network := range activeNetworks {
		err := h.oc.networkState.DoWithLock(network, func(key string) error {
			state, exists := h.oc.networkState.Load(key)
			if !exists || state.stoppedAndDeleting {
				return nil
			}
			// Since we lock the controller, it is not possible that the NAD/Network Controller has been removed.
			// We feed add events back to the retry framework on controller creation with the networkState locked.
			// Although the controller and the event feed is protected, it is still possible that an update or delete event
			// for this resource type triggers an Delete event first.
			// Therefore we skip handling delete events if we have no sub-handler.
			// If there is no sub-handler, then we never created the object for this network in the first place,
			// so there is no point in trying to delete it.
			switch state.controller.TopologyType() {
			case types.Layer3Topology:
				eventHandler, loaded := h.subHandlers.Load(network)
				if !loaded {
					res, err := retry.GetResourceKey(obj)
					if err != nil {
						return err
					}
					klog.V(5).Infof("Ignoring delete for object %s for network %s with no event handler", res, network)
					return nil
				}
				var cachedEntry interface{}
				if cachedObj != nil {
					// we store the cachedObj as a map[network]interface, need to unpack it here
					cacheObjMap := cachedObj.(map[string]interface{})
					cachedEntry = cacheObjMap[key]
				}
				err := eventHandler.(*Layer3UserDefinedNetworkControllerEventHandler).DeleteResource(obj, cachedEntry)
				if err != nil {
					return err
				}
			case types.Layer2Topology:
				eventHandler, loaded := h.subHandlers.Load(network)
				if !loaded {
					res, err := retry.GetResourceKey(obj)
					if err != nil {
						return err
					}
					klog.V(5).Infof("Ignoring delete for object %s for network %s with no event handler", res, network)
					return nil
				}
				var cachedEntry interface{}
				if cachedObj != nil {
					// we store the cachedObj as a map[network]interface, need to unpack it here
					cacheObjMap := cachedObj.(map[string]interface{})
					cachedEntry = cacheObjMap[key]
				}
				err := eventHandler.(*layer2UserDefinedNetworkControllerEventHandler).DeleteResource(obj, cachedEntry)
				if err != nil {
					return err
				}
			case types.LocalnetTopology:
				eventHandler, loaded := h.subHandlers.Load(network)
				if !loaded {
					res, err := retry.GetResourceKey(obj)
					if err != nil {
						return err
					}
					klog.V(5).Infof("Ignoring delete for object %s for network %s with no event handler", res, network)
					return nil
				}
				var cachedEntry interface{}
				if cachedObj != nil {
					// we store the cachedObj as a map[network]interface, need to unpack it here
					cacheObjMap := cachedObj.(map[string]interface{})
					cachedEntry = cacheObjMap[key]
				}
				err := eventHandler.(*LocalnetUserDefinedNetworkControllerEventHandler).DeleteResource(obj, cachedEntry)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("unhandled topology type: %s for update event handling", state.controller.TopologyType())
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.Join(errs...)
}

// newRetryFramework builds and returns a retry framework for the input resource type;
func (c *NetworkController) newRetryFramework(
	objectType reflect.Type) *retry.RetryFramework {
	eventHandler := &NetworkControllerEventHandler{
		baseHandler:  baseNetworkControllerEventHandler{},
		objType:      objectType,
		watchFactory: c.watchFactory,
		oc:           c,
		syncFunc:     nil,
		subHandlers:  sync.Map{},
	}
	resourceHandler := &retry.ResourceHandler{
		HasUpdateFunc:          hasResourceAnUpdateFunc(objectType),
		NeedsUpdateDuringRetry: needsUpdateDuringRetry(objectType),
		ObjType:                objectType,
		EventHandler:           eventHandler,
	}
	return retry.NewRetryFramework(
		c.stopChan,
		c.wg,
		c.watchFactory,
		resourceHandler,
	)
}

func (c *NetworkController) initRetryFramework() {
	c.BaseNetworkController.retryPods = c.newRetryFramework(factory.PodType)
	c.BaseNetworkController.retryNodes = c.newRetryFramework(factory.NodeType)
	c.BaseNetworkController.retryNamespaces = c.newRetryFramework(factory.NamespaceType)
	c.BaseNetworkController.retryNetworkPolicies = c.newRetryFramework(factory.PolicyType)

	// For secondary networkInformerCache, we don't have to watch namespace events if
	// multi-network policy support is not enabled. We don't support
	// multi-network policy for IPAM-less secondary networkInformerCache either.
	if util.IsMultiNetworkPoliciesSupportEnabled() {
		c.BaseNetworkController.retryMultiNetworkPolicies = c.newRetryFramework(factory.MultiNetworkPolicyType)
	}
}

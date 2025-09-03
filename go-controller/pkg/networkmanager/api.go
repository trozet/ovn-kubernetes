package networkmanager

import (
	"context"
	"errors"

	"k8s.io/client-go/tools/record"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
)

var ErrNetworkControllerTopologyNotManaged = errors.New("no cluster network controller to manage topology")

const (
	// MaxNetworks is the maximum number of networks allowed.
	MaxNetworks = 4096
)

// Interface is the main package entrypoint and provides network related
// information to the rest of the project.
type Interface interface {
	// GetActiveNetworkForNamespace returns a copy of the primary network for
	// the namespace if any or the default network otherwise. If there is a
	// primary UDN defined but the NAD has not been processed yet, returns
	// ErrNetworkControllerTopologyNotManaged. Used for controllers that are not
	// capable of reconciling primary network changes. If unsure, use this one
	// and not GetActiveNetworkForNamespaceFast.
	GetActiveNetworkForNamespace(namespace string) (util.NetInfo, error)

	// GetActiveNetworkForNamespaceFast returns the primary network for the
	// namespace if any or the default network otherwise. It is faster than
	// GetActiveNetworkForNamespace because it does not copy the network and it
	// does not verify against UDNs. However, it is recommended to be used only
	// by controllers capable of reconciling primary network changes. If unsure,
	// use GetActiveNetworkForNamespace.
	GetActiveNetworkForNamespaceFast(namespace string) util.NetInfo

	// GetNetwork returns the network of the given name or nil if unknown
	GetNetwork(name string) util.NetInfo

	// GetActiveNetwork returns the NetInfo currently held by the controller for the given network.
	// This may differ from the NetInfo returned by GetNetwork which reflects the API state.
	// Returns nil if there is no running controller for the provided network.
	GetActiveNetwork(network string) util.NetInfo

	// DoWithLock takes care of locking and unlocking while iterating over all role primary user defined networks.
	DoWithLock(f func(network util.NetInfo) error) error
	GetActiveNetworkNamespaces(networkName string) ([]string, error)
}

// Controller handles the runtime of the package
type Controller interface {
	Interface() Interface
	Start() error
	Stop()
}

// Default returns a default implementation that assumes the default network is
// the only ever existing network. Used when multi-network capabilities are not
// enabled or testing.
func Default() Controller {
	return def
}

type NetworkControllerConstructor func(name, zone, node string, cm ControllerManager, wf *factory.WatchFactory) UDNController
type NodeNetworkControllerConstructor func(name, zone, node string, cm ControllerManager, wf factory.NodeWatchFactory) UDNController

// NewForCluster builds a controller for cluster manager
func NewForCluster(
	cm ControllerManager,
	wf *factory.WatchFactory,
	ncFunc NetworkControllerConstructor,
	ovnClient *util.OVNClusterManagerClientset,
	recorder record.EventRecorder,
) (Controller, error) {
	return newController(
		"clustermanager-nad-controller",
		"",
		"",
		cm,
		wf,
		ovnClient,
		ncFunc,
		recorder,
	)
}

// NewForZone builds a controller for zone manager
func NewForZone(
	zone string,
	cm ControllerManager,
	wf *factory.WatchFactory,
	ncFunc NetworkControllerConstructor,
) (Controller, error) {
	return newController(
		"zone-nad-controller",
		zone,
		"",
		cm,
		wf,
		nil,
		ncFunc,
		nil,
	)
}

// NewForNode builds a controller for node manager
func NewForNode(
	node string,
	cm ControllerManager,
	wf factory.NodeWatchFactory,
	ncFunc NodeNetworkControllerConstructor,
) (Controller, error) {
	return newNodeController(
		"node-nad-controller",
		"",
		node,
		cm,
		wf,
		nil,
		ncFunc,
		nil,
	)
}

// ControllerManager manages controllers. Needs to be provided in order to build
// new network controllers and to to be informed of potential stale networks in
// case it has clean-up of it's own to do.
type ControllerManager interface {
	NewNetworkController(netInfo util.NetInfo) (NetworkController, error)
	GetDefaultNetworkController() ReconcilableNetworkController
	CleanupStaleNetworks(validNetworks ...util.NetInfo) error

	// Reconcile informs the manager of network changes that other managed
	// network aware controllers might be interested in.
	Reconcile(name string, old, new util.NetInfo) error
}

// ReconcilableNetworkController is a network controller that can reconcile
// certain network configuration changes.
type ReconcilableNetworkController interface {
	util.NetInfo

	// Reconcile informs the controller of network configuration changes.
	Reconcile(util.NetInfo) error
}

// BaseNetworkController is a ReconcilableNetworkController that can be started and
// stopped.
type BaseNetworkController interface {
	ReconcilableNetworkController
	Start(ctx context.Context) error
	Stop()
}

// NetworkController is a BaseNetworkController that can also clean up after
// itself.
type NetworkController interface {
	BaseNetworkController
	Cleanup() error
}

type UDNController interface {
	BaseNetworkController
	Cleanup() error
	EnsureNetwork(network util.MutableNetInfo)
	DeleteNetwork(network string)
	GetNetworkFromInformer(network string) util.MutableNetInfo
	GetRunningNetwork(id int) string
	GetNetworkFromCurrentState(network string) util.NetInfo
	GetAllNetworks() []string
}

// defaultNetworkManager assumes the default network is
// the only ever existing network. Used when multi-network capabilities are not
// enabled or testing.
type defaultNetworkManager struct{}

func (nm defaultNetworkManager) Interface() Interface {
	return &nm
}

func (nm defaultNetworkManager) Start() error {
	return nil
}

func (nm defaultNetworkManager) Stop() {}

func (nm defaultNetworkManager) GetActiveNetworkForNamespace(string) (util.NetInfo, error) {
	return &util.DefaultNetInfo{}, nil
}

func (nm defaultNetworkManager) GetActiveNetworkForNamespaceFast(string) util.NetInfo {
	return &util.DefaultNetInfo{}
}

func (nm defaultNetworkManager) GetNetwork(name string) util.NetInfo {
	if name != types.DefaultNetworkName {
		return nil
	}
	return &util.DefaultNetInfo{}
}

func (nm defaultNetworkManager) DoWithLock(f func(network util.NetInfo) error) error {
	return f(&util.DefaultNetInfo{})
}

func (nm defaultNetworkManager) GetActiveNetworkNamespaces(_ string) ([]string, error) {
	return []string{"default"}, nil
}

func (nm defaultNetworkManager) GetActiveNetwork(network string) util.NetInfo {
	if network != types.DefaultNetworkName {
		return nil
	}
	return &util.DefaultNetInfo{}
}

var def Controller = &defaultNetworkManager{}

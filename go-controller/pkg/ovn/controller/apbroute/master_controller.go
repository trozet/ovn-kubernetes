package apbroute

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	libovsdbclient "github.com/ovn-org/libovsdb/client"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	adminpolicybasedrouteapi "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1"
	adminpolicybasedrouteclient "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1/apis/clientset/versioned"
	adminpolicybasedrouteinformer "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1/apis/informers/externalversions"
	adminpolicybasedroutelisters "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/adminpolicybasedroute/v1/apis/listers/adminpolicybasedroute/v1"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
)

const (
	resyncInterval = 0
	maxRetries     = 15
)

var (
	controllerName string
)

// Admin Policy Based Route services

type ExternalGatewayMasterController struct {
	client               kubernetes.Interface
	apbRoutePolicyClient adminpolicybasedrouteclient.Interface
	stopCh               <-chan struct{}

	// route policies

	// routerInformer v1apbinformer.AdminPolicyBasedExternalRouteInformer
	routeLister adminpolicybasedroutelisters.AdminPolicyBasedExternalRouteLister
	routeSynced cache.InformerSynced
	routeQueue  workqueue.RateLimitingInterface

	// Pods
	podLister corev1listers.PodLister
	podSynced cache.InformerSynced
	podQueue  workqueue.RateLimitingInterface

	// Namespaces
	namespaceQueue  workqueue.RateLimitingInterface
	namespaceLister corev1listers.NamespaceLister
	namespaceSynced cache.InformerSynced

	// External gateway caches
	// Make them public so that they can be used by the annotation logic to lock on namespaces and share the same external route information
	ExternalGWCache map[ktypes.NamespacedName]*ExternalRouteInfo
	ExGWCacheMutex  *sync.RWMutex

	routePolicyInformer adminpolicybasedrouteinformer.SharedInformerFactory

	mgr      *externalPolicyManager
	nbClient *northBoundClient
}

func NewExternalMasterController(
	parentControllerName string,
	client kubernetes.Interface,
	apbRoutePolicyClient adminpolicybasedrouteclient.Interface,
	stopCh <-chan struct{},
	podInformer coreinformers.PodInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	nodeLister corev1listers.NodeLister,
	nbClient libovsdbclient.Client,
	addressSetFactory addressset.AddressSetFactory,
) (*ExternalGatewayMasterController, error) {

	controllerName = parentControllerName
	routePolicyInformer := adminpolicybasedrouteinformer.NewSharedInformerFactory(apbRoutePolicyClient, resyncInterval)
	externalRouteInformer := routePolicyInformer.K8s().V1().AdminPolicyBasedExternalRoutes()
	externalGWCache := make(map[ktypes.NamespacedName]*ExternalRouteInfo)
	exGWCacheMutex := &sync.RWMutex{}
	nbCli := &northBoundClient{
		routeLister:       externalRouteInformer.Lister(),
		nodeLister:        nodeLister,
		nbClient:          nbClient,
		addressSetFactory: addressSetFactory,
		externalGWCache:   externalGWCache,
		exGWCacheMutex:    exGWCacheMutex,
	}

	c := &ExternalGatewayMasterController{
		client:               client,
		apbRoutePolicyClient: apbRoutePolicyClient,
		stopCh:               stopCh,
		routeLister:          externalRouteInformer.Lister(),
		routeSynced:          externalRouteInformer.Informer().HasSynced,
		routeQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.NewItemFastSlowRateLimiter(time.Second, 5*time.Second, 5),
			"adminpolicybasedexternalroutes",
		),
		podLister: podInformer.Lister(),
		podSynced: podInformer.Informer().HasSynced,
		podQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.NewItemFastSlowRateLimiter(time.Second, 5*time.Second, 5),
			"apbexternalroutepods",
		),
		namespaceLister: namespaceInformer.Lister(),
		namespaceSynced: namespaceInformer.Informer().HasSynced,
		namespaceQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.NewItemFastSlowRateLimiter(time.Second, 5*time.Second, 5),
			"apbexternalroutenamespaces",
		),
		ExternalGWCache:     externalGWCache,
		ExGWCacheMutex:      exGWCacheMutex,
		routePolicyInformer: routePolicyInformer,
		nbClient:            nbCli,
		mgr: newExternalPolicyManager(
			stopCh,
			podInformer.Lister(),
			namespaceInformer.Lister(),
			routePolicyInformer.K8s().V1().AdminPolicyBasedExternalRoutes().Lister(),
			nbCli),
	}

	_, err := namespaceInformer.Informer().AddEventHandler(
		factory.WithUpdateHandlingForObjReplace(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.onNamespaceAdd,
			UpdateFunc: c.onNamespaceUpdate,
			DeleteFunc: c.onNamespaceDelete,
		}))
	if err != nil {
		return nil, err
	}

	_, err = podInformer.Informer().AddEventHandler(
		factory.WithUpdateHandlingForObjReplace(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.onPodAdd,
			UpdateFunc: c.onPodUpdate,
			DeleteFunc: c.onPodDelete,
		}))
	if err != nil {
		return nil, err
	}
	_, err = externalRouteInformer.Informer().AddEventHandler(
		factory.WithUpdateHandlingForObjReplace(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.onPolicyAdd,
			UpdateFunc: c.onPolicyUpdate,
			DeleteFunc: c.onPolicyDelete,
		}))
	if err != nil {
		return nil, err
	}

	return c, nil

}

func (c *ExternalGatewayMasterController) Run(threadiness int) {
	defer utilruntime.HandleCrash()
	klog.Infof("Starting Admin Policy Based Route Controller")

	c.routePolicyInformer.Start(c.stopCh)

	startWg := &sync.WaitGroup{}

	for _, se := range []struct {
		resourceName string
		syncFn       cache.InformerSynced
	}{
		{"apbexternalroutenamespaces", c.namespaceSynced},
		{"apbexternalroutepods", c.podSynced},
		{"adminpolicybasedexternalroutes", c.routeSynced},
	} {
		startWg.Add(1)
		go func(resourceName string, syncFn cache.InformerSynced) {
			defer startWg.Done()
			if !cache.WaitForNamedCacheSync(resourceName, c.stopCh, syncFn) {
				utilruntime.HandleError(fmt.Errorf("timed out waiting for %q caches to sync", resourceName))
			}
		}(se.resourceName, se.syncFn)
	}

	klog.Infof("Repairing Admin Policy Based External Route Services")
	c.repair()

	startWg.Wait()
	wg := &sync.WaitGroup{}
	for i := 0; i < threadiness; i++ {
		for _, workerFn := range []func(*sync.WaitGroup){
			// processes route policies
			c.runPolicyWorker,
			// detects gateway pod changes and updates the pod's IP and MAC in the northbound DB
			c.runPodWorker,
			// detects namespace changes and applies polices that match the namespace selector in the `From` policy field
			c.runNamespaceWorker,
		} {
			// startWg.Add(1)
			wg.Add(1)
			go func(fn func(*sync.WaitGroup)) {
				// startWg.Done()
				defer wg.Done()
				wait.Until(func() {
					fn(wg)
				}, time.Second, c.stopCh)
			}(workerFn)
		}
	}

	// wait until we're told to stop
	<-c.stopCh

	c.podQueue.ShutDown()
	c.routeQueue.ShutDown()
	c.namespaceQueue.ShutDown()

	wg.Wait()
}

func (c *ExternalGatewayMasterController) runPolicyWorker(wg *sync.WaitGroup) {
	for c.processNextPolicyWorkItem(wg) {
	}
}

func (c *ExternalGatewayMasterController) processNextPolicyWorkItem(wg *sync.WaitGroup) bool {
	wg.Add(1)
	defer wg.Done()

	key, shutdown := c.routeQueue.Get()

	if shutdown {
		return false
	}

	defer c.routeQueue.Done(key)

	klog.Infof("Processing policy %s", key)
	policy, err := c.mgr.syncRoutePolicy(key.(string), c.routeQueue)
	if err != nil {
		klog.Errorf("Failed to sync APB policy %s: %v", key, err)
	}
	// capture the error from processing the sync in the statuses message field
	err = c.updateStatusAPBExternalRoute(policy, err)
	if err != nil {
		if c.routeQueue.NumRequeues(key) < maxRetries {
			klog.V(2).InfoS("Error found while processing policy: %w", err)
			c.routeQueue.AddRateLimited(key)
			return true
		}
		klog.Warningf("Dropping policy %q out of the queue: %w", key, err)
		utilruntime.HandleError(err)
	}
	c.routeQueue.Forget(key)
	return true
}

func (c *ExternalGatewayMasterController) onPolicyAdd(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	_ = obj.(*adminpolicybasedrouteapi.AdminPolicyBasedExternalRoute)
	klog.V(4).Infof("Adding policy %s", key)
	c.routeQueue.Add(key)
}

func (c *ExternalGatewayMasterController) onPolicyUpdate(oldObj, newObj interface{}) {
	oldRoutePolicy := oldObj.(*adminpolicybasedrouteapi.AdminPolicyBasedExternalRoute)
	newRoutePolicy := newObj.(*adminpolicybasedrouteapi.AdminPolicyBasedExternalRoute)

	if oldRoutePolicy.Generation == newRoutePolicy.Generation ||
		!newRoutePolicy.GetDeletionTimestamp().IsZero() {
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err == nil {
		c.routeQueue.Add(key)
	}
}

func (c *ExternalGatewayMasterController) onPolicyDelete(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	_ = obj.(*adminpolicybasedrouteapi.AdminPolicyBasedExternalRoute)
	c.routeQueue.Add(key)
}

func (c *ExternalGatewayMasterController) onNamespaceAdd(obj interface{}) {
	c.namespaceQueue.Add(obj)
}

func (c *ExternalGatewayMasterController) onNamespaceUpdate(oldObj, newObj interface{}) {
	oldNamespace := oldObj.(*v1.Namespace)
	newNamespace := newObj.(*v1.Namespace)

	if oldNamespace.ResourceVersion == newNamespace.ResourceVersion || !newNamespace.GetDeletionTimestamp().IsZero() {
		return
	}
	c.namespaceQueue.Add(newObj)
}

func (c *ExternalGatewayMasterController) onNamespaceDelete(obj interface{}) {
	c.namespaceQueue.Add(obj)
}

func (c *ExternalGatewayMasterController) runNamespaceWorker(wg *sync.WaitGroup) {
	for c.processNextNamespaceWorkItem(wg) {

	}
}

func (c *ExternalGatewayMasterController) processNextNamespaceWorkItem(wg *sync.WaitGroup) bool {
	wg.Add(1)
	defer wg.Done()

	obj, shutdown := c.namespaceQueue.Get()

	if shutdown {
		return false
	}

	defer c.namespaceQueue.Done(obj)

	err := c.mgr.syncNamespace(obj.(*v1.Namespace), c.routeQueue)
	if err != nil {
		if c.namespaceQueue.NumRequeues(obj) < maxRetries {
			klog.V(2).InfoS("Error found while processing namespace %s:%w", obj.(*v1.Namespace), err)
			c.namespaceQueue.AddRateLimited(obj)
			return true
		}
		klog.Warningf("Dropping namespace %q out of the queue: %v", obj.(*v1.Namespace).Name, err)
		utilruntime.HandleError(err)
	}
	c.namespaceQueue.Forget(obj)
	return true
}

func (c *ExternalGatewayMasterController) onPodAdd(obj interface{}) {
	o := obj.(*v1.Pod)
	// if the pod does not have IPs AND there are no multus network status annotations found, skip it
	if len(o.Status.PodIPs) == 0 && len(o.Annotations[nettypes.NetworkStatusAnnot]) == 0 {
		return
	}
	c.podQueue.Add(obj)
}

func (c *ExternalGatewayMasterController) onPodUpdate(oldObj, newObj interface{}) {
	o := oldObj.(*v1.Pod)
	n := newObj.(*v1.Pod)
	// if labels AND assigned Pod IPs AND networkStatus annotations are the same, skip processing changes to the pod.
	if reflect.DeepEqual(o.Labels, n.Labels) &&
		reflect.DeepEqual(o.Status.PodIPs, n.Status.PodIPs) &&
		reflect.DeepEqual(o.Annotations[nettypes.NetworkStatusAnnot], n.Annotations[nettypes.NetworkStatusAnnot]) {
		return
	}
	c.podQueue.Add(newObj)
}

func (c *ExternalGatewayMasterController) onPodDelete(obj interface{}) {
	c.podQueue.Add(obj)
}

func (c *ExternalGatewayMasterController) runPodWorker(wg *sync.WaitGroup) {
	for c.processNextPodWorkItem(wg) {
	}
}

func (c *ExternalGatewayMasterController) processNextPodWorkItem(wg *sync.WaitGroup) bool {
	wg.Add(1)
	defer wg.Done()

	obj, shutdown := c.podQueue.Get()

	if shutdown {
		return false
	}

	defer c.podQueue.Done(obj)

	p := obj.(*v1.Pod)
	err := c.mgr.syncPod(p, c.podLister, c.routeQueue)
	if err != nil {
		if c.podQueue.NumRequeues(obj) < maxRetries {
			klog.V(2).InfoS("Error found while processing pod %s/%s:%w", p.Namespace, p.Name, err)
			c.podQueue.AddRateLimited(obj)
			return true
		}
		klog.Warningf("Dropping pod %s/%s out of the queue: %s", p.Namespace, p.Name, err)
		utilruntime.HandleError(err)
	}

	c.podQueue.Forget(obj)
	return true
}

// updateStatusAPBExternalRoute updates the CR with the current status of the CR instance, including errors captured while processing the CR during its lifetime
func (c *ExternalGatewayMasterController) updateStatusAPBExternalRoute(externalRoutePolicy *adminpolicybasedrouteapi.AdminPolicyBasedExternalRoute, processedError error) error {
	if externalRoutePolicy == nil {
		// policy doesnt exist anymore, nothing to do
		return nil
	}

	processedPolicy, err := c.mgr.processExternalRoutePolicy(externalRoutePolicy)
	if err != nil {
		return err
	}

	gwIPs := sets.New[string]()
	if processedError == nil {
		for _, static := range processedPolicy.staticGateways {
			gwIPs = gwIPs.Insert(static.Gateways.UnsortedList()...)
		}
		for _, dynamic := range processedPolicy.dynamicGateways {
			gwIPs = gwIPs.Insert(dynamic.Gateways.UnsortedList()...)
		}
	}
	// retrieve the policy for update
	routePolicy, err := c.apbRoutePolicyClient.K8sV1().AdminPolicyBasedExternalRoutes().Get(context.TODO(), externalRoutePolicy.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		return processedError
	}
	if err != nil {
		return err
	}
	updateStatus(routePolicy, strings.Join(sets.List(gwIPs), ","), processedError)
	_, err = c.apbRoutePolicyClient.K8sV1().AdminPolicyBasedExternalRoutes().UpdateStatus(context.TODO(), routePolicy, metav1.UpdateOptions{})
	if !apierrors.IsNotFound(err) {
		return err
	}
	return processedError
}

func (c *ExternalGatewayMasterController) GetDynamicGatewayIPsForTargetNamespace(namespaceName string) (sets.Set[string], error) {
	return c.mgr.getDynamicGatewayIPsForTargetNamespace(namespaceName)
}

func (c *ExternalGatewayMasterController) GetStaticGatewayIPsForTargetNamespace(namespaceName string) (sets.Set[string], error) {
	return c.mgr.getStaticGatewayIPsForTargetNamespace(namespaceName)
}

func updateStatus(route *adminpolicybasedrouteapi.AdminPolicyBasedExternalRoute, gwIPs string, err error) {
	if err != nil {
		route.Status.Status = adminpolicybasedrouteapi.FailStatus
		route.Status.Messages = append(route.Status.Messages, "Failed to apply policy:%w", err.Error())
		return
	}
	route.Status.LastTransitionTime = metav1.Time{Time: time.Now()}
	route.Status.Status = adminpolicybasedrouteapi.SuccessStatus
	route.Status.Messages = append(route.Status.Messages, fmt.Sprintf("Configured external gateway IPs: %s", gwIPs))
	// klog.Infof("Updating Admin Policy Based External Route %s with Status: %s, Message: %s", route.Name, route.Status.Status, route.Status.Messages[len(route.Status.Messages)-1])
}

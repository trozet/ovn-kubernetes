package node

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/cni"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/kube"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	kapi "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// OvnNode is the object holder for utilities meant for node management
type OvnNode struct {
	name         string
	Kube         kube.Interface
	watchFactory *factory.WatchFactory
}

// NewNode creates a new controller for node management
func NewNode(kubeClient kubernetes.Interface, wf *factory.WatchFactory, name string) *OvnNode {
	return &OvnNode{
		name:         name,
		Kube:         &kube.Kube{KClient: kubeClient},
		watchFactory: wf,
	}
}

func setupOVNNode(node *kapi.Node) error {
	var err error

	nodeName, err := util.GetNodeHostname(node)
	if err != nil {
		return fmt.Errorf("failed to obtain hostname from node %q: %v", node.Name, err)
	}

	nodeIP := config.Default.EncapIP
	if nodeIP == "" {
		nodeIP, err = util.GetNodeIP(node)
		if err != nil {
			return fmt.Errorf("failed to obtain local IP from node %q: %v", node.Name, err)
		}
	} else {
		if ip := net.ParseIP(nodeIP); ip == nil {
			return fmt.Errorf("invalid encapsulation IP provided %q", nodeIP)
		}
	}

	_, stderr, err := util.RunOVSVsctl("set",
		"Open_vSwitch",
		".",
		fmt.Sprintf("external_ids:ovn-encap-type=%s", config.Default.EncapType),
		fmt.Sprintf("external_ids:ovn-encap-ip=%s", nodeIP),
		fmt.Sprintf("external_ids:ovn-remote-probe-interval=%d",
			config.Default.InactivityProbe),
		fmt.Sprintf("external_ids:ovn-openflow-probe-interval=%d",
			config.Default.OpenFlowProbe),
		fmt.Sprintf("external_ids:hostname=\"%s\"", nodeName),
		"external_ids:ovn-monitor-all=true",
	)
	if err != nil {
		return fmt.Errorf("error setting OVS external IDs: %v\n  %q", err, stderr)
	}
	// If EncapPort is not the default tell sbdb to use specified port.
	if config.Default.EncapPort != config.DefaultEncapPort {
		systemID, err := util.GetNodeChassisID()
		if err != nil {
			return err
		}
		uuid, _, err := util.RunOVNSbctl("--data=bare", "--no-heading", "--columns=_uuid", "find", "Encap",
			fmt.Sprintf("chassis_name=%s", systemID))
		if err != nil {
			return err
		}
		if len(uuid) == 0 {
			return fmt.Errorf("unable to find encap uuid to set geneve port for chassis %s", systemID)
		}
		_, stderr, errSet := util.RunOVNSbctl("set", "encap", uuid,
			fmt.Sprintf("options:dst_port=%d", config.Default.EncapPort),
		)
		if errSet != nil {
			return fmt.Errorf("error setting OVS encap-port: %v\n  %q", errSet, stderr)
		}
	}
	return nil
}

func isOVNControllerReady(name string) (bool, error) {
	runDir := util.GetOvnRunDir()

	pid, err := ioutil.ReadFile(runDir + "ovn-controller.pid")
	if err != nil {
		return false, fmt.Errorf("unknown pid for ovn-controller process: %v", err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		ctlFile := runDir + fmt.Sprintf("ovn-controller.%s.ctl", strings.TrimSuffix(string(pid), "\n"))
		ret, _, err := util.RunOVSAppctl("-t", ctlFile, "connection-status")
		if err == nil {
			klog.Infof("node %s connection status = %s", name, ret)
			return ret == "connected", nil
		}
		return false, err
	})
	if err != nil {
		return false, fmt.Errorf("timed out waiting sbdb for node %s: %v", name, err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		_, _, err := util.RunOVSVsctl("--", "br-exists", "br-int")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return false, fmt.Errorf("timed out checking whether br-int exists or not on node %s: %v", name, err)
	}

	err = wait.PollImmediate(500*time.Millisecond, 60*time.Second, func() (bool, error) {
		stdout, _, err := util.RunOVSOfctl("dump-aggregate", "br-int")
		if err != nil {
			return false, nil
		}
		return !strings.Contains(stdout, "flow_count=0"), nil
	})
	if err != nil {
		return false, fmt.Errorf("timed out dumping br-int flow entries for node %s: %v", name, err)
	}

	return true, nil
}

func getNodeHostSubnetAnnotation(node *kapi.Node) (string, error) {
	subnet, ok := node.Annotations[ovn.OvnNodeSubnets]
	if ok {
		nodeSubnets := make(map[string]string)
		if err := json.Unmarshal([]byte(subnet), &nodeSubnets); err != nil {
			return "", fmt.Errorf("error parsing node-subnets annotation: %v", err)
		}
		subnet, ok = nodeSubnets["default"]
	}
	if !ok {
		return "", fmt.Errorf("node %q has no subnet annotation", node.Name)
	}
	return subnet, nil
}

// Start learns the subnet assigned to it by the master controller
// and calls the SetupNode script which establishes the logical switch
func (n *OvnNode) Start() error {
	var err error
	var node *kapi.Node
	var subnet *net.IPNet
	var cidr string

	// Setting debug log level during node bring up to expose bring up process.
	// Log level is returned to configured value when bring up is complete.
	var level klog.Level
	lastLevel := fmt.Sprintf("%v", level.Get())

	if err := level.Set("5"); err != nil {
		klog.Errorf("setting klog \"loglevel\" to 5 failed, err: %v", err)
	}

	if config.MasterHA.ManageDBServers {
		var readyChan = make(chan bool, 1)

		err = n.watchConfigEndpoints(readyChan)
		if err != nil {
			return err
		}
		// Hold until we are certain that the endpoint has been setup.
		// We risk polling an inactive master if we don't wait while a new leader election is on-going
		<-readyChan
	} else {
		for _, auth := range []config.OvnAuthConfig{config.OvnNorth, config.OvnSouth} {
			if err := auth.SetDBAuth(); err != nil {
				return err
			}
		}
	}

	if node, err = n.Kube.GetNode(n.name); err != nil {
		return fmt.Errorf("error retrieving node %s: %v", n.name, err)
	}
	err = setupOVNNode(node)
	if err != nil {
		return err
	}

	// First wait for the node logical switch to be created by the Master, timeout is 300s.
	err = wait.PollImmediate(500*time.Millisecond, 300*time.Second, func() (bool, error) {
		if node, err = n.Kube.GetNode(n.name); err != nil {
			klog.Infof("waiting to retrieve node %s: %v", n.name, err)
			return false, nil
		}
		cidr, err = getNodeHostSubnetAnnotation(node)
		if err != nil {
			klog.Infof("waiting for node %s to start, no annotation found on node for subnet: %v", n.name, err)
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for node's: %q logical switch: %v", n.name, err)
	}

	_, subnet, err = net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid hostsubnet found for node %s: %v", n.name, err)
	}

	klog.Infof("Node %s ready for ovn initialization with subnet %s", n.name, subnet.String())

	if _, err = isOVNControllerReady(n.name); err != nil {
		return err
	}

	// force recompute of flows for ovn-controller periodically
	go func() {
		klog.Info("OVN-Controller resync thread started")
		for {
			_, stderr, err := util.RunOVNControllerAppCtl(" recompute")
			if err != nil {
				klog.Errorf("Failed to force ovn-controller flow re-computation: %s, %v", stderr, err)
			}
			time.Sleep(time.Duration(config.Default.OVNResyncTimer) * time.Second)
		}
	}()

	nodeAnnotator := kube.NewNodeAnnotator(n.Kube, node)
	waiter := newStartupWaiter(n.name)

	// Initialize gateway resources on the node
	if err := n.initGateway(subnet.String(), nodeAnnotator, waiter); err != nil {
		return err
	}

	// Initialize management port resources on the node
	if err := createManagementPort(n.name, subnet, nodeAnnotator, waiter); err != nil {
		return err
	}

	if err := nodeAnnotator.Run(); err != nil {
		return fmt.Errorf("Failed to set node %s annotations: %v", n.name, err)
	}

	// Wait for management port and gateway resources to be created by the master
	klog.Infof("Waiting for gateway and management port readiness...")
	start := time.Now()
	if err := waiter.Wait(); err != nil {
		return err
	}
	klog.Infof("Gateway and management port readiness took %v", time.Since(start))

	if err := level.Set(lastLevel); err != nil {
		klog.Errorf("reset of initial klog \"loglevel\" failed, err: %v", err)
	}

	confFile := filepath.Join(config.CNI.ConfDir, config.CNIConfFileName)
	_, err = os.Stat(confFile)
	if os.IsNotExist(err) {
		err = config.WriteCNIConfig(config.CNI.ConfDir, config.CNIConfFileName)
		if err != nil {
			return err
		}
	}

	// start the cni server
	cniServer := cni.NewCNIServer("")
	err = cniServer.Start(cni.HandleCNIRequest)

	return err
}

func updateOVNConfig(ep *kapi.Endpoints, readyChan chan bool) error {
	masterIPList, southboundDBPort, northboundDBPort, err := util.ExtractDbRemotesFromEndpoint(ep)
	if err != nil {
		return err
	}

	config.UpdateOVNNodeAuth(masterIPList, strconv.Itoa(int(southboundDBPort)), strconv.Itoa(int(northboundDBPort)))

	for _, auth := range []config.OvnAuthConfig{config.OvnNorth, config.OvnSouth} {
		if err := auth.SetDBAuth(); err != nil {
			return err
		}
	}

	klog.Infof("OVN databases reconfigured, masterIPs %v, northbound-db %v, southbound-db %v", masterIPList, northboundDBPort, southboundDBPort)

	readyChan <- true
	return nil
}

//watchConfigEndpoints starts the watching of Endpoint resource and calls back to the appropriate handler logic
func (n *OvnNode) watchConfigEndpoints(readyChan chan bool) error {
	_, err := n.watchFactory.AddFilteredEndpointsHandler(config.Kubernetes.OVNConfigNamespace, nil,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ep := obj.(*kapi.Endpoints)
				if ep.Name == "ovnkube-db" {
					if err := updateOVNConfig(ep, readyChan); err != nil {
						klog.Errorf(err.Error())
					}
				}
			},
			UpdateFunc: func(old, new interface{}) {
				epNew := new.(*kapi.Endpoints)
				epOld := old.(*kapi.Endpoints)
				if !reflect.DeepEqual(epNew.Subsets, epOld.Subsets) && epNew.Name == "ovnkube-db" {
					if err := updateOVNConfig(epNew, readyChan); err != nil {
						klog.Errorf(err.Error())
					}
				}
			},
		}, nil)
	return err
}

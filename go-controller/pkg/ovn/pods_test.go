package ovn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

func getPodAnnotations(fakeClient kubernetes.Interface, namespace, name string) string {
	pod, err := fakeClient.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return pod.Annotations[util.OvnPodAnnotationName]
}

func newPodMeta(namespace, name string, additionalLabels map[string]string) metav1.ObjectMeta {
	labels := map[string]string{
		"name": name,
	}
	for k, v := range additionalLabels {
		labels[k] = v
	}
	return metav1.ObjectMeta{
		Name:      name,
		UID:       types.UID(name),
		Namespace: namespace,
		Labels:    labels,
	}
}

func newPodWithLabels(namespace, name, node, podIP string, additionalLabels map[string]string) *v1.Pod {
	podIPs := []v1.PodIP{}
	if podIP != "" {
		podIPs = append(podIPs, v1.PodIP{IP: podIP})
	}
	return &v1.Pod{
		ObjectMeta: newPodMeta(namespace, name, additionalLabels),
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "containerName",
					Image: "containerImage",
				},
			},
			NodeName: node,
		},
		Status: v1.PodStatus{
			Phase:  v1.PodRunning,
			PodIP:  podIP,
			PodIPs: podIPs,
		},
	}
}

func newPod(namespace, name, node, podIP string) *v1.Pod {
	podIPs := []v1.PodIP{}
	if podIP != "" {
		podIPs = append(podIPs, v1.PodIP{IP: podIP})
	}
	return &v1.Pod{
		ObjectMeta: newPodMeta(namespace, name, nil),
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "containerName",
					Image: "containerImage",
				},
			},
			NodeName: node,
		},
		Status: v1.PodStatus{
			Phase:  v1.PodRunning,
			PodIP:  podIP,
			PodIPs: podIPs,
		},
	}
}

type pod struct {
	nodeName   string
	nodeSubnet string
	nodeMgtIP  string
	nodeGWIP   string
	podName    string
	podIP      string
	podMAC     string
	namespace  string
	portName   string
}

func newTPod(nodeName, nodeSubnet, nodeMgtIP, nodeGWIP, podName, podIP, podMAC, namespace string) (to pod) {
	to = pod{
		nodeName:   nodeName,
		nodeSubnet: nodeSubnet,
		nodeMgtIP:  nodeMgtIP,
		nodeGWIP:   nodeGWIP,
		podName:    podName,
		podIP:      podIP,
		podMAC:     podMAC,
		namespace:  namespace,
		portName:   namespace + "_" + podName,
	}
	return
}

func (p pod) baseCmds(fexec *ovntest.FakeExec) {
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --format=csv --data=bare --no-heading --columns=_uuid,output_port find Logical_Router_Static_Route options={ecmp_symmetric_reply=\"true\"}",
		Output: "",
	})
}

func (p pod) populateLogicalSwitchCache(fakeOvn *FakeOVN) {
	gomega.Expect(p.nodeName).NotTo(gomega.Equal(""))
	fakeOvn.controller.lsManager.AddNode(p.nodeName, []*net.IPNet{ovntest.MustParseIPNet(p.nodeSubnet)})
}

func (p pod) addCmds(fexec *ovntest.FakeExec, fail bool) {
	// pod setup
	if !fail {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists get logical_switch_port" + " " + p.portName + " dynamic_addresses addresses",
		})

		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --may-exist lsp-add " + p.nodeName + " " + p.portName + " -- lsp-set-addresses " + p.portName + " " + p.podMAC + " " + p.podIP + " -- set logical_switch_port " + p.portName + " external-ids:namespace=" + p.namespace + " external-ids:pod=true -- lsp-set-port-security " + p.portName + " " + p.podMAC + " " + p.podIP,
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd:    "ovn-nbctl --timeout=15 get logical_switch_port " + p.portName + " _uuid",
			Output: fakeUUID + "\n",
		})
	} else {
		fexec.AddFakeCmdsNoOutputNoError([]string{
			"ovn-nbctl --timeout=15 --if-exists get logical_switch_port" + " " + p.portName + " dynamic_addresses addresses",
		})
		fexec.AddFakeCmd(&ovntest.ExpectedCmd{
			Cmd: strings.Join([]string{
				"ovn-nbctl --timeout=15 --may-exist lsp-add " + p.nodeName + " " + p.portName + " -- lsp-set-addresses " + p.portName + " " + p.podMAC + " " + p.podIP + " -- set logical_switch_port " + p.portName + " external-ids:namespace=" + p.namespace + " external-ids:pod=true -- lsp-set-port-security " + p.portName + " " + p.podMAC + " " + p.podIP,
			}, " "),
			Err: fmt.Errorf("adsfadsfasfdasfd"),
		})
	}
}

func (p pod) addCmdsForNonExistingPod(fexec *ovntest.FakeExec) {
	p.addCmds(fexec, false)
}

var _ = ginkgo.Describe("OVN Pod Operations", func() {
	var (
		app     *cli.App
		fakeOvn *FakeOVN
		fExec   *ovntest.FakeExec
	)

	ginkgo.BeforeEach(func() {
		// Restore global default values before each testcase
		config.PrepareTestConfig()

		app = cli.NewApp()
		app.Name = "test"
		app.Flags = config.Flags

		fExec = ovntest.NewFakeExec()
		fakeOvn = NewFakeOVN(fExec)
	})

	ginkgo.AfterEach(func() {
		fakeOvn.shutdown()
	})


	ginkgo.Context("podscale", func() {
		ginkgo.It("scales pods", func() {
			fmt.Println("TROZET")
			app.Action = func(ctx *cli.Context) error {

				pods := make([]*v1.Pod, 500, 500)
				for i := 0; i < 500; i++ {
					pods[i] = &v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Namespace:   "default",
							Name:        fmt.Sprintf("my-pod:%d", i),
						},
					}
				}

				fakeOvn.start(ctx,
					&v1.NamespaceList{
					},
					&v1.PodList{
					},
				)
				fakeOvn.controller.WatchPods()

				for _, pod := range pods {
					_, err := fakeOvn.fakeClient.KubeClient.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
				}
				return nil
			}

			err := app.Run([]string{app.Name})
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			time.After(10* time.Second)
		})
	})
})


func TestPodScale(*testing.T) {
	var (
		app     *cli.App
		fakeOvn *FakeOVN
		fExec   *ovntest.FakeExec
	)

	config.PrepareTestConfig()

	config.IPv6Mode = true
	config.IPv4Mode = false
	app = cli.NewApp()
	app.Name = "test"
	app.Flags = config.Flags

	fExec = ovntest.NewFakeExec()
	fakeOvn = NewFakeOVN(fExec)
	fmt.Println("TROZET")
	app.Action = func(ctx *cli.Context) error {

		config.IPv6Mode = true
		config.IPv4Mode = false
		numPods := 5000
		pods := make([]v1.Pod, numPods, numPods)
		for i := 0; i < numPods; i++ {
			pods[i] = v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      fmt.Sprintf("my-pod:%d", i),
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "containerName",
							Image: "containerImage",
						},
					},
					NodeName: "node1",
				},
			}
		}

		fakeOvn.start(ctx,
			&v1.NamespaceList{
				Items: []v1.Namespace{
					v1.Namespace{
						ObjectMeta: metav1.ObjectMeta{
							UID:         types.UID("default"),
							Name:        "default",
						},
						Spec:       v1.NamespaceSpec{},
						Status:     v1.NamespaceStatus{},
					},
				},
			},
			&v1.PodList{
				Items: pods,
			},
		)
		fakeOvn.controller.lsManager.AddNode("node1", []*net.IPNet{ovntest.MustParseIPNet("fdda:9005:a1c5:bd04::/64")})
		fakeOvn.controller.WatchNamespaces()
		fakeOvn.controller.WatchPods()

		return nil
	}

	app.Run([]string{app.Name})
	fakeOvn.shutdown()
}
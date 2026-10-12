// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/ovn-kubernetes/ovn-kubernetes/test/e2e/images"
)

var _ = ginkgo.Describe("Pod network annotation admission", func() {
	f := wrappedTestFramework("pod-network-admission")
	ginkgo.BeforeEach(func() {
		_, err := f.ClientSet.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(context.Background(), "ovn-kubernetes-admission-webhook-pod", metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			ginkgo.Skip("requires the OVN pod admission webhook")
		}
		framework.ExpectNoError(err)
	})
	ginkgo.It("rejects supplied allocation results on creation and updates", func() {
		ctx := context.Background()
		pods := f.ClientSet.CoreV1().Pods(f.Namespace.Name)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "annotation-test", Annotations: map[string]string{OvnPodAnnotationName: ""}}, Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "test", Image: images.AgnHost()}},
			// Keep the pod unscheduled so no allocator races with the admission checks.
			SchedulingGates: []corev1.PodSchedulingGate{{Name: "example.com/admission-test"}},
		}}
		_, err := pods.Create(ctx, pod, metav1.CreateOptions{})
		gomega.Expect(err).To(gomega.HaveOccurred())
		gomega.Expect(err.Error()).To(gomega.ContainSubstring("must not be supplied on pod creation"))
		pod.Annotations = nil
		_, err = pods.Create(ctx, pod, metav1.CreateOptions{})
		framework.ExpectNoError(err)
		patch := []byte(`{"metadata":{"annotations":{"k8s.ovn.org/pod-networks":"forged"}}}`)
		for _, subresource := range [][]string{nil, {"status"}} {
			_, err = pods.Patch(ctx, pod.Name, ktypes.MergePatchType, patch, metav1.PatchOptions{}, subresource...)
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(err.Error()).To(gomega.ContainSubstring("not allowed to set"))
		}
		_, err = pods.Patch(ctx, pod.Name, ktypes.MergePatchType, []byte(`{"metadata":{"annotations":{"example.com/note":"allowed"}}}`), metav1.PatchOptions{})
		framework.ExpectNoError(err)
	})
})

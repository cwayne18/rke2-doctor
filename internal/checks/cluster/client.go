package cluster

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClientFromKubeconfig builds a Kubernetes clientset from the given
// kubeconfig path. RKE2 writes a ready-to-use kubeconfig to
// /etc/rancher/rke2/rke2.yaml on server nodes.
func NewClientFromKubeconfig(path string) (kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

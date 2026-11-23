// Package cluster contains diagnostics that require a working Kubernetes API
// connection (e.g. via kubeconfig). These are skipped gracefully when no
// client is available, so rke2-doctor still functions on an unreachable or
// not-yet-bootstrapped node.
package cluster

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cwayne18/rke2-doctor/internal/check"
)

// NodeReadyCheck lists cluster nodes and flags any that are NotReady or
// report pressure conditions (disk/memory/PID), which often precede pod
// evictions.
type NodeReadyCheck struct {
	Client kubernetes.Interface
}

func (c *NodeReadyCheck) Name() string     { return "node-ready" }
func (c *NodeReadyCheck) Category() string { return "cluster" }

func (c *NodeReadyCheck) Run(ctx context.Context) check.Result {
	if c.Client == nil {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Skip,
			Message: "no Kubernetes client available (pass --kubeconfig to enable cluster checks)",
		}
	}

	nodes, err := c.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Fail,
			Message: fmt.Sprintf("could not list nodes: %v", err),
		}
	}

	var problems []string
	for _, n := range nodes.Items {
		if msg := nodeProblems(n); msg != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", n.Name, msg))
		}
	}

	if len(problems) == 0 {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Pass,
			Message: fmt.Sprintf("%d node(s) Ready, no pressure conditions", len(nodes.Items)),
		}
	}
	return check.Result{
		Name: c.Name(), Category: c.Category(), Status: check.Fail,
		Message:     strings.Join(problems, "; "),
		Remediation: "run 'kubectl describe node <name>' on affected nodes for details",
	}
}

func nodeProblems(n corev1.Node) string {
	var issues []string
	for _, cond := range n.Status.Conditions {
		switch cond.Type {
		case corev1.NodeReady:
			if cond.Status != corev1.ConditionTrue {
				issues = append(issues, "NotReady")
			}
		case corev1.NodeDiskPressure, corev1.NodeMemoryPressure, corev1.NodePIDPressure, corev1.NodeNetworkUnavailable:
			if cond.Status == corev1.ConditionTrue {
				issues = append(issues, string(cond.Type))
			}
		}
	}
	return strings.Join(issues, ",")
}

// PodHealthCheck lists pods in kube-system (and any other requested
// namespaces) and flags ones that are pending, failed, or crash-looping.
type PodHealthCheck struct {
	Client     kubernetes.Interface
	Namespaces []string // default: kube-system
}

func (c *PodHealthCheck) Name() string     { return "pod-health" }
func (c *PodHealthCheck) Category() string { return "cluster" }

func (c *PodHealthCheck) Run(ctx context.Context) check.Result {
	if c.Client == nil {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Skip,
			Message: "no Kubernetes client available (pass --kubeconfig to enable cluster checks)",
		}
	}

	namespaces := c.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{"kube-system"}
	}

	var problems []string
	total := 0
	for _, ns := range namespaces {
		pods, err := c.Client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return check.Result{
				Name: c.Name(), Category: c.Category(), Status: check.Fail,
				Message: fmt.Sprintf("could not list pods in %s: %v", ns, err),
			}
		}
		for _, p := range pods.Items {
			total++
			if msg := podProblem(p); msg != "" {
				problems = append(problems, fmt.Sprintf("%s/%s: %s", ns, p.Name, msg))
			}
		}
	}

	if len(problems) == 0 {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Pass,
			Message: fmt.Sprintf("%d pod(s) checked across %v, none unhealthy", total, namespaces),
		}
	}
	return check.Result{
		Name: c.Name(), Category: c.Category(), Status: check.Fail,
		Message:     strings.Join(problems, "; "),
		Remediation: "run 'kubectl logs'/'kubectl describe pod' on the affected pods",
	}
}

func podProblem(p corev1.Pod) string {
	switch p.Status.Phase {
	case corev1.PodFailed:
		return "phase=Failed"
	case corev1.PodPending:
		return "phase=Pending"
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.RestartCount >= 5 {
			return fmt.Sprintf("container %s restarted %d times", cs.Name, cs.RestartCount)
		}
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			return fmt.Sprintf("container %s is CrashLoopBackOff", cs.Name)
		}
	}
	return ""
}

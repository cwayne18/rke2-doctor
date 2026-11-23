// Package config contains checks that parse and lint RKE2's config.yaml for
// known-problematic combinations of settings.
package config

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cwayne18/rke2-doctor/internal/check"
)

// defaultConfigPath is where RKE2 expects its config file on both server
// and agent nodes.
const defaultConfigPath = "/etc/rancher/rke2/config.yaml"

// LintCheck parses config.yaml and flags settings that are syntactically
// valid but operationally risky or contradictory.
type LintCheck struct {
	Path string
}

// NewLintCheck returns a LintCheck pointed at RKE2's default config path.
func NewLintCheck() *LintCheck {
	return &LintCheck{Path: defaultConfigPath}
}

func (c *LintCheck) Name() string     { return "config-lint" }
func (c *LintCheck) Category() string { return "config" }

func (c *LintCheck) Run(_ context.Context) check.Result {
	path := c.Path
	if path == "" {
		path = defaultConfigPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Skip,
			Message: fmt.Sprintf("%s not found", path),
		}
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Fail,
			Message:     fmt.Sprintf("%s is not valid YAML: %v", path, err),
			Remediation: "fix the YAML syntax error above; RKE2 will fail to start otherwise",
		}
	}

	findings := Lint(raw)
	if len(findings) == 0 {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Pass,
			Message: fmt.Sprintf("%s has no known issues", path),
		}
	}

	status := check.Warn
	var messages []string
	var remediations []string
	for _, f := range findings {
		if f.Fail {
			status = check.Fail
		}
		messages = append(messages, f.Message)
		remediations = append(remediations, f.Remediation)
	}

	return check.Result{
		Name: c.Name(), Category: c.Category(), Status: status,
		Message:     strings.Join(messages, "; "),
		Remediation: strings.Join(remediations, "; "),
	}
}

// Finding is a single config.yaml issue detected by Lint.
type Finding struct {
	Message     string
	Remediation string
	Fail        bool // true => Fail severity, false => Warn severity
}

// Lint inspects a parsed config.yaml document for known-risky settings.
// It is a pure function (no file I/O) so it can be unit tested directly.
func Lint(cfg map[string]interface{}) []Finding {
	var findings []Finding

	if f := lintKubeconfigMode(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := lintTLSSAN(cfg); f != nil {
		findings = append(findings, *f)
	}
	if f := lintCIDROverlap(cfg); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

func lintKubeconfigMode(cfg map[string]interface{}) *Finding {
	v, ok := cfg["write-kubeconfig-mode"]
	if !ok {
		return nil
	}
	mode := fmt.Sprintf("%v", v)
	// Flag world-readable/writable modes; RKE2 defaults to 0600 (owner-only).
	if strings.HasSuffix(mode, "4") || strings.HasSuffix(mode, "6") || strings.HasSuffix(mode, "7") {
		return &Finding{
			Message:     fmt.Sprintf("write-kubeconfig-mode %q is world-readable or world-writable", mode),
			Remediation: "set write-kubeconfig-mode to \"0600\" (or \"0640\" with a trusted group) to avoid leaking cluster-admin credentials",
		}
	}
	return nil
}

func lintTLSSAN(cfg map[string]interface{}) *Finding {
	v, ok := cfg["tls-san"]
	if !ok {
		return nil
	}
	list, ok := v.([]interface{})
	if ok && len(list) == 0 {
		return &Finding{
			Message:     "tls-san is present but empty",
			Remediation: "add the load-balancer/VIP hostname or IP used to reach this server to tls-san, or remove the empty key",
		}
	}
	return nil
}

func lintCIDROverlap(cfg map[string]interface{}) *Finding {
	clusterCIDR, _ := cfg["cluster-cidr"].(string)
	serviceCIDR, _ := cfg["service-cidr"].(string)
	if clusterCIDR == "" || serviceCIDR == "" {
		return nil
	}

	for _, clusterStr := range strings.Split(clusterCIDR, ",") {
		for _, serviceStr := range strings.Split(serviceCIDR, ",") {
			if cidrsOverlap(strings.TrimSpace(clusterStr), strings.TrimSpace(serviceStr)) {
				return &Finding{
					Message:     fmt.Sprintf("cluster-cidr %q overlaps service-cidr %q", clusterStr, serviceStr),
					Remediation: "choose non-overlapping ranges for cluster-cidr and service-cidr; overlap causes unpredictable routing",
					Fail:        true,
				}
			}
		}
	}
	return nil
}

func cidrsOverlap(a, b string) bool {
	_, netA, errA := net.ParseCIDR(a)
	_, netB, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return false
	}
	return netA.Contains(netB.IP) || netB.Contains(netA.IP)
}

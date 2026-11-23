package host

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/cwayne18/rke2-doctor/internal/check"
)

// sysctlRequirement is a single /proc/sys entry RKE2 relies on, along with
// the value it must have.
type sysctlRequirement struct {
	path string
	want string
	why  string
}

var requiredSysctls = []sysctlRequirement{
	{path: "/proc/sys/net/bridge/bridge-nf-call-iptables", want: "1", why: "required for kube-proxy iptables rules to see bridged traffic"},
	{path: "/proc/sys/net/ipv4/ip_forward", want: "1", why: "required for pod-to-pod routing across nodes"},
}

// SysctlCheck verifies kernel network sysctls RKE2 requires are set
// correctly. It fails (not just warns) because an incorrect value here
// silently breaks pod networking rather than preventing startup.
type SysctlCheck struct {
	Requirements []sysctlRequirement
}

// NewSysctlCheck returns a SysctlCheck configured with RKE2's required
// network sysctls.
func NewSysctlCheck() *SysctlCheck {
	return &SysctlCheck{Requirements: requiredSysctls}
}

func (c *SysctlCheck) Name() string     { return "network-sysctls" }
func (c *SysctlCheck) Category() string { return "host" }

func (c *SysctlCheck) Run(_ context.Context) check.Result {
	var wrong []string
	var missing []string
	for _, req := range c.Requirements {
		got, err := readSysctl(req.path)
		if err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, req.path)
			}
			continue
		}
		if got != req.want {
			wrong = append(wrong, fmt.Sprintf("%s=%s (want %s): %s", req.path, got, req.want, req.why))
		}
	}

	switch {
	case len(wrong) > 0:
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Fail,
			Message:     strings.Join(wrong, "; "),
			Remediation: "set via 'sysctl -w <path>=<value>' and persist in /etc/sysctl.d/90-rke2.conf",
		}
	case len(missing) > 0:
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Skip,
			Message: fmt.Sprintf("sysctl paths not present (module not loaded?): %s", strings.Join(missing, ", ")),
		}
	default:
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Pass,
			Message: "required network sysctls set correctly",
		}
	}
}

func readSysctl(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

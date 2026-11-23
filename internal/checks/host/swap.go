package host

import (
	"bufio"
	"context"
	"os"

	"github.com/cwayne18/rke2-doctor/internal/check"
)

// SwapCheck verifies whether swap is enabled. Kubernetes historically
// required swap disabled; recent versions support it behind the NodeSwap
// feature gate, so this is a Warn (not Fail) to flag for review rather than
// assume misconfiguration.
type SwapCheck struct {
	SwapsPath string // default: /proc/swaps
}

// NewSwapCheck returns a SwapCheck using the real /proc/swaps path.
func NewSwapCheck() *SwapCheck {
	return &SwapCheck{SwapsPath: "/proc/swaps"}
}

func (c *SwapCheck) Name() string     { return "swap-enabled" }
func (c *SwapCheck) Category() string { return "host" }

func (c *SwapCheck) Run(_ context.Context) check.Result {
	path := c.SwapsPath
	if path == "" {
		path = "/proc/swaps"
	}
	f, err := os.Open(path)
	if err != nil {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Skip,
			Message: "could not read /proc/swaps",
		}
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lines := 0
	for scanner.Scan() {
		lines++
	}

	if lines > 1 { // header line + at least one active swap entry
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Warn,
			Message:     "swap is enabled",
			Remediation: "disable swap ('swapoff -a' + remove fstab entry) unless intentionally running with the NodeSwap feature gate",
		}
	}
	return check.Result{
		Name: c.Name(), Category: c.Category(), Status: check.Pass,
		Message: "swap is disabled",
	}
}

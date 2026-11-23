package host

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/cwayne18/rke2-doctor/internal/check"
)

// rke2Paths are directories RKE2 writes substantial, growing data to:
// etcd/container images/overlay layers and kubelet ephemeral storage.
// Running out of space on either silently wedges the control plane or pods.
var rke2Paths = []string{
	"/var/lib/rancher/rke2",
	"/var/lib/kubelet",
}

// DiskSpaceCheck verifies free space on RKE2's data directories stays above
// warn/fail thresholds (expressed as a percentage of total capacity).
type DiskSpaceCheck struct {
	Paths       []string
	WarnPercent float64 // e.g. 15.0 => warn below 15% free
	FailPercent float64 // e.g. 5.0  => fail below 5% free
	statfs      func(path string, buf *syscall.Statfs_t) error
}

// NewDiskSpaceCheck returns a DiskSpaceCheck configured with RKE2's data
// directories and sensible default thresholds.
func NewDiskSpaceCheck() *DiskSpaceCheck {
	return &DiskSpaceCheck{
		Paths:       rke2Paths,
		WarnPercent: 15.0,
		FailPercent: 5.0,
	}
}

func (c *DiskSpaceCheck) Name() string     { return "disk-space" }
func (c *DiskSpaceCheck) Category() string { return "host" }

func (c *DiskSpaceCheck) Run(_ context.Context) check.Result {
	statfs := c.statfs
	if statfs == nil {
		statfs = syscall.Statfs
	}

	var messages []string
	status := check.Pass
	checked := 0
	for _, p := range c.Paths {
		if _, err := os.Stat(p); err != nil {
			continue // directory doesn't exist yet (e.g. node not yet installed)
		}
		var buf syscall.Statfs_t
		if err := statfs(p, &buf); err != nil {
			messages = append(messages, fmt.Sprintf("%s: could not stat (%v)", p, err))
			continue
		}
		checked++
		total := uint64(buf.Blocks) * uint64(buf.Bsize)
		free := uint64(buf.Bavail) * uint64(buf.Bsize)
		if total == 0 {
			continue
		}
		freePct := float64(free) / float64(total) * 100

		switch {
		case freePct < c.FailPercent:
			status = check.Fail
			messages = append(messages, fmt.Sprintf("%s: %.1f%% free (below %.0f%% fail threshold)", p, freePct, c.FailPercent))
		case freePct < c.WarnPercent:
			if status != check.Fail {
				status = check.Warn
			}
			messages = append(messages, fmt.Sprintf("%s: %.1f%% free (below %.0f%% warn threshold)", p, freePct, c.WarnPercent))
		default:
			messages = append(messages, fmt.Sprintf("%s: %.1f%% free", p, freePct))
		}
	}

	if checked == 0 {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Skip,
			Message: "no RKE2 data directories found to check",
		}
	}

	remediation := ""
	if status != check.Pass {
		remediation = "free up space, or move the directory to a larger volume via 'data-dir' in config.yaml"
	}
	return check.Result{
		Name: c.Name(), Category: c.Category(), Status: status,
		Message:     joinSemicolon(messages),
		Remediation: remediation,
	}
}

func joinSemicolon(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

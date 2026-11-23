package host

import (
	"os"
	"syscall"
	"testing"
)

func TestDiskSpaceCheckPass(t *testing.T) {
	dir := t.TempDir()
	c := &DiskSpaceCheck{
		Paths:       []string{dir},
		WarnPercent: 15,
		FailPercent: 5,
		statfs: func(path string, buf *syscall.Statfs_t) error {
			buf.Blocks = 1000
			buf.Bavail = 500 // 50% free
			buf.Bsize = 4096
			return nil
		},
	}
	res := c.Run(nil)
	if res.Status != 0 { // check.Pass == 0
		t.Errorf("expected Pass, got %v: %s", res.Status, res.Message)
	}
}

func TestDiskSpaceCheckWarn(t *testing.T) {
	dir := t.TempDir()
	c := &DiskSpaceCheck{
		Paths:       []string{dir},
		WarnPercent: 15,
		FailPercent: 5,
		statfs: func(path string, buf *syscall.Statfs_t) error {
			buf.Blocks = 1000
			buf.Bavail = 100 // 10% free: below warn, above fail
			buf.Bsize = 4096
			return nil
		},
	}
	res := c.Run(nil)
	if res.Status != 1 { // check.Warn == 1
		t.Errorf("expected Warn, got %v: %s", res.Status, res.Message)
	}
}

func TestDiskSpaceCheckFail(t *testing.T) {
	dir := t.TempDir()
	c := &DiskSpaceCheck{
		Paths:       []string{dir},
		WarnPercent: 15,
		FailPercent: 5,
		statfs: func(path string, buf *syscall.Statfs_t) error {
			buf.Blocks = 1000
			buf.Bavail = 20 // 2% free: below fail threshold
			buf.Bsize = 4096
			return nil
		},
	}
	res := c.Run(nil)
	if res.Status != 2 { // check.Fail == 2
		t.Errorf("expected Fail, got %v: %s", res.Status, res.Message)
	}
	if res.Remediation == "" {
		t.Errorf("expected a remediation hint on Fail")
	}
}

func TestDiskSpaceCheckSkipsMissingPaths(t *testing.T) {
	c := &DiskSpaceCheck{
		Paths: []string{"/nonexistent-path-for-test"},
	}
	res := c.Run(nil)
	if res.Status != 3 { // check.Skip == 3
		t.Errorf("expected Skip for nonexistent paths, got %v", res.Status)
	}
}

func TestKernelModuleCheckAllPresent(t *testing.T) {
	dir := t.TempDir()
	procModules := dir + "/modules"
	if err := os.WriteFile(procModules, []byte("overlay 151552 1 - Live 0x0000000000000000\nbr_netfilter 32768 0 - Live 0x0000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &KernelModuleCheck{Modules: []string{"overlay", "br_netfilter"}, ProcModules: procModules}
	res := c.Run(nil)
	if res.Status != 0 {
		t.Errorf("expected Pass, got %v: %s", res.Status, res.Message)
	}
}

func TestKernelModuleCheckMissing(t *testing.T) {
	dir := t.TempDir()
	procModules := dir + "/modules"
	if err := os.WriteFile(procModules, []byte("overlay 151552 1 - Live 0x0000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &KernelModuleCheck{Modules: []string{"overlay", "br_netfilter"}, ProcModules: procModules}
	res := c.Run(nil)
	if res.Status != 2 {
		t.Errorf("expected Fail for missing br_netfilter, got %v: %s", res.Status, res.Message)
	}
}

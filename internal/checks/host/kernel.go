// Package host contains diagnostics that only need local read access to the
// node's filesystem/proc — no Kubernetes API or network access required.
package host

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cwayne18/rke2-doctor/internal/check"
)

// requiredModules lists kernel modules RKE2 depends on for networking.
var requiredModules = []string{"overlay", "br_netfilter"}

// KernelModuleCheck verifies that kernel modules RKE2 depends on are loaded
// or compiled in, either dynamically (/proc/modules) or built-in
// (modules.builtin for the running kernel).
type KernelModuleCheck struct {
	Modules      []string
	ProcModules  string // default: /proc/modules
	BuiltinGlob  string // default: /lib/modules/<uname-r>/modules.builtin
	unameRelease func() (string, error)
}

// NewKernelModuleCheck returns a KernelModuleCheck configured with RKE2's
// required modules and real system paths.
func NewKernelModuleCheck() *KernelModuleCheck {
	return &KernelModuleCheck{
		Modules:     requiredModules,
		ProcModules: "/proc/modules",
	}
}

func (c *KernelModuleCheck) Name() string     { return "kernel-modules" }
func (c *KernelModuleCheck) Category() string { return "host" }

func (c *KernelModuleCheck) Run(_ context.Context) check.Result {
	loaded, err := loadedModules(c.procModulesPath())
	if err != nil {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Skip,
			Message: fmt.Sprintf("could not read %s: %v", c.procModulesPath(), err),
		}
	}

	builtin, _ := builtinModules(c.builtinGlobPath())

	var missing []string
	for _, m := range c.Modules {
		if loaded[m] || builtin[m] {
			continue
		}
		missing = append(missing, m)
	}

	if len(missing) == 0 {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Pass,
			Message: fmt.Sprintf("required modules present: %s", strings.Join(c.Modules, ", ")),
		}
	}
	return check.Result{
		Name: c.Name(), Category: c.Category(), Status: check.Fail,
		Message:     fmt.Sprintf("missing kernel modules: %s", strings.Join(missing, ", ")),
		Remediation: fmt.Sprintf("run 'modprobe %s' and persist via /etc/modules-load.d/rke2.conf", strings.Join(missing, " ")),
	}
}

func (c *KernelModuleCheck) procModulesPath() string {
	if c.ProcModules != "" {
		return c.ProcModules
	}
	return "/proc/modules"
}

func (c *KernelModuleCheck) builtinGlobPath() string {
	if c.BuiltinGlob != "" {
		return c.BuiltinGlob
	}
	release, err := readUnameRelease()
	if err != nil {
		return ""
	}
	return filepath.Join("/lib/modules", release, "modules.builtin")
}

func loadedModules(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			out[fields[0]] = true
		}
	}
	return out, scanner.Err()
}

func builtinModules(path string) (map[string]bool, error) {
	if path == "" {
		return map[string]bool{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return map[string]bool{}, nil // not fatal; builtin list is best-effort
	}
	defer f.Close()

	out := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		base := filepath.Base(line)
		name := strings.TrimSuffix(base, ".ko")
		name = strings.TrimSuffix(name, ".ko.xz")
		name = strings.TrimSuffix(name, ".ko.gz")
		out[name] = true
	}
	return out, scanner.Err()
}

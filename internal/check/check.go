// Package check defines the core abstractions used by rke2-doctor: a Check
// is a single, independently runnable diagnostic that produces a Result.
package check

import "context"

// Status is the outcome of running a Check.
type Status int

const (
	// Pass indicates the check found no problems.
	Pass Status = iota
	// Warn indicates a non-critical issue that may still cause problems.
	Warn
	// Fail indicates a critical issue that is likely already causing problems.
	Fail
	// Skip indicates the check could not run in this environment (e.g. not a
	// server node, or no kubeconfig available) and was intentionally skipped.
	Skip
)

// String renders a Status for human-readable output.
func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	case Skip:
		return "SKIP"
	default:
		return "UNKNOWN"
	}
}

// Result is the outcome of running a single Check.
type Result struct {
	// Name of the check that produced this result.
	Name string `json:"name"`
	// Category groups related checks (host, config, cluster, network, logs).
	Category string `json:"category"`
	Status   Status `json:"status"`
	// Message is a short human-readable summary of what was found.
	Message string `json:"message"`
	// Remediation is an optional one-line suggestion for fixing a Warn/Fail.
	Remediation string `json:"remediation,omitempty"`
	// Evidence holds optional raw details (file contents, command output)
	// useful for support bundles; omitted from default text output.
	Evidence string `json:"evidence,omitempty"`
}

// Check is a single diagnostic. Implementations should be side-effect free
// (read-only) and must not assume network or Kubernetes API access unless
// Category() == "cluster".
type Check interface {
	// Name is a short, stable, unique identifier (e.g. "disk-space").
	Name() string
	// Category groups the check for filtering (host, config, cluster, network, logs).
	Category() string
	// Run executes the check and returns its Result. Implementations should
	// honor context cancellation for long-running operations (e.g. API calls).
	Run(ctx context.Context) Result
}

// Registry holds the set of Checks available to run.
type Registry struct {
	checks []Check
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds one or more Checks to the Registry.
func (r *Registry) Register(cs ...Check) {
	r.checks = append(r.checks, cs...)
}

// All returns every registered Check.
func (r *Registry) All() []Check {
	return r.checks
}

// ByCategory returns only the Checks matching the given category. An empty
// category returns all Checks.
func (r *Registry) ByCategory(category string) []Check {
	if category == "" {
		return r.All()
	}
	var out []Check
	for _, c := range r.checks {
		if c.Category() == category {
			out = append(out, c)
		}
	}
	return out
}

// Run executes every given Check in order and collects their Results.
// A panic in an individual check is recovered and converted into a Fail
// result so that one broken check cannot abort the whole run.
func Run(ctx context.Context, checks []Check) []Result {
	results := make([]Result, 0, len(checks))
	for _, c := range checks {
		results = append(results, runOne(ctx, c))
	}
	return results
}

func runOne(ctx context.Context, c Check) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res = Result{
				Name:     c.Name(),
				Category: c.Category(),
				Status:   Fail,
				Message:  "check panicked",
			}
		}
	}()
	return c.Run(ctx)
}

// WorstStatus returns the most severe Status among results, used to compute
// the process exit code (Pass=0, Warn=1, Fail=2).
func WorstStatus(results []Result) Status {
	worst := Pass
	for _, r := range results {
		if r.Status == Fail {
			return Fail
		}
		if r.Status == Warn {
			worst = Warn
		}
	}
	return worst
}

// ExitCode maps a Status to a process exit code.
func ExitCode(s Status) int {
	switch s {
	case Fail:
		return 2
	case Warn:
		return 1
	default:
		return 0
	}
}

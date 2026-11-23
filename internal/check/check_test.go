package check

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type fakeCheck struct {
	name     string
	category string
	status   Status
}

func (f fakeCheck) Name() string     { return f.name }
func (f fakeCheck) Category() string { return f.category }
func (f fakeCheck) Run(context.Context) Result {
	return Result{Name: f.name, Category: f.category, Status: f.status, Message: "test"}
}

type panickyCheck struct{}

func (panickyCheck) Name() string     { return "panicky" }
func (panickyCheck) Category() string { return "host" }
func (panickyCheck) Run(context.Context) Result {
	panic("boom")
}

func TestRegistryByCategory(t *testing.T) {
	r := NewRegistry()
	r.Register(
		fakeCheck{name: "a", category: "host", status: Pass},
		fakeCheck{name: "b", category: "cluster", status: Pass},
	)
	hostChecks := r.ByCategory("host")
	if len(hostChecks) != 1 || hostChecks[0].Name() != "a" {
		t.Fatalf("expected only check 'a', got %+v", hostChecks)
	}
	if len(r.ByCategory("")) != 2 {
		t.Fatalf("expected empty category to return all checks")
	}
}

func TestRunRecoversFromPanic(t *testing.T) {
	results := Run(context.Background(), []Check{panickyCheck{}})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != Fail {
		t.Errorf("expected a panicking check to produce Fail, got %v", results[0].Status)
	}
}

func TestWorstStatusAndExitCode(t *testing.T) {
	cases := []struct {
		results []Result
		want    Status
		code    int
	}{
		{[]Result{{Status: Pass}, {Status: Skip}}, Pass, 0},
		{[]Result{{Status: Pass}, {Status: Warn}}, Warn, 1},
		{[]Result{{Status: Warn}, {Status: Fail}, {Status: Pass}}, Fail, 2},
	}
	for _, tc := range cases {
		got := WorstStatus(tc.results)
		if got != tc.want {
			t.Errorf("WorstStatus(%+v) = %v, want %v", tc.results, got, tc.want)
		}
		if code := ExitCode(got); code != tc.code {
			t.Errorf("ExitCode(%v) = %d, want %d", got, code, tc.code)
		}
	}
}

func TestWriteJSONRoundTrips(t *testing.T) {
	results := []Result{
		{Name: "disk-space", Category: "host", Status: Fail, Message: "low disk", Remediation: "free space"},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, results); err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded[0]["status"] != "FAIL" {
		t.Errorf("expected status FAIL in JSON, got %+v", decoded[0])
	}
}

func TestWriteTextIncludesRemediationOnlyWhenNotPass(t *testing.T) {
	results := []Result{
		{Name: "ok-check", Category: "host", Status: Pass, Message: "fine", Remediation: "should not appear"},
		{Name: "bad-check", Category: "host", Status: Fail, Message: "broken", Remediation: "fix it"},
	}
	var buf bytes.Buffer
	WriteText(&buf, results, false)
	out := buf.String()
	if strings.Contains(out, "should not appear") {
		t.Errorf("remediation should be suppressed for Pass results: %s", out)
	}
	if !strings.Contains(out, "fix it") {
		t.Errorf("remediation should be shown for Fail results: %s", out)
	}
}

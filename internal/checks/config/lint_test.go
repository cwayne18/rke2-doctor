package config

import "testing"

func TestLintKubeconfigModeWorldReadable(t *testing.T) {
	cfg := map[string]interface{}{"write-kubeconfig-mode": "0644"}
	findings := Lint(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Fail {
		t.Errorf("expected a warn-level finding, got Fail=true")
	}
}

func TestLintKubeconfigModeSafe(t *testing.T) {
	cfg := map[string]interface{}{"write-kubeconfig-mode": "0600"}
	if findings := Lint(cfg); len(findings) != 0 {
		t.Errorf("expected no findings for a safe mode, got %+v", findings)
	}
}

func TestLintTLSSANEmpty(t *testing.T) {
	cfg := map[string]interface{}{"tls-san": []interface{}{}}
	findings := Lint(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestLintTLSSANPopulated(t *testing.T) {
	cfg := map[string]interface{}{"tls-san": []interface{}{"rke2.example.com"}}
	if findings := Lint(cfg); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}

func TestLintCIDROverlapDetected(t *testing.T) {
	cfg := map[string]interface{}{
		"cluster-cidr": "10.42.0.0/16",
		"service-cidr": "10.42.128.0/20",
	}
	findings := Lint(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !findings[0].Fail {
		t.Errorf("expected overlap to be Fail severity")
	}
}

func TestLintCIDRNoOverlap(t *testing.T) {
	cfg := map[string]interface{}{
		"cluster-cidr": "10.42.0.0/16",
		"service-cidr": "10.43.0.0/16",
	}
	if findings := Lint(cfg); len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}

func TestLintMultipleCIDRsOneOverlaps(t *testing.T) {
	cfg := map[string]interface{}{
		"cluster-cidr": "10.42.0.0/16,2001:db8:1::/56",
		"service-cidr": "10.43.0.0/16,2001:db8:1::/64",
	}
	findings := Lint(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected the dual-stack overlap to be caught, got %d findings", len(findings))
	}
}

func TestLintEmptyConfigNoFindings(t *testing.T) {
	if findings := Lint(map[string]interface{}{}); len(findings) != 0 {
		t.Errorf("expected no findings for empty config, got %+v", findings)
	}
}

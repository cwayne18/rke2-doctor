package bundle

import (
	"strings"
	"testing"
)

func TestRedactToken(t *testing.T) {
	in := []byte("token: K10abc123def456::server:xyz\nserver: https://1.2.3.4:9345\n")
	out := string(Redact(in))
	if strings.Contains(out, "K10abc123def456") {
		t.Errorf("token value was not redacted: %s", out)
	}
	if !strings.Contains(out, "token: [REDACTED]") {
		t.Errorf("expected redacted token key to be preserved, got: %s", out)
	}
	if !strings.Contains(out, "server: https://1.2.3.4:9345") {
		t.Errorf("non-secret lines should be preserved, got: %s", out)
	}
}

func TestRedactPrivateKey(t *testing.T) {
	in := []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKEY...DATA...\n-----END EC PRIVATE KEY-----\n")
	out := string(Redact(in))
	if strings.Contains(out, "MHcCAQEEIKEY") {
		t.Errorf("private key material was not redacted: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected placeholder in output: %s", out)
	}
}

func TestRedactBearerToken(t *testing.T) {
	in := []byte("Authorization: Bearer abc123.def456-ghi789\n")
	out := string(Redact(in))
	if strings.Contains(out, "abc123.def456-ghi789") {
		t.Errorf("bearer token was not redacted: %s", out)
	}
}

func TestRedactLeavesNonSecretContentUntouched(t *testing.T) {
	in := []byte("cluster-cidr: 10.42.0.0/16\nservice-cidr: 10.43.0.0/16\n")
	out := string(Redact(in))
	if out != string(in) {
		t.Errorf("expected non-secret content unchanged, got: %s", out)
	}
}

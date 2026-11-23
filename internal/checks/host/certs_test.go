package host

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCert(t *testing.T, dir, name string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".crt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCertExpiryCheckPass(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "server-ca", time.Now().Add(365*24*time.Hour))
	c := &CertExpiryCheck{Dirs: []string{dir}, WarnDays: 30, FailDays: 7}
	res := c.Run(nil)
	if res.Status != 0 {
		t.Errorf("expected Pass, got %v: %s", res.Status, res.Message)
	}
}

func TestCertExpiryCheckWarn(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "client-ca", time.Now().Add(20*24*time.Hour))
	c := &CertExpiryCheck{Dirs: []string{dir}, WarnDays: 30, FailDays: 7}
	res := c.Run(nil)
	if res.Status != 1 {
		t.Errorf("expected Warn, got %v: %s", res.Status, res.Message)
	}
}

func TestCertExpiryCheckFail(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "request-header-ca", time.Now().Add(3*24*time.Hour))
	c := &CertExpiryCheck{Dirs: []string{dir}, WarnDays: 30, FailDays: 7}
	res := c.Run(nil)
	if res.Status != 2 {
		t.Errorf("expected Fail, got %v: %s", res.Status, res.Message)
	}
}

func TestCertExpiryCheckNoCertsSkips(t *testing.T) {
	dir := t.TempDir()
	c := &CertExpiryCheck{Dirs: []string{dir}, WarnDays: 30, FailDays: 7}
	res := c.Run(nil)
	if res.Status != 3 {
		t.Errorf("expected Skip for empty dir, got %v", res.Status)
	}
}

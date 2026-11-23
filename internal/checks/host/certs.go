package host

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cwayne18/rke2-doctor/internal/check"
)

// defaultTLSDirs are where RKE2 server and agent nodes store generated
// certificates.
var defaultTLSDirs = []string{
	"/var/lib/rancher/rke2/server/tls",
	"/var/lib/rancher/rke2/agent",
}

// CertExpiryCheck scans PEM certificate files under one or more directories
// and flags any that are expired or expiring soon. RKE2 auto-rotates most
// certificates, but this catches cases where rotation has silently stopped
// working (e.g. clock skew, a stopped service) before an outage occurs.
type CertExpiryCheck struct {
	Dirs     []string
	WarnDays int
	FailDays int
	now      func() time.Time
}

// NewCertExpiryCheck returns a CertExpiryCheck using RKE2's default TLS
// directories and standard thresholds (warn at 30 days, fail at 7).
func NewCertExpiryCheck() *CertExpiryCheck {
	return &CertExpiryCheck{
		Dirs:     defaultTLSDirs,
		WarnDays: 30,
		FailDays: 7,
	}
}

func (c *CertExpiryCheck) Name() string     { return "certificate-expiry" }
func (c *CertExpiryCheck) Category() string { return "host" }

type certFinding struct {
	path     string
	daysLeft int
	notAfter time.Time
	subject  string
}

func (c *CertExpiryCheck) Run(_ context.Context) check.Result {
	now := time.Now
	if c.now != nil {
		now = c.now
	}

	var findings []certFinding
	scanned := 0
	for _, dir := range c.Dirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != ".crt" {
				return nil
			}
			cert, err := loadCert(path)
			if err != nil {
				return nil
			}
			scanned++
			daysLeft := int(cert.NotAfter.Sub(now()).Hours() / 24)
			findings = append(findings, certFinding{
				path:     path,
				daysLeft: daysLeft,
				notAfter: cert.NotAfter,
				subject:  cert.Subject.CommonName,
			})
			return nil
		})
	}

	if scanned == 0 {
		return check.Result{
			Name: c.Name(), Category: c.Category(), Status: check.Skip,
			Message: "no certificates found under configured TLS directories",
		}
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].daysLeft < findings[j].daysLeft })

	status := check.Pass
	msg := fmt.Sprintf("checked %d certificates; earliest expiry in %d days (%s)", scanned, findings[0].daysLeft, findings[0].path)
	remediation := ""
	switch {
	case findings[0].daysLeft < c.FailDays:
		status = check.Fail
		remediation = "run 'rke2 certificate rotate' and restart the service, or investigate why automatic rotation stopped"
	case findings[0].daysLeft < c.WarnDays:
		status = check.Warn
		remediation = "certificate rotation should happen automatically near expiry; confirm the rke2 service is healthy"
	}

	return check.Result{
		Name: c.Name(), Category: c.Category(), Status: status,
		Message:     msg,
		Remediation: remediation,
	}
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("not a PEM file")
	}
	return x509.ParseCertificate(block.Bytes)
}

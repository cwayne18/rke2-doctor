// Package bundle creates a redacted support bundle: a tar.gz containing
// RKE2 configuration, recent logs, and the doctor JSON report, suitable for
// attaching to a support ticket without leaking secrets.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"time"
)

// Source is a single file or command whose output is included in the bundle.
type Source struct {
	// Name is the path the content is stored under inside the archive.
	Name string
	// Path is a file to read, mutually exclusive with Command.
	Path string
	// Command is a shell command whose stdout is captured, mutually
	// exclusive with Path (used for e.g. `journalctl -u rke2-server`).
	Command []string
	// Redact, if true, runs the content through the redaction patterns
	// before writing it to the archive.
	Redact bool
}

// DefaultSources returns the standard set of files/commands collected into
// an RKE2 support bundle.
func DefaultSources() []Source {
	return []Source{
		{Name: "config.yaml", Path: "/etc/rancher/rke2/config.yaml", Redact: true},
		{Name: "journal-rke2-server.log", Command: []string{"journalctl", "-u", "rke2-server", "--no-pager", "-n", "2000"}, Redact: true},
		{Name: "journal-rke2-agent.log", Command: []string{"journalctl", "-u", "rke2-agent", "--no-pager", "-n", "2000"}, Redact: true},
	}
}

// redactPatterns match secret-bearing lines/values that must never leave the
// node unredacted: bearer tokens, cluster join tokens, and any PEM private
// key block.
var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(token:\s*)\S+`),
	regexp.MustCompile(`(?i)(agent-token:\s*)\S+`),
	regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._-]+`),
	regexp.MustCompile(`(?s)-----BEGIN[ A-Z]*PRIVATE KEY-----.*?-----END[ A-Z]*PRIVATE KEY-----`),
}

// Redact replaces secret material in b with a fixed placeholder, preserving
// surrounding context so the bundle is still useful for troubleshooting.
func Redact(b []byte) []byte {
	out := b
	for _, re := range redactPatterns {
		out = re.ReplaceAllFunc(out, func(match []byte) []byte {
			// For "key: value" style matches, keep the captured prefix and
			// replace only the secret portion that follows it.
			if loc := re.FindSubmatchIndex(match); len(loc) >= 4 && loc[2] >= 0 {
				prefix := match[loc[2]:loc[3]]
				return append(append([]byte{}, prefix...), []byte("[REDACTED]")...)
			}
			return []byte("[REDACTED]")
		})
	}
	return out
}

// Write collects the given sources plus an optional extra report file into
// a gzip-compressed tar archive at outPath.
func Write(outPath string, sources []Source, reportName string, reportContent []byte) error {
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating bundle file: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	if reportName != "" {
		if err := writeEntry(tw, reportName, reportContent); err != nil {
			return err
		}
	}

	for _, src := range sources {
		content, err := readSource(src)
		if err != nil {
			// Missing files/commands are expected (e.g. agent-only node has
			// no rke2-server journal); skip rather than fail the bundle.
			content = []byte(fmt.Sprintf("[rke2-doctor] could not collect %s: %v\n", src.Name, err))
		}
		if src.Redact {
			content = Redact(content)
		}
		if err := writeEntry(tw, src.Name, content); err != nil {
			return err
		}
	}

	return nil
}

func readSource(src Source) ([]byte, error) {
	if src.Path != "" {
		return os.ReadFile(src.Path)
	}
	if len(src.Command) == 0 {
		return nil, fmt.Errorf("source has neither Path nor Command")
	}
	//nolint:gosec // command list is a fixed, non-user-controlled set defined in DefaultSources
	out, err := exec.Command(src.Command[0], src.Command[1:]...).Output()
	return out, err
}

func writeEntry(tw *tar.Writer, name string, content []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(content)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("writing header for %s: %w", name, err)
	}
	if _, err := io.Copy(tw, bytes.NewReader(content)); err != nil {
		return fmt.Errorf("writing content for %s: %w", name, err)
	}
	return nil
}

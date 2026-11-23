package host

import (
	"os"
	"strings"
)

// osReleasePath is where the Linux kernel exposes `uname -r` as a plain
// string; reading this avoids architecture-specific syscall struct layouts.
const osReleasePath = "/proc/sys/kernel/osrelease"

// readUnameRelease returns the running kernel's release string (uname -r),
// used to locate /lib/modules/<release>/modules.builtin.
func readUnameRelease() (string, error) {
	b, err := os.ReadFile(osReleasePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

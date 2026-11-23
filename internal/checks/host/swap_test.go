package host

import (
	"os"
	"testing"
)

func TestSwapCheckDisabled(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/swaps"
	header := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
	if err := os.WriteFile(path, []byte(header), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &SwapCheck{SwapsPath: path}
	res := c.Run(nil)
	if res.Status != 0 {
		t.Errorf("expected Pass when only header present, got %v", res.Status)
	}
}

func TestSwapCheckEnabled(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/swaps"
	content := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swapfile  file  2097148  0  -2\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &SwapCheck{SwapsPath: path}
	res := c.Run(nil)
	if res.Status != 1 { // Warn
		t.Errorf("expected Warn when swap entry present, got %v", res.Status)
	}
}

//go:build rehearsal

package verifycmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rehearsal check's host key goes to rehearsal_known_hosts beside the
// record of verified keys, one line a sandbox, marked NOT ATTESTED; a
// second check of the same name replaces its line.
func TestRehearsalKnownHosts(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "sbx", "verified.json")
	file := RehearsalKnownHosts(record)
	if file != filepath.Join(dir, "sbx", "rehearsal_known_hosts") {
		t.Fatal(file)
	}
	const k1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	const k2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5WqUuNcLsKfQwwgrBkpwhkzYxEMv2QjGRo3pTMbDJ4"
	if k, err := RehearsalHostKey(file, "web"); k != "" || err != nil {
		t.Fatalf("no file: %q %v", k, err)
	}
	var out strings.Builder
	rehearsalRecord(&out, record, "web", "sbx-0123456789abcdef", k1+" comment")
	rehearsalRecord(&out, record, "db", "sbx-1123456789abcdef", k2)
	rehearsalRecord(&out, record, "web", "sbx-0123456789abcdef", k2)
	if !strings.Contains(out.String(), "REHEARSAL, host key NOT attested") {
		t.Errorf("printed:\n%s", out.String())
	}
	for name, want := range map[string]string{"web": k2, "db": k2, "api": ""} {
		if k, err := RehearsalHostKey(file, name); k != want || err != nil {
			t.Errorf("%s: %q %v, want %q", name, k, err, want)
		}
	}
	b, _ := os.ReadFile(file)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "# REHEARSAL ONLY") || strings.Count(string(b), " REHEARSAL-NOT-ATTESTED ") != 2 {
		t.Fatalf("the file:\n%s", b)
	}
	if _, err := os.Stat(record); err == nil {
		t.Error("the record of verified keys was written")
	}
}

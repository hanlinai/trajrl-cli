package sshsetup

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// An older setup's "KnownHostsCommand ... known-hosts %H" for *.DOMAIN is
// commented out, with a backup; other blocks, other domains and other
// commands are left as they are; twice is once.
func TestDropKnownHostsCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if c, b, err := DropKnownHostsCommand(path, "sbx.example"); c != nil || b != "" || err != nil {
		t.Fatalf("no file: %q %q %v", c, b, err)
	}
	before := "Host entry.example\n    Port 2222\n" +
		"# BEGIN trajrl sbx demo\nHost sbx.example\n    HostName 192.0.2.1\n" +
		"Host *.sbx.example\n    ProxyJump sbx.example\n    User root\n" +
		"    KnownHostsCommand /usr/bin/ssh sbx.example known-hosts %H\n    ServerAliveInterval 30\n# END trajrl sbx demo\n" +
		"Host *.other.example\n    KnownHostsCommand /usr/bin/ssh other.example known-hosts %H\n" +
		"Host web *.SBX.example\n\tKnownHostsCommand=/usr/bin/ssh sbx.example known-hosts %H\n" +
		"Host *.sbx.example\n    KnownHostsCommand /usr/local/bin/my-own-lookup %H\n" +
		"Match host *.sbx.example\n    KnownHostsCommand /usr/bin/ssh sbx.example known-hosts %H\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	changed, backup, err := DropKnownHostsCommand(path, "sbx.example")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"KnownHostsCommand /usr/bin/ssh sbx.example known-hosts %H", "KnownHostsCommand=/usr/bin/ssh sbx.example known-hosts %H"}
	if !reflect.DeepEqual(changed, want) {
		t.Fatalf("changed %q, want %q", changed, want)
	}
	if b, _ := os.ReadFile(backup); string(b) != before || filepath.Dir(backup) != dir || !strings.HasPrefix(filepath.Base(backup), "config.before-trajrl.") {
		t.Fatalf("backup %s: %q", backup, b)
	}
	after, _ := os.ReadFile(path)
	wantAfter := strings.Replace(before, "    KnownHostsCommand /usr/bin/ssh sbx.example known-hosts %H\n    ServerAlive",
		"    # (trajrl setup: off, the platform holds no host keys) KnownHostsCommand /usr/bin/ssh sbx.example known-hosts %H\n    ServerAlive", 1)
	wantAfter = strings.Replace(wantAfter, "\tKnownHostsCommand=", "\t# (trajrl setup: off, the platform holds no host keys) KnownHostsCommand=", 1)
	if string(after) != wantAfter {
		t.Fatalf("after:\n%s\nwant:\n%s", after, wantAfter)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if c, b, err := DropKnownHostsCommand(path, "sbx.example"); c != nil || b != "" || err != nil {
		t.Fatalf("twice: %q %q %v", c, b, err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "config.before-trajrl.*")); len(m) != 1 {
		t.Fatalf("backups: %q", m)
	}
}

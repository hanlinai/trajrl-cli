package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
)

// A colleague's known_hosts (#32): the owner's share ssh prints the line of
// the host key verified on the owner's machine, under the colleague's name
// for the sandbox; the colleague's known-hosts --import takes that shape
// only and records it for trajrl ssh and for their ssh. Without it, trajrl
// ssh refuses: nothing is taken on first use.
func TestSharedKnownHosts(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	const key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGs3l9DZzZkHn7r5qcWnkm2R3OM6yXcX9w9WyFzX5YkF"
	e := newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		switch cmd {
		case "whoami":
			fmt.Fprintln(out, "alice")
		case "show web --json":
			fmt.Fprintf(out, `{"name":"web","id":%q,"state":"running"}`+"\n", idB)
		case "share ssh web bob":
			fmt.Fprintln(out, "web  running\n  shared with:  bob")
		default:
			fmt.Fprintf(errw, "unexpected %q\n", cmd)
			return 2
		}
		return 0
	})
	// The owner: web's host key verified here, but of another sandbox (ID)
	// first.
	newHome(t, e)
	pin := sbxapi.Pin{Name: "web", ID: idA, HostKey: key, Verified: time.Now()}
	if err := sbxapi.RecordPin(sbxapi.DefaultPinFile(), pin); err != nil {
		t.Fatal(err)
	}
	if _, errs, code := trajrl(t, "", "known-hosts", "--share", "web"); code != 1 || !strings.Contains(errs, "run trajrl verify web first") {
		t.Fatalf("known-hosts --share of a pin of another ID: %d %q", code, errs)
	}
	pin.ID = idB
	if err := sbxapi.RecordPin(sbxapi.DefaultPinFile(), pin); err != nil {
		t.Fatal(err)
	}
	out, errs, code := trajrl(t, "", "share", "ssh", "web", "bob")
	m := regexp.MustCompile(`\n  trajrl known-hosts --import '([^']*)'\n`).FindStringSubmatch(out)
	line := "web-alice,web-alice.sbx.example " + key
	if code != 0 || !strings.HasPrefix(out, "web  running\n  shared with:  bob\n") || m == nil || m[1] != line {
		t.Fatalf("share ssh web bob: %d %q %q", code, out, errs)
	}

	// The colleague, on a machine of their own.
	bob := newHome(t, e)
	standInSSH(t, `for a; do echo "arg $a"; case $a in UserKnownHostsFile=*) f=${a#UserKnownHostsFile=}; f=${f#\"}; cat "${f%\"}";; esac; done
exit 3
`)
	if _, errs, code := trajrl(t, "", "ssh", "web-alice"); code != 255 || !strings.Contains(errs, "run trajrl verify web-alice") {
		t.Fatalf("ssh web-alice before the import: %d %q", code, errs)
	}
	for _, bad := range []string{
		"web,web.sbx.example " + key,                  // not a colleague's name
		"web-alice,*.sbx.example " + key,              // a pattern
		"web-alice,web-alice.other.example " + key,    // another domain
		"web-alice,web-alice.sbx.example,evil " + key, // another name
		"@cert-authority web-alice " + key,
		"web-alice,web-alice.sbx.example ssh-ed25519 AAAAnotakey",
	} {
		if _, errs, code := trajrl(t, "", "known-hosts", "--import", bad); code != 1 {
			t.Errorf("import %q: %d %q", bad, code, errs)
		}
	}
	if _, err := os.Stat(sharedHostsPath()); err == nil {
		t.Fatal("a refused line was recorded")
	}
	// Taken twice, the second a new key: one line each, the new one.
	for _, k := range []string{key2, key} {
		if out, errs, code := trajrl(t, "", "known-hosts", "--import", "web-alice,web-alice.sbx.example "+k); code != 0 || !strings.Contains(out, "trajrl ssh web-alice") {
			t.Fatalf("import: %d %q %q", code, out, errs)
		}
	}
	for _, f := range []string{sharedHostsPath(), filepath.Join(bob.dir, "home", ".ssh", "known_hosts")} {
		b, err := os.ReadFile(f)
		if err != nil || strings.Count(string(b), "web-alice") != 2 || !strings.Contains(string(b), line+"\n") {
			t.Errorf("%s: %q %v", f, b, err)
		}
	}
	out, errs, code = trajrl(t, "", "ssh", "web-alice", "--", "true")
	if code != 3 || !strings.Contains(out, "web-alice.sbx.example "+key+"\n") || !strings.HasSuffix(out, "arg root@web-alice.sbx.example\narg true\n") ||
		!strings.Contains(errs, "shared with you") {
		t.Fatalf("ssh web-alice after the import: %d %q %q", code, out, errs)
	}
}

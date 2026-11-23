package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/keystmt"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// doctor: every check ok on a machine set up in full; an entry point with
// another host key, a policy that does not load and an entry point that
// never answers are failures (exit 1), each with a fix, and the last given
// up on in time.
func TestDoctor(t *testing.T) {
	var signed []byte
	e := newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		switch cmd {
		case "whoami":
			fmt.Fprintln(out, "alice")
		case "ssh-key statement --json":
			json.NewEncoder(out).Encode(map[string]any{"account": "alice", "keys": []string{}, "signed": string(signed)})
		default:
			fmt.Fprintf(errw, "unexpected %q\n", cmd)
			return 2
		}
		return 0
	})
	h := newHome(t, e)
	b, _ := os.ReadFile(h.keyFile)
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	mine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	recovery := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl sbx-recovery-alice"
	if signed, err = keystmt.Sign(&keystmt.Statement{Account: "alice", Seq: 2, Keys: []string{mine}, Recovery: recovery}, signer); err != nil {
		t.Fatal(err)
	}
	testPolicy(t, filepath.Join(policyDir(), "img.json"), "1")
	// A key file by its first line (doctor opens none).
	if err := os.WriteFile(ownerkey.KeyFileIn(h.sbxkey), []byte("TDX-SANDBOX-OWNER-KEY-1\nsealed"), 0o600); err != nil {
		t.Fatal(err)
	}

	// setup's lines in ~/.ssh/config, through trajrl proxy.
	os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".ssh"), 0o700)
	os.WriteFile(filepath.Join(os.Getenv("HOME"), ".ssh", "config"), []byte("# BEGIN trajrl ssh: sbx.example\nHost *.sbx.example\n    ProxyCommand /usr/local/bin/trajrl proxy %h %p\n    User root\n\nHost *\n# END trajrl ssh: sbx.example\n"), 0o600)

	status := func(rep doctorReport) string {
		var s []string
		for _, c := range rep.Checks {
			s = append(s, c.Name+"="+c.Status)
			if c.Status != "ok" && c.Fix == "" {
				t.Errorf("%s is %s with no fix", c.Name, c.Status)
			}
		}
		return strings.Join(s, " ")
	}
	out, errs, code := trajrl(t, "", "doctor", "--json")
	var rep doctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("doctor --json: %v %q %q", err, out, errs)
	}
	if want := "config=ok ssh-key=ok entry=ok ssh-config=ok owner-key=ok recovery-key=ok policies=ok version=ok"; code != 0 || !rep.OK || status(rep) != want {
		t.Fatalf("doctor: %d %s\nwant %s\n%s", code, status(rep), want, out)
	}

	// Another host key at the entry point, and a policy that does not load.
	os.WriteFile(filepath.Join(policyDir(), "bad.json"), []byte(`{"mrtd": "x"}`), 0o600)
	moved := *h.cfg
	moved.EntryKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	if err := moved.save(); err != nil {
		t.Fatal(err)
	}
	out, _, code = trajrl(t, "", "doctor")
	for _, l := range []string{"fail  entry         " + e.addr + " answered with another host key than the one pinned",
		"warn  recovery-key  not checked: the entry point was not reached", "fail  policies      not usable in ", "fix: "} {
		if !strings.Contains(out, l) {
			t.Errorf("doctor: no %q in\n%s", l, out)
		}
	}
	if code != 1 {
		t.Fatalf("doctor with failures: exit %d", code)
	}

	// An entry point that takes the connection and never answers: given up
	// on after doctorTimeout.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	silent := *h.cfg
	silent.Entry = l.Addr().String()
	if err := silent.save(); err != nil {
		t.Fatal(err)
	}
	defer func(d time.Duration) { doctorTimeout = d }(doctorTimeout)
	doctorTimeout = 300 * time.Millisecond
	start := time.Now()
	rep = doctor()
	if took := time.Since(start); took > 5*time.Second || rep.OK || !strings.Contains(status(rep), "entry=fail") ||
		!strings.Contains(rep.Checks[2].Message, "did not answer within 300ms") {
		t.Fatalf("doctor with a silent entry point: %s in %s, %q", status(rep), took, rep.Checks[2].Message)
	}
}

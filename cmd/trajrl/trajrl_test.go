package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
)

// echo is an entry point that answers a few commands, for forwarding.
func echo(cmd string, stdin io.Reader, out, errw io.Writer) int {
	switch {
	case strings.HasPrefix(cmd, "say "):
		fmt.Fprintln(out, strings.TrimPrefix(cmd, "say "))
	case cmd == "warn":
		fmt.Fprintln(errw, "a warning")
	case cmd == "cat":
		io.Copy(out, stdin)
	case cmd == "exit 1":
		fmt.Fprintln(errw, "failed")
		return 1
	case cmd == "exit 2":
		return 2
	case cmd == "help" || cmd == "new web --size small":
		fmt.Fprintln(out, "the entry point's "+cmd)
	default:
		fmt.Fprintf(errw, "unknown command: %s\n", cmd)
		return 2
	}
	return 0
}

// The command table is the commands trajrl runs here, and nothing else;
// the seven names it shares with the entry point are its own, and "entry"
// reaches the entry point's.
func TestCommandTable(t *testing.T) {
	var names []string
	for _, c := range Commands {
		if slices.Contains(names, c.Name) {
			t.Errorf("%s twice in the table", c.Name)
		}
		names = append(names, c.Name)
		if handlers[c.Name] == nil {
			t.Errorf("%s is in the table and runs nothing", c.Name)
		}
		if c.Help == "" {
			t.Errorf("%s says nothing of itself", c.Name)
		}
	}
	for name := range handlers {
		if !slices.Contains(names, name) {
			t.Errorf("%s runs here and is not in the table", name)
		}
	}
	for _, shared := range []string{"new", "start", "unlock", "rename", "known-hosts", "verify", "help"} {
		if !slices.Contains(names, shared) {
			t.Errorf("%s, a command of the entry point's too, is not trajrl's own", shared)
		}
	}

	e := newFakeEntry(t, echo)
	newHome(t, e)
	out, _, code := trajrl(t, "", "help")
	if code != 0 || !strings.Contains(out, "trajrl verify NAME") || !strings.Contains(out, "trajrl entry ARGS") {
		t.Fatalf("help: %d\n%s", code, out)
	}
	if execs, conns := e.seen(); conns != 0 {
		t.Fatalf("help reached the entry point: %q", execs)
	}
	for _, c := range [][]string{{"entry", "help"}, {"entry", "new", "web", "--size", "small"}} {
		out, errs, code := trajrl(t, "", c...)
		if want := "the entry point's " + strings.Join(c[1:], " ") + "\n"; code != 0 || out != want {
			t.Errorf("%q: %d %q %q, want %q", c, code, out, errs, want)
		}
	}
	if out, _, code := trajrl(t, "", "version"); code != 0 || out != "trajrl "+version+"\n" {
		t.Errorf("version: %d %q", code, out)
	}
}

// Every other command goes to the entry point as it is: the words joined
// by one space, stdin given, stdout and stderr as they come, the exit
// status the command's; 255 when there is none.
func TestForward(t *testing.T) {
	e := newFakeEntry(t, echo)
	h := newHome(t, e)
	for _, c := range []struct {
		args             []string
		stdin, out, errs string
		code             int
	}{
		{[]string{"say", "a", "b"}, "", "a b\n", "", 0},
		{[]string{"warn"}, "", "", "a warning\n", 0},
		{[]string{"cat"}, "line one\nline two\n", "line one\nline two\n", "", 0},
		{[]string{"exit", "1"}, "", "", "failed\n", 1},
		{[]string{"exit", "2"}, "", "", "", 2},
	} {
		var out, errb bytes.Buffer
		if code := forward(h.cfg, c.args, strings.NewReader(c.stdin), &out, &errb); code != c.code || out.String() != c.out || errb.String() != c.errs {
			t.Errorf("%q: %d %q %q, want %d %q %q", c.args, code, out.String(), errb.String(), c.code, c.out, c.errs)
		}
	}
	// As a program: any word not in the table.
	if out, errs, code := trajrl(t, "x\n", "cat"); code != 0 || out != "x\n" || errs != "" {
		t.Errorf("trajrl cat: %d %q %q", code, out, errs)
	}
	if _, errs, code := trajrl(t, "", "exit", "2"); code != 2 || errs != "" {
		t.Errorf("trajrl exit 2: %d %q", code, errs)
	}
	// No entry point there: 255.
	gone := *h.cfg
	gone.Entry = "127.0.0.1:1"
	var errb bytes.Buffer
	if code := forward(&gone, []string{"ls"}, nil, io.Discard, &errb); code != 255 || !strings.Contains(errb.String(), "the entry point") {
		t.Errorf("an entry point not there: %d %q", code, errb.String())
	}
	// Not set up: 255, and how to set up.
	os.Remove(configPath())
	if _, errs, code := trajrl(t, "", "ls"); code != 255 || !strings.Contains(errs, "trajrl setup -entry HOST:PORT") {
		t.Errorf("not set up: %d %q", code, errs)
	}
}

// The configuration's values are given to the flags a command has and was
// not given, after parsing: keys sync, rename and init get no -entry, and
// start and unlock take their flags after NAME.
func TestDefaultsPerCommand(t *testing.T) {
	e := newFakeEntry(t, echo)
	h := newHome(t, e)
	pass := filepath.Join(h.dir, "pass")
	os.WriteFile(pass, []byte("a passphrase of length\n"), 0o600)

	// Without a policy: how to add one.
	_, errs, code := trajrl(t, "", "unlock", "web", "-passphrase-file", pass)
	if code != 1 || !strings.Contains(errs, "trajrl: no launch policy") || !strings.Contains(errs, "trajrl policy add FILE") {
		t.Fatalf("unlock without a policy: %d %q", code, errs)
	}
	// With one in the policy directory, and the entry point and the key
	// from the configuration, unlock gets as far as the key file; the
	// flag after NAME was taken.
	testPolicy(t, filepath.Join(policyDir(), "img.json"), "1")
	for _, cmd := range []string{"unlock", "start"} {
		_, errs, code = trajrl(t, "", cmd, "web", "-passphrase-file", pass)
		if code != 1 || !strings.Contains(errs, filepath.Join(h.sbxkey, "owner.key")) || strings.Contains(errs, "-entry") {
			t.Fatalf("%s web -passphrase-file: %d %q", cmd, code, errs)
		}
	}
	// A -policy after NAME is the one used.
	if _, errs, code = trajrl(t, "", "unlock", "web", "-policy", "/nonexistent/p.json"); code != 1 || !strings.Contains(errs, "/nonexistent/p.json") {
		t.Fatalf("unlock web -policy: %d %q", code, errs)
	}
	// The old sbxkey still takes its flags before NAME only.
	if _, errs, code = trajrl(t, "", "sbxkey", "unlock", "web", "-policy", "x"); code != 2 || !strings.Contains(errs, "usage:\n  sbxkey init") {
		t.Fatalf("sbxkey unlock web -policy x: %d %q", code, errs)
	}
	if execs, conns := e.seen(); conns != 0 {
		t.Fatalf("the entry point was reached before the key file: %q", execs)
	}

	// keys sync gets no -entry: the entry point is not asked.
	if _, errs, code = trajrl(t, "", "keys", "sync", "web"); code != 1 || !strings.Contains(errs, "there is no signed statement of your keys to send (trajrl keys add makes one)") {
		t.Fatalf("keys sync: %d %q", code, errs)
	}
	// key init gets none either (it would not parse).
	if _, errs, code = trajrl(t, "", "key", "init"); code != 1 || !strings.Contains(errs, "run it on a terminal") {
		t.Fatalf("key init: %d %q", code, errs)
	}
	if execs, conns := e.seen(); conns != 0 {
		t.Fatalf("keys sync or key init reached the entry point: %q", execs)
	}
	// keys list does: with the configuration's entry point and key.
	trajrl(t, "", "keys", "list")
	if execs, conns := e.seen(); conns != 1 || len(execs) == 0 {
		t.Fatalf("keys list: %d logins, %q", conns, execs)
	}
}

const (
	idA = "sbx-00000000000000a1"
	idB = "sbx-00000000000000b2"
)

// putRecord puts a sandbox on the owner's record.
func putRecord(t *testing.T, r ownerkey.Record) {
	t.Helper()
	st, err := ownerState()
	if err != nil {
		t.Fatal(err)
	}
	r.Provisioned, r.Epoch = true, 1
	if err := st.Put(r, r.SSHHostKey != ""); err != nil {
		t.Fatal(err)
	}
}

// rename OLD NEW: renamed at the platform already (its NEW is the record's
// OLD), only the record follows; otherwise the platform renames it first.
func TestRename(t *testing.T) {
	for _, already := range []bool{true, false} {
		e := newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
			switch {
			case cmd == "show b --json" && already:
				json.NewEncoder(out).Encode(map[string]string{"name": "b", "id": idA})
			case cmd == "show b --json":
				fmt.Fprintln(errw, "show: no sandbox b")
				return 1
			case cmd == "rename a b" && !already:
				fmt.Fprintln(out, "a is b now")
			default:
				fmt.Fprintf(errw, "unexpected: %s\n", cmd)
				return 2
			}
			return 0
		})
		newHome(t, e)
		putRecord(t, ownerkey.Record{ID: idA, Name: "a"})
		out, errs, code := trajrl(t, "", "rename", "a", "b")
		if code != 0 || !strings.Contains(out, "a ("+idA+") is b in your record now") {
			t.Fatalf("already %v: %d %q %q", already, code, out, errs)
		}
		execs, _ := e.seen()
		if renamed := slices.Contains(execs, "rename a b"); renamed == already {
			t.Errorf("already %v: the entry point was asked %q", already, execs)
		}
		if st, _ := ownerState(); st.ByName("b") == nil || st.ByName("a") != nil {
			t.Errorf("already %v: the record is not b's", already)
		}
	}
}

// The old programs as they are: what they printed before their code moved.
func TestLegacyAliases(t *testing.T) {
	cases := map[string][]string{
		"keycmd/testdata/legacy/sbxkey":            {"sbxkey"},
		"keycmd/testdata/legacy/sbxkey-h":          {"sbxkey", "-h"},
		"keycmd/testdata/legacy/sbxkey-start":      {"sbxkey", "start"},
		"keycmd/testdata/legacy/sbxkey-keys":       {"sbxkey", "keys"},
		"keycmd/testdata/legacy/sbxkey-unlock-web": {"sbxkey", "unlock", "web"},
		"verifycmd/testdata/legacy/sbxverify-h":    {"sbxverify", "-h"},
		"verifycmd/testdata/legacy/sbxverify":      {"sbxverify"},
		"verifycmd/testdata/legacy/sbxverify-x":    {"sbxverify", "-x"},
		"apicmd/testdata/legacy/sbxapi":            {"sbxapi"},
		"apicmd/testdata/legacy/sbxapi-exec-h":     {"sbxapi", "exec", "-h"},
		"apicmd/testdata/legacy/sbxapi-cp-h":       {"sbxapi", "cp", "-h"},
	}
	env := []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=", "SBXKEY_DIR="}
	for file, args := range cases {
		read := func(ext string) string {
			b, err := os.ReadFile(filepath.Join("..", "..", "internal", "cli", file+"."+ext))
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
		out, errs, code := runAs(t, env, "", args...)
		if fmt.Sprint(code) != strings.TrimSpace(read("code")) || out != read("stdout") || errs != read("stderr") {
			t.Errorf("trajrl %q: %d\n%s\n%s\nrecorded %s\n%s\n%s", args, code, out, errs, read("code"), read("stdout"), read("stderr"))
		}
	}
}

// exec and cp pin the sandbox's host key from sbxverify's record, or from
// the owner's record of the TD it unlocked with the host name the
// platform's "show" names, never from what the platform says the key is.
func TestExecKeySource(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	show := map[string]string{
		"show web --json":   `{"name":"web","id":"` + idA + `","https_url":"https://web-alice.sbx.example","host_key":"ssh-ed25519 AAAAplatform"}`,
		"show nokey --json": `{"name":"nokey","id":"` + idB + `","https_url":"https://nokey-alice.sbx.example"}`,
		"show nopol --json": `{"name":"nopol","id":"` + idB + `","https_url":"https://nopol-alice.sbx.example"}`,
		"show other --json": `{"name":"other","id":"` + idB + `","https_url":"https://other-alice.sbx.example"}`,
		"show nourl --json": `{"name":"nourl","id":"sbx-00000000000000e5"}`,
	}
	e := newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		if s, ok := show[cmd]; ok {
			fmt.Fprintln(out, s)
			return 0
		}
		fmt.Fprintf(errw, "unexpected: %s\n", cmd)
		return 2
	})
	h := newHome(t, e)
	putRecord(t, ownerkey.Record{ID: idA, Name: "web", SSHHostKey: key, Policy: "img"})
	putRecord(t, ownerkey.Record{ID: idB, Name: "nokey", Policy: "img"})
	putRecord(t, ownerkey.Record{ID: "sbx-00000000000000c3", Name: "nopol", SSHHostKey: key})
	putRecord(t, ownerkey.Record{ID: "sbx-00000000000000d4", Name: "other", SSHHostKey: key, Policy: "img"})
	putRecord(t, ownerkey.Record{ID: "sbx-00000000000000e5", Name: "nourl", SSHHostKey: key, Policy: "img"})
	fb := apiFallback(h.cfg)
	if pin, host, err := fb("web"); err != nil || pin != key || host != "web-alice.sbx.example" {
		t.Fatalf("the owner's record: %q %q %v", pin, host, err)
	}
	for name, want := range map[string]string{
		"nokey": "has no host key", "nopol": "without a quote", "other": "your record's is sbx-00000000000000d4",
		"nourl": "names no https_url", "nothere": "no record of nothere", "web.sbx.example": "no record of web.sbx.example",
	} {
		if pin, _, err := fb(name); err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "run trajrl verify") {
			t.Errorf("%s: %q %v, want a refusal with %q", name, pin, err, want)
		}
	}
	// sbxverify's record comes first: the owner's record and the platform
	// are not asked (the call fails after the pin and the name were
	// settled, at your SSH key: none here, exit status 1).
	n := len(func() []string { s, _ := e.seen(); return s }())
	if err := sbxapi.RecordPin(sbxapi.DefaultPinFile(), sbxapi.Pin{Name: "rec", ID: idB, HostKey: key, HTTPSURL: "https://rec-alice.sbx.example", Verified: time.Now()}); err != nil {
		t.Fatal(err)
	}
	_, errs, code := trajrl(t, "", "exec", "-connect", "127.0.0.1:1", "rec", "--", "true")
	if code != 1 || strings.Contains(errs, "verify") || !strings.Contains(errs, "trajrl: no SSH key") {
		t.Fatalf("exec with sbxverify's record: %d %q", code, errs)
	}
	_, errs, code = trajrl(t, "", "exec", "nopol", "--", "true")
	if code != 1 || !strings.Contains(errs, "trajrl: your record of nopol was made without a quote") {
		t.Fatalf("exec of a record without a policy: %d %q", code, errs)
	}
	if execs, _ := e.seen(); len(execs) != n {
		t.Errorf("the platform was asked %q", execs[n:])
	}
}

// ssh NAME runs the system's ssh with the verified host key alone and the
// key setup saved (-i), through this trajrl (ProxyCommand trajrl proxy,
// whatever ssh's files say); without a verified host key it refuses.
func TestSSH(t *testing.T) {
	bin := t.TempDir()
	// A stand-in ssh: prints its arguments and the known-hosts file it was
	// given, and exits 3.
	script := "#!/bin/sh\nfor a; do echo \"arg $a\"; case $a in UserKnownHostsFile=*) f=${a#UserKnownHostsFile=}; f=${f#\\\"}; cat \"${f%\\\"}\";; esac; done\nexit 3\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh for the stand-in ssh")
	}
	h := newHome(t, newFakeEntry(t, echo))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	if _, errs, code := trajrl(t, "", "ssh", "web"); code != 255 || !strings.Contains(errs, "run trajrl verify web") {
		t.Fatalf("ssh without a verified key: %d %q", code, errs)
	}
	putRecord(t, ownerkey.Record{ID: idA, Name: "rehearsed", SSHHostKey: key})
	if _, errs, code := trajrl(t, "", "ssh", "rehearsed"); code != 255 || !strings.Contains(errs, "run trajrl verify rehearsed") {
		t.Fatalf("ssh with a record without a policy: %d %q", code, errs)
	}
	putRecord(t, ownerkey.Record{ID: idB, Name: "web", SSHHostKey: key, Policy: "img"})
	out, errs, code := trajrl(t, "", "ssh", "web", "--", "uname", "-a")
	self, _ := os.Executable()
	want := "arg StrictHostKeyChecking=yes\narg -o\narg ProxyCommand=" + self + " proxy %h %p\narg root@web.sbx.example\narg uname\narg -a\n"
	if code != 3 || !strings.Contains(out, "web.sbx.example "+key+"\n") || !strings.HasSuffix(out, want) {
		t.Fatalf("ssh web -- uname -a: %d %q %q", code, out, errs)
	}	// The key setup saved goes to ssh, which would otherwise offer only its
	// own default files.
	if !strings.HasPrefix(out, "arg -i\narg "+h.keyFile+"\n") {
		t.Fatalf("ssh web: the saved key was not passed first: %q", out)
	}
}

func TestPolicy(t *testing.T) {
	h := newHome(t, nil)
	p := testPolicy(t, filepath.Join(h.dir, "img.json"), "1")
	if _, errs, code := trajrl(t, "", "policy", "add", p); code != 0 {
		t.Fatalf("policy add: %d %q", code, errs)
	}
	if out, _, code := trajrl(t, "", "policy", "add", p); code != 0 || !strings.Contains(out, "already") {
		t.Fatalf("policy add again: %d %q", code, out)
	}
	testPolicy(t, p, "4")
	if _, errs, code := trajrl(t, "", "policy", "add", p); code != 1 || !strings.Contains(errs, "another img") {
		t.Fatalf("policy add of another img: %d %q", code, errs)
	}
	bad := filepath.Join(h.dir, "bad.json")
	os.WriteFile(bad, []byte(`{"mrtd": "x", "allow_tdx_module_tcb": true}`), 0o600)
	if _, _, code := trajrl(t, "", "policy", "add", bad); code != 1 {
		t.Fatalf("policy add of a file that is no policy: %d", code)
	}
	if out, _, code := trajrl(t, "", "policy", "list"); code != 0 || !strings.HasPrefix(out, "img ") || strings.Count(out, "\n") != 1 {
		t.Fatalf("policy list: %d %q", code, out)
	}
	if _, _, code := trajrl(t, "", "policy", "rm", "img"); code != 0 {
		t.Fatalf("policy rm: %d", code)
	}
	if files, _ := policies(); len(files) != 0 {
		t.Fatalf("after rm: %q", files)
	}
	if _, errs, code := trajrl(t, "", "verify", "--all", "-owner"); code != 3 || !strings.Contains(errs, "-passphrase-file") {
		t.Fatalf("verify --all -owner: %d %q", code, errs)
	}
}

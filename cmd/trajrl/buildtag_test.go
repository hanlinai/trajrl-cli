package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The code that gives a TD without a quote its disk secret exists only in a
// binary built with the tag "rehearsal", as in cmd/sbxkey. trajrl is built
// here both ways, as a user or the rehearsal would build it:
//
//   - go build ./cmd/trajrl: no command takes -dev-insecure-rehearsal or
//     lists it, and the binary holds none of the strings
//     release/build-owner-tools.sh refuses (the rehearsal's and the TCB
//     exception's); it does hold the skills (skills.go);
//   - go build -tags rehearsal ./cmd/trajrl: it lists the flag and prints the
//     "NOT FOR ANY REAL USE" banner, so the check above proves something.
//
// The same for trajrl ssh's rehearsal fallback (rehearsal.go): only the
// rehearsal build reads rehearsal_known_hosts and says the key is NOT
// attested; the default build still refuses without a verified key.
func TestBuildTagDefaultHasNoRehearsal(t *testing.T) {
	if testing.Short() {
		t.Skip("builds trajrl twice")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	dir := t.TempDir()
	build := func(out string, tags ...string) string {
		path := filepath.Join(dir, out)
		args := append([]string{"build"}, tags...)
		cmd := exec.Command(goBin, append(args, "-o", path, ".")...)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %v: %v\n%s", tags, err, b)
		}
		return path
	}
	runEnv := func(bin string, env []string, args ...string) string {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(append(os.Environ(), "TRAJRL_DIR="+filepath.Join(dir, "trajrl"), "SBXKEY_DIR="+filepath.Join(dir, "sbxkey")), env...)
		b, _ := cmd.CombinedOutput() // exits 2 with the usage
		return string(b)
	}
	run := func(bin string, args ...string) string { return runEnv(bin, nil, args...) }
	normal, rehearsal := build("trajrl"), build("trajrl-rehearsal", "-tags", "rehearsal")

	for _, c := range [][]string{{"sbxkey", "-h"}, {"verify", "-h"}, {"unlock", "-h"}} {
		if h := run(normal, c...); strings.Contains(h, "rehearsal") {
			t.Fatalf("default build, trajrl %s:\n%s", strings.Join(c, " "), h)
		}
	}
	for _, c := range [][]string{{"unlock", "-dev-insecure-rehearsal", "web"}, {"verify", "-dev-insecure-rehearsal", "web"}} {
		if out := run(normal, c...); !strings.Contains(out, "flag provided but not defined: -dev-insecure-rehearsal") {
			t.Fatalf("default build took -dev-insecure-rehearsal (trajrl %s):\n%s", strings.Join(c, " "), out)
		}
	}
	b, err := os.ReadFile(normal)
	if err != nil {
		t.Fatal(err)
	}
	normalBin := b
	for _, s := range releaseForbidden {
		if bytes.Contains(b, []byte(s)) {
			t.Errorf("the default build contains %q", s)
		}
	}
	all, err := skills()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		if !bytes.Contains(b, s.Body) {
			t.Errorf("the default build does not carry the skill %s", s.Name)
		}
	}

	if h := run(rehearsal, "sbxkey", "-h"); !strings.Contains(h, "-dev-insecure-rehearsal") || !strings.Contains(h, "NOT FOR ANY REAL USE") {
		t.Fatalf("rehearsal build, trajrl sbxkey -h:\n%s", h)
	}
	b, err = os.ReadFile(rehearsal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("ownerkey.AllowUnattestedRehearsal")) {
		t.Fatal("the rehearsal build has no AllowUnattestedRehearsal: the check of the default build proves nothing")
	}
	if out := run(rehearsal, "unlock", "-dev-insecure-rehearsal", "web"); !strings.Contains(out, "DISK SECRETS ARE SENT WITHOUT ATTESTATION. NOT FOR ANY REAL USE") {
		t.Fatalf("rehearsal build, trajrl unlock -dev-insecure-rehearsal:\n%s", out)
	}

	// trajrl ssh on the emulated stage: only a rehearsal build takes the
	// host key a rehearsal verify saw (rehearsal_known_hosts), and says it
	// is not attested; the default build has neither the file nor the
	// words, and still asks for a verified key.
	for _, s := range rehearsalOnly {
		if bytes.Contains(normalBin, []byte(s)) {
			t.Errorf("the default build contains %q", s)
		}
		if !bytes.Contains(b, []byte(s)) {
			t.Errorf("the rehearsal build does not contain %q: the check of the default build proves nothing", s)
		}
	}
	xdg := filepath.Join(dir, "xdg")
	os.MkdirAll(filepath.Join(xdg, "sbx"), 0o700)
	tdir := filepath.Join(dir, "trajrl-dir")
	os.MkdirAll(tdir, 0o700)
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	os.WriteFile(filepath.Join(xdg, "sbx", "rehearsal_known_hosts"), []byte("web "+key+" REHEARSAL-NOT-ATTESTED sbx-0123456789abcdef\n"), 0o600)
	os.WriteFile(filepath.Join(tdir, "config.json"), []byte(`{"entry": "127.0.0.1:1", "entry_key": "`+key+`", "domain": "sbx.example"}`), 0o600)
	noSSH := []string{"TRAJRL_DIR=" + tdir, "XDG_CONFIG_HOME=" + xdg, "PATH=" + t.TempDir()} // no ssh to run
	if out := runEnv(normal, noSSH, "ssh", "web"); !strings.Contains(out, "run trajrl verify web first") || strings.Contains(out, "REHEARSAL") {
		t.Fatalf("default build, trajrl ssh web with a rehearsal's known-hosts file:\n%s", out)
	}
	if out := runEnv(rehearsal, noSSH, "ssh", "web"); !strings.Contains(out, "*** REHEARSAL, host key NOT attested: web's key is the one from "+filepath.Join(xdg, "sbx", "rehearsal_known_hosts")) ||
		!strings.Contains(out, `"ssh": executable file not found`) {
		t.Fatalf("rehearsal build, trajrl ssh web:\n%s", out)
	}
	if out := runEnv(rehearsal, noSSH, "ssh", "db"); !strings.Contains(out, "run trajrl verify db first") || strings.Contains(out, "REHEARSAL") {
		t.Fatalf("rehearsal build, trajrl ssh db (on no record):\n%s", out)
	}
	// The screen's rehearsal flag: the rehearsal build takes it (no
	// terminal here, so the screen refuses), the default build has no
	// such flag and gives it to the entry point as a command.
	if out := run(rehearsal, "-dev-insecure-rehearsal"); !strings.Contains(out, "the screen's unlock, start, new and verify run with -dev-insecure-rehearsal") {
		t.Fatalf("rehearsal build, trajrl -dev-insecure-rehearsal:\n%s", out)
	}
}

// What only a rehearsal build of trajrl holds: the rehearsal's known-hosts
// file and the words trajrl ssh says when it uses it.
var rehearsalOnly = []string{"rehearsal_known_hosts", "REHEARSAL, host key NOT attested", "REHEARSAL-NOT-ATTESTED"}

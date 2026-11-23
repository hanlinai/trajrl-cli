package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/sshsetup"
)

// needPrograms skips a test if a program the installer runs is missing.
func needPrograms(t *testing.T, programs ...string) {
	t.Helper()
	for _, p := range programs {
		if _, err := exec.LookPath(p); err != nil {
			t.Skipf("%s is not installed: the installer cannot run here", p)
		}
	}
}

// sshConfigOf is what internal/control's sshConfig writes for an entry
// point in owner-key mode.
func sshConfigOf() string {
	return "# For ~/.ssh/config. With these lines, \"ssh root@NAME.sbx.example\" reaches your\n" +
		"# sandbox NAME through this entry point, which carries the session unopened.\n" +
		"Host *.sbx.example\n    ProxyCommand trajrl proxy %h %p\n    User root\n" +
		"    UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/sbx_known_hosts\n    ServerAliveInterval 30\n    ServerAliveCountMax 4\n    StrictHostKeyChecking yes\n"
}

// legacyLines are an older entry point's ssh_config lines, through it
// with ProxyJump, and legacyInstall what an older setup made of them in an
// SSH directory: its block at the top of config, the entry point's key
// pinned in known_hosts.
const legacyLines = "# For ~/.ssh/config.\nHost entry.example\n    Port 2222\nHost *.sbx.example\n    ProxyJump entry.example\n    User root\n" +
	"    UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/sbx_known_hosts\n    ServerAliveInterval 30\n    ServerAliveCountMax 4\n    StrictHostKeyChecking yes\n"

func legacyInstall(config, knownHosts, key string) [2]string {
	return [2]string{"# BEGIN sandbox SSH entry: entry.example\n" + legacyLines + "\nHost *\n# END sandbox SSH entry: entry.example\n" + config,
		knownHosts + "\n[entry.example]:2222 " + key + "\n"}
}

// installedLines are sshConfigOf's lines as setup installs them: this
// trajrl in ProxyCommand.
func installedLines(t *testing.T) string {
	t.Helper()
	return strings.Replace(sshConfigOf(), "ProxyCommand trajrl ", "ProxyCommand "+selfPath()+" ", 1)
}

// blockIn is installedLines as the installer puts them in the SSH
// directory dir, not ~/.ssh: its known-hosts files named, in setup's block.
func blockIn(t *testing.T, dir string) string {
	t.Helper()
	lines := strings.Replace(installedLines(t), sshsetup.UserKnownHostsLine, `    UserKnownHostsFile "`+dir+`/known_hosts" "`+dir+`/sbx_known_hosts"`, 1)
	return "# BEGIN trajrl ssh: sbx.example\n" + lines + "\nHost *\n# END trajrl ssh: sbx.example\n"
}

// setupEntry answers setup's questions: whoami (registered or not),
// domain and ssh-config.
func setupEntry(t *testing.T, registered *bool, domain string, sshConfig *string) *fakeEntry {
	return newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		switch cmd {
		case "whoami":
			if !*registered {
				fmt.Fprintln(errw, "this key has no account: register first")
				return 1
			}
			fmt.Fprintln(out, "alice")
		case "domain --json":
			json.NewEncoder(out).Encode(map[string]string{"domain": domain})
		case "ssh-config --json":
			json.NewEncoder(out).Encode(map[string]string{"ssh_config": *sshConfig})
		default:
			fmt.Fprintf(errw, "unexpected: %s\n", cmd)
			return 2
		}
		return 0
	})
}

// files is the SSH directory's config and known_hosts as they are ("" for
// none).
func files(t *testing.T, dir string) [2]string {
	t.Helper()
	var f [2]string
	for i, name := range []string{"config", "known_hosts"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			f[i] = string(b)
		}
	}
	return f
}

func TestSetup(t *testing.T) {
	needPrograms(t, "sh", "ssh", "ssh-keygen", "awk")
	registered, text := false, sshConfigOf()
	e := setupEntry(t, &registered, "sbx.example", &text)
	h := newHome(t, nil)
	sshDir := filepath.Join(h.dir, "ssh")
	os.MkdirAll(sshDir, 0o700)
	mine := "Host mine\n    User me\n"
	known := "mine " + e.key + "\n"
	os.WriteFile(filepath.Join(sshDir, "config"), []byte(mine), 0o600)
	os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(known), 0o600)
	before := files(t, sshDir)
	setup := func(extra ...string) int {
		return run(append([]string{"setup", "-entry", e.addr, "-entry-key", e.key + " a comment", "-i", h.keyFile, "-ssh-dir", sshDir}, extra...))
	}

	// A key the entry point does not know yet: the configuration is saved,
	// and setup says to register first.
	if code := setup(); code != 1 {
		t.Fatalf("setup before registering: %d", code)
	}
	if c, err := loadConfig(); err != nil || c.Entry != e.addr || c.EntryKey != e.key || c.Identity != h.keyFile {
		t.Fatalf("the configuration after setup before registering: %+v %v", c, err)
	}
	if files(t, sshDir) != before {
		t.Fatal("setup before registering changed the SSH directory")
	}
	registered = true

	// Lines the entry point should not give: refused, nothing written.
	good := text
	for name, bad := range map[string]string{
		"Host *":                       strings.Replace(good, "Host *.sbx.example", "Host *", 1),
		"ProxyCommand":                 strings.Replace(good, "trajrl proxy %h %p", "sh -c 'id > /tmp/x'", 1),
		"ProxyCommand another program": strings.Replace(good, "trajrl proxy", "/usr/bin/nc proxy", 1),
		"ProxyJump":                    legacyLines,
		"StrictHostKeyChecking no":     strings.Replace(good, "StrictHostKeyChecking yes", "StrictHostKeyChecking no", 1),
		"UserKnownHostsFile /dev/null": strings.Replace(good, "~/.ssh/known_hosts ~/.ssh/sbx_known_hosts", "/dev/null", 1),
		"another domain":               strings.Replace(good, "Host *.sbx.example", "Host *.evil.example", 1),
		"Include":                      "Include /tmp/x\n" + good,
	} {
		text = bad
		if code := setup(); code != 1 {
			t.Errorf("%s: setup %d", name, code)
		}
		if files(t, sshDir) != before {
			t.Fatalf("%s: setup changed the SSH directory", name)
		}
	}

	// The lines it gives: installed with this trajrl in ProxyCommand, and
	// nothing of the entry point in known_hosts; twice is once.
	text = good
	if code := setup(); code != 0 {
		t.Fatalf("setup: %d", code)
	}
	once := files(t, sshDir)
	want := blockIn(t, sshDir) + mine
	if once[0] != want || once[1] != known {
		t.Fatalf("after setup:\n%s\n%s\nwant:\n%s", once[0], once[1], want)
	}
	if code := setup(); code != 0 || files(t, sshDir) != once {
		t.Fatalf("setup twice: %d\n%v", code, files(t, sshDir))
	}
	if c, _ := loadConfig(); c.Domain != "sbx.example" || c.EntryName != "" || c.SSHConfig != installedLines(t) {
		t.Fatalf("the configuration after setup: %+v", c)
	}

	// --remove: with no entry point, the files are as they were before.
	if code := run([]string{"setup", "--remove"}); code != 0 {
		t.Fatalf("setup --remove: %d", code)
	}
	if files(t, sshDir) != before {
		t.Fatalf("after setup --remove:\n%v\nbefore:\n%v", files(t, sshDir), before)
	}
	if execs, _ := e.seen(); execs[len(execs)-1] != "ssh-config --json" {
		t.Fatalf("setup --remove asked the entry point: %q", execs)
	}
}

// The upgrade (#123): a machine an older setup installed, its lines
// through the entry point with ProxyJump and the entry point's key pinned
// in known_hosts. doctor warns, with the fix "trajrl setup"; setup, run
// again, replaces the block and takes the pin out, leaving the user's own
// lines and keys as they were; doctor is then content.
func TestSetupReplacesTheOlderLines(t *testing.T) {
	needPrograms(t, "sh", "ssh", "ssh-keygen", "awk")
	registered, text := true, sshConfigOf()
	e := setupEntry(t, &registered, "sbx.example", &text)
	h := newHome(t, nil)
	sshDir := filepath.Join(h.dir, "ssh")
	os.MkdirAll(sshDir, 0o700)
	mine, known := "Host mine\n    User me\n", "mine "+e.key+"\n"
	old := legacyInstall(mine, known, e.key)
	os.WriteFile(filepath.Join(sshDir, "config"), []byte(old[0]), 0o600)
	os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte(old[1]), 0o600)
	cfg := &config{Entry: e.addr, EntryKey: e.key, Identity: h.keyFile, Domain: "sbx.example",
		EntryName: "[entry.example]:2222", SSHConfig: legacyLines, SSHDir: sshDir}
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}

	doctorSays := func() check {
		t.Helper()
		out, _, _ := trajrl(t, "", "doctor", "--json")
		var rep doctorReport
		json.Unmarshal([]byte(out), &rep)
		for _, c := range rep.Checks {
			if c.Name == "ssh-config" {
				return c
			}
		}
		t.Fatalf("doctor has no ssh-config check:\n%s", out)
		return check{}
	}
	if c := doctorSays(); c.Status != "warn" || !strings.Contains(c.Message, "ProxyJump") || !strings.HasPrefix(c.Fix, "trajrl setup") {
		t.Errorf("doctor with the older lines: %+v", c)
	}
	out, _, _ := trajrl(t, "", "doctor")
	if !strings.Contains(out, "fix: trajrl setup (run it again") {
		t.Errorf("doctor's text:\n%s", out)
	}

	if code := run([]string{"setup"}); code != 0 {
		t.Fatalf("setup again: %d", code)
	}
	got := files(t, sshDir)
	if want := blockIn(t, sshDir) + mine; got[0] != want || got[1] != known {
		t.Fatalf("after setup again:\n%s\n%s", got[0], got[1])
	}
	if c, _ := loadConfig(); c.EntryName != "" || c.SSHConfig != installedLines(t) {
		t.Errorf("the configuration after setup again: %+v", c)
	}
	if c := doctorSays(); c.Status != "ok" || !strings.Contains(c.Message, "trajrl proxy") {
		t.Errorf("doctor after setup again: %+v", c)
	}
	// Removed again, nothing of either is left.
	if code := run([]string{"setup", "--remove"}); code != 0 || files(t, sshDir) != [2]string{mine, known} {
		t.Fatalf("setup --remove: %v", files(t, sshDir))
	}
	if c := doctorSays(); c.Status != "warn" || c.Fix != "trajrl setup" {
		t.Errorf("doctor after setup --remove: %+v", c)
	}
}

// captureStderr runs f with os.Stderr going to a file, and returns what
// was written there.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = tmp
	defer func() { os.Stderr = saved }()
	f()
	b, _ := os.ReadFile(tmp.Name())
	return string(b)
}

// A key with no account: the entry point holds whoami, waiting for the key
// to be linked on the website. setup gives up after whoamiWait, says what
// the entry point said and how to register, and exits 1.
func TestSetupUnknownKeyNoAnswer(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	e := newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		if cmd != "whoami" {
			fmt.Fprintf(errw, "unexpected: %s\n", cmd)
			return 2
		}
		fmt.Fprint(errw, "this key does not identify an account yet:\r\n\r\n  https://example.test/link/abc\r\n")
		<-stop // never answers
		return 1
	})
	h := newHome(t, nil)
	saved := whoamiWait
	whoamiWait = 300 * time.Millisecond
	defer func() { whoamiWait = saved }()
	var code int
	start := time.Now()
	said := captureStderr(t, func() {
		code = run([]string{"setup", "-entry", e.addr, "-entry-key", e.key, "-i", h.keyFile, "-ssh-dir", t.TempDir()})
	})
	if code != 1 || time.Since(start) > 10*time.Second {
		t.Fatalf("setup: exit %d after %s", code, time.Since(start))
	}
	for _, want := range []string{"held whoami for 300ms without an answer: your key has no account there yet",
		"https://example.test/link/abc", "trajrl register NAME --invite CODE", "then run trajrl setup again"} {
		if !strings.Contains(said, want) {
			t.Errorf("setup said no %q:\n%s", want, said)
		}
	}
	if strings.Contains(said, "\r") {
		t.Errorf("a carriage return in:\n%q", said)
	}
}

// Without -i and without an SSH agent, setup uses the key file ssh would
// (here id_ecdsa: id_ed25519 has a passphrase) and saves it; in owner-key
// mode it comments out an older KnownHostsCommand for the domain, with a
// backup. No key at all: exit 1, nothing asked.
func TestSetupDefaultKeyAndOldKnownHostsCommand(t *testing.T) {
	needPrograms(t, "sh", "ssh", "ssh-keygen", "awk")
	registered, text := true, sshConfigOf()
	e := setupEntry(t, &registered, "sbx.example", &text)
	newHome(t, nil)
	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	setup := func() int { return run([]string{"setup", "-entry", e.addr, "-entry-key", e.key}) }

	said := captureStderr(t, func() {
		if code := setup(); code != 1 {
			t.Errorf("setup with no key: %d", code)
		}
	})
	if !strings.Contains(said, "no SSH key: give -i KEYFILE") {
		t.Errorf("setup with no key said:\n%s", said)
	}
	if execs, _ := e.seen(); len(execs) != 0 {
		t.Fatalf("setup with no key asked the entry point %q", execs)
	}

	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	locked, _ := ssh.MarshalPrivateKeyWithPassphrase(ed, "", []byte("secret"))
	os.WriteFile(filepath.Join(sshDir, "id_ed25519"), pem.EncodeToMemory(locked), 0o600)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plain, _ := ssh.MarshalPrivateKey(ec, "")
	os.WriteFile(filepath.Join(sshDir, "id_ecdsa"), pem.EncodeToMemory(plain), 0o600)
	old := "# BEGIN trajrl sbx demo\nHost *.sbx.example\n    ProxyJump sbx.example\n    User root\n" +
		"    KnownHostsCommand /usr/bin/ssh sbx.example known-hosts %H\n# END trajrl sbx demo\n"
	os.WriteFile(filepath.Join(sshDir, "config"), []byte(old), 0o600)

	said = captureStderr(t, func() {
		if code := setup(); code != 0 {
			t.Fatalf("setup: %d", code)
		}
	})
	if !strings.Contains(said, filepath.Join(sshDir, "id_ed25519")+" has a passphrase") {
		t.Errorf("setup did not say it passed over id_ed25519:\n%s", said)
	}
	if c, _ := loadConfig(); c.Identity != filepath.Join(sshDir, "id_ecdsa") {
		t.Fatalf("the configuration's key: %q", c.Identity)
	}
	cfg := files(t, sshDir)[0]
	if !strings.Contains(cfg, "    # (trajrl setup: off, the platform holds no host keys) KnownHostsCommand /usr/bin/ssh sbx.example known-hosts %H\n") ||
		!strings.Contains(cfg, "ProxyCommand "+selfPath()+" proxy %h %p") {
		t.Fatalf("config after setup:\n%s", cfg)
	}
	backups, _ := filepath.Glob(filepath.Join(sshDir, "config.before-trajrl.*"))
	if len(backups) != 1 {
		t.Fatalf("backups: %q", backups)
	}
	if b, _ := os.ReadFile(backups[0]); !strings.Contains(string(b), "\n    KnownHostsCommand ") {
		t.Errorf("the backup has no KnownHostsCommand line:\n%s", b)
	}

	// Again: the saved key, nothing more commented out.
	if code := setup(); code != 0 || files(t, sshDir)[0] != cfg {
		t.Fatalf("setup again: %d\n%s", code, files(t, sshDir)[0])
	}
	if backups, _ := filepath.Glob(filepath.Join(sshDir, "config.before-trajrl.*")); len(backups) != 1 {
		t.Fatalf("backups after setup again: %q", backups)
	}
}

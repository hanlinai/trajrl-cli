package keycmd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

const (
	pinKeyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBk8hWv1Hd2sWzG2Wn4nI3yJ2gW1dO4i8t5T0u0r7aXZ"
	pinKeyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAm1qGosNnFbt8c4OE+oeoxMzvM0Aca+VG/9s4/Mr4QU"
)

// pinWorld is an owner's machine in a temporary directory: a home, where
// nothing is written unless a test names a file in it, and sbxkey's state
// with two sandboxes that have host keys and one that has none.
func pinWorld(t *testing.T) (*opts, *ownerkey.State, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("SBXKEY_DIR", "")
	dir := filepath.Join(home, "state")
	os.Mkdir(dir, 0o700)
	o := &opts{dir: dir, statePath: filepath.Join(dir, "sandboxes.json"), knownHostPath: filepath.Join(dir, "known_hosts")}
	st, err := ownerkey.OpenState(o.statePath, o.knownHostPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []ownerkey.Record{
		{ID: "sbx-00000000000000a1", Name: "web", Provisioned: true, Epoch: 7, SSHHostKey: pinKeyA},
		{ID: "sbx-00000000000000a2", Name: "db", Provisioned: true, Epoch: 1, SSHHostKey: pinKeyB},
		{ID: "sbx-00000000000000a3", Name: "elsewhere", Provisioned: true, Epoch: 2},
	} {
		if err := st.Put(r, true); err != nil {
			t.Fatal(err)
		}
	}
	// As a first boot before this existed left it: the name alone.
	st.PinHostKey([]string{"web"}, pinKeyA)
	return o, st, home
}

func fileOrNone(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(none)"
	}
	return string(b)
}

// mirrorLines is a mirror without its comment lines.
func mirrorLines(path string) string {
	var out []string
	for _, l := range strings.Split(fileOrNone(path), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

const bothMirror = "db " + pinKeyB + "\ndb.sbx.example " + pinKeyB + "\nweb " + pinKeyA + "\nweb.sbx.example " + pinKeyA

// Where the mirror goes: ~/.ssh/sbx_known_hosts for sbxkey's own directory
// and for no other, the file named with -ssh-known-hosts, and none with
// "none". -domain has to be a domain.
func TestSSHPinWhereTheMirrorGoes(t *testing.T) {
	_, _, home := pinWorld(t)
	own := defaultDir()
	if own != filepath.Join(home, ".config", "sbxkey") {
		t.Fatalf("sbxkey's own directory here: %s", own)
	}
	for _, c := range []struct{ dir, flag, want string }{
		{own, "", filepath.Join(home, ".ssh", "sbx_known_hosts")},
		{own + "/", "", filepath.Join(home, ".ssh", "sbx_known_hosts")},
		{filepath.Join(home, "state"), "", ""}, // another state: not its file to write
		{filepath.Join(home, "state"), "/somewhere/else", "/somewhere/else"},
		{own, "none", ""},
		{own, "/somewhere/else", "/somewhere/else"},
	} {
		p := sshPin{mirrorFlag: c.flag}
		if err := p.resolve(c.dir); err != nil || p.mirror != c.want {
			t.Errorf("-dir %s -ssh-known-hosts %q: mirror %q %v, want %q", c.dir, c.flag, p.mirror, err, c.want)
		}
	}
	p := sshPin{domainFlag: "Sbx.Example."}
	if err := p.resolve(own); err != nil || p.domain != "sbx.example" {
		t.Errorf("-domain Sbx.Example.: %q %v", p.domain, err)
	}
	p = sshPin{domainFlag: "sbx example"}
	if err := p.resolve(own); err == nil || !strings.Contains(err.Error(), "is not a domain for sandbox names") {
		t.Errorf("-domain with a space: %v", err)
	}
	if left, _ := os.ReadDir(home); len(left) != 1 {
		t.Errorf("settling the path wrote something: %v", left)
	}
}

// The domain for sandbox names: what the entry point answers to "domain",
// kept in the state for the runs that cannot ask; -domain overrides and is
// not asked about; a platform that does not know the command, names none
// or names something else changes nothing.
func TestDomainFromTheEntryPoint(t *testing.T) {
	o, st, _ := pinWorld(t)
	asked := 0
	answer := func(out string, err error) func() (string, error) {
		return func() (string, error) { asked++; return out, err }
	}
	if d := sandboxDomain(o, st, answer("", errors.New(`domain: unknown command "domain"`))); d != "" || st.Domain() != "" {
		t.Errorf("an entry point without the command: %q, state %q", d, st.Domain())
	}
	if d := sandboxDomain(o, st, answer("\n", nil)); d != "" || st.Domain() != "" {
		t.Errorf("a service without a domain: %q, state %q", d, st.Domain())
	}
	if d := sandboxDomain(o, st, answer("Sbx.Example.\n", nil)); d != "sbx.example" || st.Domain() != "sbx.example" || o.pin.domain != "sbx.example" {
		t.Fatalf("asked: %q, state %q", d, st.Domain())
	}
	// Later runs: no entry point to ask (rename, known-hosts), one that
	// fails, and one that answers nonsense. The recorded domain stands.
	for _, ask := range []func() (string, error){nil, answer("", errors.New("no")), answer("two words\n", nil), answer("a.example\nb.example\n", nil)} {
		o.pin = sshPin{}
		if d := sandboxDomain(o, st, ask); d != "sbx.example" || st.Domain() != "sbx.example" {
			t.Errorf("a later run: %q, state %q", d, st.Domain())
		}
	}
	// -domain: used, recorded, and the entry point is not asked.
	o.pin = sshPin{domainFlag: "other.example"}
	if err := o.pin.resolve(o.dir); err != nil {
		t.Fatal(err)
	}
	before := asked
	if d := sandboxDomain(o, st, answer("sbx.example\n", nil)); d != "other.example" || st.Domain() != "other.example" || asked != before {
		t.Errorf("-domain: %q, state %q, asked %d times", d, st.Domain(), asked-before)
	}
	// The real thing over SSH, against an entry point of before this command.
	entry := fakeEntry(t, "", &events{})
	o.pin = sshPin{}
	if d := sandboxDomain(o, st, func() (string, error) { return ownerkey.RunEntry(entry, []string{"domain"}) }); d != "other.example" {
		t.Errorf("an entry point that answers \"unknown command\": %q", d)
	}
	if got := o.pinHosts("web", "sbx.example"); len(got) != 2 || got[1] != "web.sbx.example" {
		t.Errorf("pinHosts: %v", got)
	}
	o.knownHosts = paths{"mine.example"}
	if got := o.pinHosts("web", "sbx.example"); len(got) != 1 || got[0] != "mine.example" {
		t.Errorf("pinHosts with -known-host: %v", got)
	}
}

// After a successful unlock both names are pinned in sbxkey's own
// known_hosts and the mirror holds the state's sandboxes; sbxkey then names
// the plain login. With "none", or for a directory that is not sbxkey's
// own, no file is written anywhere and it names the long command as before.
func TestSSHPinAfterUnlock(t *testing.T) {
	o, st, home := pinWorld(t)
	mirror := filepath.Join(home, ".ssh", "sbx_known_hosts")

	// "none", and no flag for a state that is not sbxkey's own.
	for _, flag := range []string{sshMirrorOff, ""} {
		o.pin = sshPin{mirrorFlag: flag}
		if err := o.pin.resolve(o.dir); err != nil {
			t.Fatal(err)
		}
		o.pin.domain = "sbx.example"
		syncSSHPins(o, st, "web", "sbx.example")
		if _, err := os.Stat(filepath.Join(home, ".ssh")); err == nil || o.pin.mirrored {
			t.Fatalf("-ssh-known-hosts %q wrote a mirror", flag)
		}
		if hint := sshHint(o, "web"); !strings.Contains(hint, "ssh -o UserKnownHostsFile="+o.knownHostPath+" -o StrictHostKeyChecking=yes root@web\n") {
			t.Errorf("without a mirror sbxkey says:\n%s", hint)
		}
	}
	// The key is pinned under both names all the same.
	if got, want := fileOrNone(o.knownHostPath), "web,web.sbx.example "+pinKeyA+"\n"; got != want {
		t.Fatalf("sbxkey's known_hosts:\n%s\nwant:\n%s", got, want)
	}

	// With the mirror on.
	o.pin = sshPin{mirror: mirror, domain: "sbx.example"}
	syncSSHPins(o, st, "db", "sbx.example")
	if got := mirrorLines(mirror); got != bothMirror || !o.pin.mirrored {
		t.Fatalf("mirror:\n%s\nwant:\n%s", got, bothMirror)
	}
	if got := fileOrNone(o.knownHostPath); !strings.Contains(got, "db,db.sbx.example "+pinKeyB+"\n") {
		t.Errorf("sbxkey's known_hosts after db's unlock:\n%s", got)
	}
	if hint := sshHint(o, "db"); !strings.Contains(hint, "\n    ssh root@db.sbx.example\n") || strings.Contains(hint, "UserKnownHostsFile") || !strings.Contains(hint, mirror) {
		t.Errorf("with the mirror sbxkey says:\n%s", hint)
	}
	// OpenSSH finds each name in it.
	if _, err := exec.LookPath("ssh-keygen"); err == nil {
		for _, name := range []string{"web", "web.sbx.example", "db", "db.sbx.example"} {
			if out, err := exec.Command("ssh-keygen", "-F", name, "-f", mirror).CombinedOutput(); err != nil {
				t.Errorf("ssh-keygen -F %s: %v\n%s", name, err, out)
			}
		}
		if exec.Command("ssh-keygen", "-F", "elsewhere.sbx.example", "-f", mirror).Run() == nil {
			t.Error("the mirror has a line for a sandbox without a recorded key")
		}
	}
	// Names the owner chose with -known-host are not replaced by the default ones.
	o.knownHosts = paths{"mine.example"}
	before := fileOrNone(o.knownHostPath)
	syncSSHPins(o, st, "web", "sbx.example")
	if fileOrNone(o.knownHostPath) != before {
		t.Error("an unlock with -known-host rewrote the default pins")
	}
	o.knownHosts = nil
	// Without a domain the long command stays: plain ssh by name needs one.
	o.pin = sshPin{mirror: mirror}
	syncSSHPins(o, st, "web", "")
	if hint := sshHint(o, "web"); !o.pin.mirrored || !strings.Contains(hint, "UserKnownHostsFile="+o.knownHostPath) {
		t.Errorf("without a domain sbxkey says:\n%s", hint)
	}
	// A mirror that cannot be written does not undo the unlock: it is said.
	os.WriteFile(filepath.Join(home, "file"), nil, 0o600)
	o.pin = sshPin{mirror: filepath.Join(home, "file", "sbx_known_hosts"), domain: "sbx.example"}
	syncSSHPins(o, st, "web", "sbx.example")
	if o.pin.mirrored || !strings.Contains(sshHint(o, "web"), "UserKnownHostsFile="+o.knownHostPath) {
		t.Error("a mirror that could not be written is named as written")
	}
}

// "sbxkey rename OLD NEW" moves both lines, in sbxkey's own known_hosts and
// in the mirror.
func TestSSHPinRename(t *testing.T) {
	o, st, home := pinWorld(t)
	mirror := filepath.Join(home, ".ssh", "sbx_known_hosts")
	if err := st.SetDomain("sbx.example"); err != nil {
		t.Fatal(err)
	}
	o.pin = sshPin{mirror: mirror}
	syncSSHPins(o, st, "web", "sbx.example")
	if mirrorLines(mirror) != bothMirror {
		t.Fatalf("mirror before the rename:\n%s", mirrorLines(mirror))
	}
	o.pin = sshPin{mirror: mirror} // a new run: the domain comes from the state
	if err := rename(o, "web", "site"); err != nil {
		t.Fatal(err)
	}
	if got, want := fileOrNone(o.knownHostPath), "site,site.sbx.example "+pinKeyA+"\n"; got != want {
		t.Errorf("sbxkey's known_hosts after the rename:\n%s\nwant:\n%s", got, want)
	}
	want := "db " + pinKeyB + "\ndb.sbx.example " + pinKeyB + "\nsite " + pinKeyA + "\nsite.sbx.example " + pinKeyA
	if got := mirrorLines(mirror); got != want {
		t.Errorf("mirror after the rename:\n%s\nwant:\n%s", got, want)
	}
	// "none": the record and sbxkey's own file follow, the mirror is not touched.
	o.pin = sshPin{mirrorFlag: sshMirrorOff}
	o.pin.resolve(o.dir)
	if err := rename(o, "site", "shop"); err != nil {
		t.Fatal(err)
	}
	if got := mirrorLines(mirror); got != want {
		t.Errorf("rename with -ssh-known-hosts none changed the mirror:\n%s", got)
	}
}

// "sbxkey known-hosts [NAME]" writes the mirror from the record, without
// an unlock: for sandboxes made before sbxkey wrote it, and to rebuild a
// file that was deleted.
func TestKnownHostsCommand(t *testing.T) {
	o, _, home := pinWorld(t)
	mirror := filepath.Join(home, ".ssh", "sbx_known_hosts")

	// Not sbxkey's own directory and no file named; and "none".
	o.pin = sshPin{}
	o.pin.resolve(o.dir)
	if err := knownHosts(o, nil); err == nil || !strings.Contains(err.Error(), "give -ssh-known-hosts PATH") {
		t.Errorf("known-hosts for another directory: %v", err)
	}
	o.pin = sshPin{mirrorFlag: sshMirrorOff}
	o.pin.resolve(o.dir)
	if err := knownHosts(o, nil); err == nil || !strings.Contains(err.Error(), "there is no file to write") {
		t.Errorf("known-hosts -ssh-known-hosts none: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh")); err == nil {
		t.Fatal("a refused known-hosts wrote something")
	}

	// No domain known yet: the names alone. Then with -domain, which is kept.
	o.pin = sshPin{mirror: mirror}
	if err := knownHosts(o, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := mirrorLines(mirror), "db "+pinKeyB+"\nweb "+pinKeyA; got != want {
		t.Fatalf("mirror without a domain:\n%s", got)
	}
	o.pin = sshPin{mirror: mirror, domainFlag: "sbx.example"}
	o.pin.resolve(o.dir)
	o.pin.mirror = mirror
	if err := knownHosts(o, nil); err != nil {
		t.Fatal(err)
	}
	whole := fileOrNone(mirror)
	st, err := ownerkey.OpenState(o.statePath, o.knownHostPath) // as the next run reads it
	if err != nil || mirrorLines(mirror) != bothMirror || st.Domain() != "sbx.example" {
		t.Fatalf("mirror:\n%s\nstate domain %q %v", whole, st.Domain(), err)
	}
	// sbxkey's own known_hosts has both names for each as well.
	if got, want := fileOrNone(o.knownHostPath), "db,db.sbx.example "+pinKeyB+"\nweb,web.sbx.example "+pinKeyA+"\n"; got != want {
		t.Errorf("sbxkey's known_hosts:\n%s\nwant:\n%s", got, want)
	}

	// Deleted: rebuilt, the same bytes, by a run that is given no domain.
	os.Remove(mirror)
	o.pin = sshPin{mirror: mirror}
	if err := knownHosts(o, []string{"web"}); err != nil {
		t.Fatal(err)
	}
	if got := fileOrNone(mirror); got != whole {
		t.Errorf("rebuilt mirror:\n%s\nwant:\n%s", got, whole)
	}
	// A name that is not on record, one without a key, and too many.
	for args, why := range map[string]string{"nosuch": "no sandbox called nosuch", "elsewhere": "no SSH host key for elsewhere", "a/b": "not a sandbox name", "web db": "usage:"} {
		os.Remove(mirror)
		if err := knownHosts(o, strings.Fields(args)); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("known-hosts %s: %v", args, err)
		}
		if fileOrNone(mirror) != "(none)" {
			t.Errorf("known-hosts %s wrote the mirror", args)
		}
	}
}

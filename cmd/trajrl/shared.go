package main

// A colleague's known_hosts for a sandbox shared with them (#118 B2, #32).
//
// Where owners hold the keys, the platform does not know a sandbox's SSH
// host key, so it cannot give it to a colleague the owner shared the
// sandbox with ("share ssh NAME ACCOUNT"). A colleague cannot verify it
// either: "show NAME-OWNER" is the owner's alone, so they do not have the
// sandbox's ID the quote is bound to. The one trustworthy source is the
// owner, whose machine verified the key. So:
//
//   - the owner's "trajrl share ssh NAME ACCOUNT" (the entry point's
//     command, forwarded), once the entry point carried it out, prints a
//     command for the colleague holding the known_hosts line of the key
//     verified here, under the colleague's name for the sandbox, NAME-OWNER
//     (NAME.OWNER for an account with a hyphen) and NAME-OWNER.DOMAIN.
//     "trajrl known-hosts --share NAME" prints it again;
//   - the colleague runs it: "trajrl known-hosts --import 'LINE'" checks
//     the line's shape, and records it in trajrl's shared_known_hosts (for
//     "trajrl ssh NAME-OWNER") and in their ~/.ssh/known_hosts (for plain
//     "ssh root@NAME-OWNER.DOMAIN").
//
// The line is as trustworthy as the channel that carried it, like the
// public key the colleague sent the owner. Nothing is ever taken from the
// first connection (no trust on first use): without an imported line,
// trajrl ssh refuses, and so does the colleague's strict ssh.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
)

// sharedHostsPath is trajrl's record of the host keys owners gave you.
func sharedHostsPath() string { return filepath.Join(dir(), "shared_known_hosts") }

const sharedHostsHeader = "# trajrl: SSH host keys of sandboxes shared with you, as their owners gave them\n" +
	"# (trajrl known-hosts --import). Not verified on this machine. One line per sandbox.\n"

// sharedName is the name the account owner's sandbox name has for the
// accounts it is shared with: the control plane's sshSharedName.
func sharedName(name, owner string) string {
	if l := name + "-" + owner; !strings.Contains(owner, "-") && len(l) <= 63 {
		return l
	}
	return name + "." + owner
}

// readKnownHosts reads a known_hosts file as lines; a missing one is none.
func readKnownHosts(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n"), nil
}

// sharedHostKey is the host key the owner of the shared sandbox name gave
// you, if one is recorded.
func sharedHostKey(c *config, name string) (string, bool) {
	lines, err := readKnownHosts(sharedHostsPath())
	if err != nil {
		return "", false
	}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != 3 || strings.HasPrefix(l, "#") {
			continue
		}
		if slices.Contains(strings.Split(f[0], ","), name) {
			return f[1] + " " + f[2], true
		}
	}
	return "", false
}

// verifiedHostKeyOf is the host key of the sandbox name, of ID id, that a
// check here vouched for (verifiedHostKey, with the ID held against it).
func verifiedHostKeyOf(name, id string) (string, error) {
	if ps, err := sbxapi.LoadPins(sbxapi.DefaultPinFile()); err == nil {
		if p, ok := ps.Sandboxes[name]; ok && p.HostKey != "" && p.ID == id {
			return p.HostKey, nil
		}
	}
	st, err := ownerState()
	if err != nil {
		return "", err
	}
	if r := st.ByName(name); r != nil && r.ID == id && r.SSHHostKey != "" && r.Policy != "" {
		return r.SSHHostKey, nil
	}
	return "", fmt.Errorf("no host key of %s (%s) was verified on this machine: run %s verify %s first", name, id, prog, name)
}

// shareLine is the known_hosts line of your sandbox name for those it is
// shared with: the host key verified here, under their names for it.
func shareLine(c *config, name string) (string, error) {
	if c.Domain == "" {
		return "", fmt.Errorf("the entry point named no domain for sandbox names: run %s setup", prog)
	}
	out, err := entryOutput(c, "whoami")
	if err != nil {
		return "", err
	}
	owner := strings.TrimSpace(string(out))
	if !ownerkey.ValidName(owner) || strings.Contains(owner, ".") {
		return "", fmt.Errorf("the entry point's answer to whoami is not an account name: %.60q", owner)
	}
	if out, err = entryOutput(c, "show", name, "--json"); err != nil {
		return "", err
	}
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &v); err != nil || v.ID == "" {
		return "", fmt.Errorf("show %s --json: no ID", name)
	}
	key, err := verifiedHostKeyOf(name, v.ID)
	if err != nil {
		return "", err
	}
	return ownerkey.KnownHostsLine(ownerkey.SandboxHosts(sharedName(name, owner), c.Domain), key)
}

// printShare prints the command the colleague runs.
func printShare(line, who string) {
	fmt.Printf("\nTo log in, %s needs this sandbox's SSH host key, which only you hold (verified on this machine).\n"+
		"Send them this command over a channel you trust, as they sent you their key; it records the key\n"+
		"for \"%s ssh\" and for their ssh:\n\n  %s known-hosts --import '%s'\n", who, prog, prog, line)
}

// shareCmd is the entry point's "share ...", forwarded; after "share ssh
// NAME ACCOUNT" it prints the line for ACCOUNT.
func shareCmd(args []string) int {
	c, err := loadConfig()
	if err != nil {
		return fail(255, "%v", err)
	}
	code := forward(c, args, os.Stdin, os.Stdout, os.Stderr)
	if code != 0 || len(args) != 4 || args[1] != "ssh" || !ownerkey.ValidName(args[2]) {
		return code
	}
	line, err := shareLine(c, args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s: %s's host key for %s: %v\n  Until they have it, their ssh refuses %s. Then: %s known-hosts --share %s\n", prog, args[3], args[2], err, args[2], prog, args[2])
		return 0
	}
	printShare(line, args[3])
	return 0
}

// knownHostsCmd is "known-hosts --share NAME", "known-hosts --import LINE"
// (trajrl's), or sbxkey's "known-hosts [NAME]".
func knownHostsCmd(args []string) int {
	rest := args[1:]
	if len(rest) == 0 || (rest[0] != "--share" && rest[0] != "-share" && rest[0] != "--import" && rest[0] != "-import") {
		return bootCmd(args)
	}
	if len(rest) != 2 {
		return fail(2, "usage: %s known-hosts --share NAME | --import 'LINE'", prog)
	}
	c, err := loadConfig()
	if err != nil {
		return fail(255, "%v", err)
	}
	if strings.HasSuffix(rest[0], "share") {
		if !ownerkey.ValidName(rest[1]) {
			return fail(2, "%q is not a sandbox name", rest[1])
		}
		line, err := shareLine(c, rest[1])
		if err != nil {
			return fail(1, "%v", err)
		}
		fmt.Println(line)
		printShare(line, "a colleague you shared it with (share ssh)")
		return 0
	}
	line := rest[1]
	if strings.Count(strings.TrimSpace(line), " ") != 2 {
		if b, err := os.ReadFile(line); err == nil {
			line = string(b)
		}
	}
	name, fp, err := importLine(c, line)
	if err != nil {
		return fail(1, "%v", err)
	}
	fmt.Printf("%s: its host key %s, as its owner gave it, is recorded in %s and %s.\n  Log in: %s ssh %s   (or: ssh root@%s)\n",
		name, fp, sharedHostsPath(), filepath.Join(sshDirOf(c.SSHDir), "known_hosts"), prog, name, name+"."+c.Domain)
	return 0
}

// importLine checks line, the owner's known_hosts line of a shared sandbox,
// and records it: in trajrl's shared_known_hosts and in your ssh's
// known_hosts, each in place of a line for the same names. Only the shape
// trajrl share prints is taken: NAME and NAME.DOMAIN (DOMAIN this
// machine's), NAME a colleague's name for a sandbox (with "-" or "."), one
// plain public key.
func importLine(c *config, line string) (name, fingerprint string, err error) {
	if c.Domain == "" {
		return "", "", fmt.Errorf("the entry point named no domain for sandbox names: run %s setup", prog)
	}
	f := strings.Fields(line)
	if len(f) != 3 || strings.ContainsAny(line, "\r\x00") || strings.Count(strings.TrimSpace(line), "\n") != 0 {
		return "", "", errors.New("not one known_hosts line: give the line trajrl share ssh printed for you, NAME-OWNER,NAME-OWNER.DOMAIN TYPE KEY")
	}
	hosts := strings.Split(strings.ToLower(f[0]), ",")
	name = hosts[0]
	for _, h := range hosts {
		if len(h) < len(name) {
			name = h
		}
	}
	want := ownerkey.SandboxHosts(name, c.Domain)
	got := slices.Clone(hosts)
	slices.Sort(got)
	slices.Sort(want)
	if !ownerkey.ValidName(name) || !strings.ContainsAny(name, "-.") || !slices.Equal(got, want) {
		return "", "", fmt.Errorf("%.80q are not the names of a sandbox shared with you: NAME-OWNER and NAME-OWNER.%s, nothing else", f[0], c.Domain)
	}
	pk, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(f[1] + " " + f[2]))
	if err != nil || len(rest) != 0 {
		return "", "", errors.New("the line holds no SSH public key")
	}
	if _, cert := pk.(*ssh.Certificate); cert {
		return "", "", errors.New("the line holds a certificate, not a host key")
	}
	written, err := ownerkey.KnownHostsLine(ownerkey.SandboxHosts(name, c.Domain), f[1]+" "+f[2])
	if err != nil {
		return "", "", err
	}
	field := strings.Fields(written)[0]
	if err := replaceKnownHost(sharedHostsPath(), sharedHostsHeader, field, written); err != nil {
		return "", "", err
	}
	if err := replaceKnownHost(filepath.Join(sshDirOf(c.SSHDir), "known_hosts"), "", field, written); err != nil {
		return "", "", err
	}
	return name, ssh.FingerprintSHA256(pk), nil
}

// replaceKnownHost writes line into the known_hosts file path in place of
// any line for exactly the hosts field, keeping every other line; a new
// file starts with header.
func replaceKnownHost(path, header, field, line string) error {
	old, err := readKnownHosts(path)
	if err != nil {
		return err
	}
	var out []string
	for _, l := range old {
		if f := strings.Fields(l); len(f) > 0 && f[0] == field {
			continue
		}
		out = append(out, l)
	}
	if len(old) == 0 && header != "" {
		out = append(out, strings.Split(strings.TrimRight(header, "\n"), "\n")...)
	}
	out = append(out, line)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".known_hosts-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(strings.Join(out, "\n") + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

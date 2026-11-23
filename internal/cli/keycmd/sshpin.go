package keycmd

// sbxkey and the owner's ssh (#114). The SSH host key of a sandbox is what
// its TD reported at its first boot, in the session whose quote sbxkey
// verified. The platform does not know it (the owner holds the keys), so
// plain "ssh root@NAME.DOMAIN" has to get it from here:
//
//   - the key is pinned under NAME and NAME.DOMAIN. DOMAIN is asked of the
//     entry point ("ssh ENTRY domain") and kept in the state; -domain D
//     overrides. It is the platform's word: a wrong one puts the pin under
//     a name the owner's ssh never looks up, which strict checking refuses.
//   - after every successful new, start, unlock and rename, the keys of
//     all sandboxes on record are written to ~/.ssh/sbx_known_hosts. The
//     ssh_config lines "trajrl setup" installs name that file for
//     *.DOMAIN, with StrictHostKeyChecking yes where owners hold the keys.
//     -ssh-known-hosts PATH moves the file, "none" turns it off.
//   - "sbxkey known-hosts [NAME]" writes the file from the record, with no
//     unlock and no key: for sandboxes made before this existed.
//
// The file in ~/.ssh is one state's: it holds exactly that state's
// sandboxes. So it is written by default only for sbxkey's own directory;
// with another -dir, give -ssh-known-hosts PATH to have one.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// sshPin is what a run knows of the owner's ssh.
type sshPin struct {
	domainFlag, mirrorFlag string
	// mirror is the file the keys are mirrored to, "" for none.
	mirror string
	// domain is the domain for sandbox names this run uses, once it is
	// known; mirrored, that the mirror was written.
	domain   string
	mirrored bool
}

const sshMirrorOff = "none"

// sshPinFlags adds the flags of this file to a command's.
func sshPinFlags(fs *flag.FlagSet, o *opts, cmd string) {
	switch cmd {
	case "known-hosts":
		fs.StringVar(&o.entry, "entry", "", "the platform's SSH entry point, host:port: ask it for the domain for sandbox names")
		fs.StringVar(&o.entryKey, "entry-key", "", "the entry point's SSH host key as the platform publishes it")
		fs.StringVar(&o.keyFile, "i", "", "your SSH private key file (default: your SSH agent)")
	case "start", "unlock", "new", "rename":
	default:
		return
	}
	fs.StringVar(&o.pin.domainFlag, "domain", "", "the platform's domain for sandbox names, the DOMAIN of NAME.DOMAIN (default: asked of the entry point, and remembered)")
	fs.StringVar(&o.pin.mirrorFlag, "ssh-known-hosts", "", "the file your ssh reads your sandboxes' host keys from; 'none': write none (default: ~/.ssh/sbx_known_hosts, for sbxkey's own directory)")
}

// resolve checks -domain and settles where the mirror goes.
func (p *sshPin) resolve(dir string) error {
	if p.domainFlag != "" {
		d, ok := ownerkey.CleanDomain(p.domainFlag)
		if !ok {
			return fmt.Errorf("-domain %q is not a domain for sandbox names", p.domainFlag)
		}
		p.domain = d
	}
	switch p.mirrorFlag {
	case sshMirrorOff:
	case "":
		// One state, one file: only sbxkey's own directory writes ~/.ssh.
		home, err := os.UserHomeDir()
		if err == nil && filepath.Clean(dir) == filepath.Clean(defaultDir()) {
			p.mirror = filepath.Join(home, ".ssh", "sbx_known_hosts")
		}
	default:
		p.mirror = p.mirrorFlag
	}
	return nil
}

// sandboxDomain settles the domain for sandbox names: -domain, or what the
// entry point answers to "domain" (ask), which is then kept in the state,
// or what the state holds from an earlier run. A platform that does not
// know the command, names no domain or names something that is not one
// changes nothing.
func sandboxDomain(o *opts, st *ownerkey.State, ask func() (string, error)) string {
	if o.pin.domain != "" {
		st.SetDomain(o.pin.domain)
		return o.pin.domain
	}
	if ask != nil {
		if out, err := ask(); err == nil && strings.TrimSpace(out) != "" {
			if d, ok := ownerkey.CleanDomain(out); ok {
				if err := st.SetDomain(d); err != nil {
					fmt.Fprintf(os.Stderr, "note: the domain for sandbox names (%s) could not be recorded: %v\n", d, err)
				}
				o.pin.domain = d
				return d
			}
			fmt.Fprintln(os.Stderr, "note: the platform's answer to \"domain\" is not a domain for sandbox names; it is not used")
		}
	}
	o.pin.domain = st.Domain()
	return o.pin.domain
}

// pinHosts are the names a first boot pins the SSH host key for: those
// given with -known-host, or NAME and NAME.DOMAIN.
func (o *opts) pinHosts(name, domain string) []string {
	if len(o.knownHosts) > 0 {
		return o.knownHosts
	}
	return ownerkey.SandboxHosts(name, domain)
}

// syncSSHPins runs after a successful unlock of name: its key is pinned
// under both names (a sandbox first booted before this existed, or before
// the domain was known, had one), and the mirror is written. Neither can
// undo the unlock, so a failure is said and not returned.
func syncSSHPins(o *opts, st *ownerkey.State, name, domain string) {
	if r := st.ByName(name); r != nil && r.SSHHostKey != "" && len(o.knownHosts) == 0 {
		if _, err := st.PinSandbox(name, name, domain, r.SSHHostKey); err != nil {
			fmt.Fprintf(os.Stderr, "note: %s's SSH host key could not be pinned in %s: %v\n", name, o.knownHostPath, err)
		}
	}
	writeSSHMirror(o, st, domain)
}

// writeSSHMirror writes the mirror, if this run has one.
func writeSSHMirror(o *opts, st *ownerkey.State, domain string) {
	if o.pin.mirror == "" {
		return
	}
	if _, err := st.WriteSSHMirror(o.pin.mirror, domain); err != nil {
		fmt.Fprintf(os.Stderr, "note: your sandboxes' SSH host keys could not be written to %s: %v\n  Until they are, your ssh refuses root@NAME.DOMAIN. Write them with: %s\n", o.pin.mirror, err, ownerkey.Command("known-hosts"))
		return
	}
	o.pin.mirrored = true
}

// sshHint is how to log in after a first boot: plainly by name where the
// owner's ssh finds the key in the mirror, otherwise with sbxkey's own
// known_hosts named.
func sshHint(o *opts, name string) string {
	if o.pin.mirrored && o.pin.domain != "" {
		settings := "\"trajrl setup\""
		if ownerkey.Tool != "sbxkey" {
			settings = "\"" + ownerkey.Tool + " setup\""
		}
		return fmt.Sprintf("  It is in %s too, for your ssh. Log in (with the settings of %s\n"+
			"  your ssh checks this key and refuses any other machine):\n    ssh root@%s.%s\n", o.pin.mirror, settings, name, o.pin.domain)
	}
	return fmt.Sprintf("  Use it so that no other machine can answer for this sandbox:\n    ssh -o UserKnownHostsFile=%s -o StrictHostKeyChecking=yes root@%s\n", o.knownHostPath, name)
}

// knownHosts is "sbxkey known-hosts [NAME]": the mirror written from the
// record as it is, with no unlock, no key file and no passphrase. With
// NAME, NAME has to be on record with a key, and its lines are printed.
func knownHosts(o *opts, args []string) error {
	if len(args) > 1 {
		return errors.New("usage: " + ownerkey.Command("known-hosts [-dir DIR] [-domain D] [-ssh-known-hosts PATH] [NAME]"))
	}
	if o.pin.mirror == "" {
		if o.pin.mirrorFlag == sshMirrorOff {
			return errors.New("-ssh-known-hosts none: there is no file to write")
		}
		return fmt.Errorf("%s is not sbxkey's own directory, so ~/.ssh/sbx_known_hosts is not its to write: give -ssh-known-hosts PATH", o.dir)
	}
	if _, err := os.Stat(o.statePath); err != nil {
		return fmt.Errorf("%s holds no record of sandboxes (%s): there is nothing to write", o.dir, filepath.Base(o.statePath))
	}
	st, err := ownerkey.OpenState(o.statePath, o.knownHostPath)
	if err != nil {
		return err
	}
	var ask func() (string, error)
	if o.pin.domain == "" && o.entry != "" {
		id, err := userverify.LoadIdentity(o.keyFile)
		if err != nil {
			return err
		}
		entry, err := userverify.DialEntry(o.entry, o.entryKey, id.Auth)
		if err != nil {
			return err
		}
		defer entry.Close()
		ask = func() (string, error) { return ownerkey.RunEntry(entry, []string{"domain"}) }
	}
	domain := sandboxDomain(o, st, ask)
	var one *ownerkey.Record
	if len(args) == 1 {
		if !ownerkey.ValidName(args[0]) {
			return fmt.Errorf("%q is not a sandbox name", args[0])
		}
		switch one = st.ByName(args[0]); {
		case one == nil:
			return fmt.Errorf("your record has no sandbox called %s", args[0])
		case one.SSHHostKey == "":
			return fmt.Errorf("your record has no SSH host key for %s (its first boot was confirmed elsewhere): '%s' checks the sandbox and prints the key", args[0], ownerkey.VerifyOwnerCommand(args[0]))
		}
	}
	// sbxkey's own known_hosts gets both names too.
	for _, r := range st.Records() {
		if r.SSHHostKey == "" || (one != nil && r.ID != one.ID) {
			continue
		}
		if _, err := st.PinSandbox(r.Name, r.Name, domain, r.SSHHostKey); err != nil {
			return err
		}
	}
	names, err := st.WriteSSHMirror(o.pin.mirror, domain)
	if err != nil {
		return err
	}
	how := "under NAME"
	if domain != "" {
		how = "under NAME and NAME." + domain
	}
	fmt.Printf("%s: the SSH host keys of %d sandboxes on your record (%s), each %s.\n", o.pin.mirror, len(names), strings.Join(names, ", "), how)
	if domain == "" {
		fmt.Println("  No domain for sandbox names is known, so there is no line for NAME.DOMAIN: give -domain D, or -entry and -entry-key to ask the platform.")
	}
	if one != nil {
		for _, h := range ownerkey.SandboxHosts(one.Name, domain) {
			line, err := ownerkey.KnownHostsLine([]string{h}, one.SSHHostKey)
			if err != nil {
				return err
			}
			fmt.Println("  " + line)
		}
	}
	return nil
}

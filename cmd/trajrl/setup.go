package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/sshsetup"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// whoamiWait is how long setup waits for the entry point's whoami. A key
// with no account is held there until it is linked on the website.
var whoamiWait = 15 * time.Second

// setupCmd is "setup": the entry point, its key pinned, saved for trajrl,
// then the entry point's ssh_config lines for "ssh root@NAME.DOMAIN",
// checked against the one shape the entry point writes, their ProxyCommand
// this trajrl ("trajrl proxy %h %p"), and installed with trajrl's own
// installer. An older setup's lines (ProxyJump, and the entry point's key
// pinned in known_hosts) are replaced. "setup --remove" takes them out
// again, with no entry point.
func setupCmd(args []string) int {
	fs := flag.NewFlagSet(prog+" setup", flag.ContinueOnError)
	entry := fs.String("entry", "", "the platform's SSH entry point, HOST:PORT")
	entryKey := fs.String("entry-key", "", "the entry point's SSH host key as the platform publishes it, 'ssh-ed25519 AAAA...'")
	keyFile := fs.String("i", "", "your SSH private key file (default: your SSH agent, or the first of ~/.ssh/id_ed25519, id_ecdsa, id_rsa without a passphrase, saved)")
	sshDir := fs.String("ssh-dir", "", "your ssh's directory (default: ~/.ssh)")
	remove := fs.Bool("remove", false, "take out what setup installed in your ssh's files")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return fail(2, "usage: %s setup %s", prog, Commands[0].Usage)
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	old, _ := loadConfig()
	if *remove {
		if old == nil || old.Domain == "" || old.SSHConfig == "" {
			fmt.Printf("Nothing of setup's is installed: %s names none.\n", configPath())
			return 0
		}
		dirTo := old.SSHDir
		if given["ssh-dir"] {
			dirTo = *sshDir
		}
		if err := sshsetup.Install(true, old.Domain, old.SSHConfig, legacyPin(old), dirTo, os.Stdout, os.Stderr); err != nil {
			return fail(1, "the removal: %v", err)
		}
		old.EntryName, old.SSHConfig, old.SSHDir = "", "", ""
		if err := old.save(); err != nil {
			return fail(1, "%v", err)
		}
		return 0
	}

	if old != nil && !given["ssh-dir"] {
		// Installed again where it was installed (and an older setup's
		// lines replaced there).
		*sshDir = old.SSHDir
	}
	c := &config{Entry: *entry, EntryKey: *entryKey, Identity: *keyFile}
	if old != nil {
		c.Site = old.Site
	}
	if old != nil && !given["entry"] && !given["entry-key"] {
		// setup again, after registering: the entry point as it was saved.
		c.Entry, c.EntryKey = old.Entry, old.EntryKey
		if !given["i"] {
			c.Identity = old.Identity
		}
	}
	if c.Entry == "" || c.EntryKey == "" {
		return fail(2, "usage: %s setup %s", prog, Commands[0].Usage)
	}
	if cred, _ := activeCredentials(); cred == nil && c.Identity == "" {
		// No -i: an SSH agent's key, or the key file ssh would use,
		// saved so that later commands use the same.
		file, locked := (&config{SSHDir: *sshDir}).identityFile()
		if file == "" && !userverify.AgentHasKeys() {
			return fail(1, "%v", noKey(locked))
		}
		for _, l := range locked {
			fmt.Fprintf(os.Stderr, "%s: %s has a passphrase, which %s does not ask for: passed over (load it into your SSH agent, or give -i KEYFILE)\n", prog, l, prog)
		}
		if c.Identity = file; file != "" {
			fmt.Printf("Your SSH key: %s (no -i given and no SSH agent with a key; saved for later commands)\n", file)
		}
	}
	k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(c.EntryKey))
	if err != nil || strings.TrimSpace(string(rest)) != "" {
		return fail(2, "-entry-key %q is not one SSH public key ('ssh-ed25519 AAAA...')", c.EntryKey)
	}
	c.EntryKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	if old != nil && old.Entry == c.Entry && old.EntryKey == c.EntryKey {
		// What setup installed stays known until it is installed again.
		c.EntryName, c.SSHConfig, c.SSHDir, c.Domain = old.EntryName, old.SSHConfig, old.SSHDir, old.Domain
	}
	if err := c.save(); err != nil {
		return fail(1, "%v", err)
	}
	fmt.Printf("Entry point %s saved in %s, its key pinned.\n", c.Entry, configPath())
	// An unknown key's whoami is held by the entry point, waiting for the
	// key to be linked on the website: setup does not wait for that.
	who, said, err := entryOutputWithin(c, whoamiWait, "whoami")
	if err != nil {
		if errors.Is(err, errNoAnswer) {
			fmt.Fprintf(os.Stderr, "%s: the entry point held whoami for %s without an answer: your key has no account there yet.\n", prog, whoamiWait)
			if said != "" {
				fmt.Fprintf(os.Stderr, "What it said:\n  %s\n", strings.ReplaceAll(said, "\n", "\n  "))
			}
		} else {
			fmt.Fprintf(os.Stderr, "%s: the entry point does not know your key yet (%v).\n", prog, err)
		}
		fmt.Fprintf(os.Stderr, "Sign in first: %s auth login (or make an account that is this key alone: %s register NAME --invite CODE), then run %s setup again.\n", prog, prog, prog)
		return 1
	}
	fmt.Printf("Your account there: %s\n", strings.TrimSpace(string(who)))

	d, err := entryOutput(c, "domain", "--json")
	if err != nil {
		return fail(1, "%v", err)
	}
	var domain struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(d, &domain); err != nil {
		return fail(1, "the entry point's answer to domain: %v", err)
	}
	sc, err := entryOutput(c, "ssh-config", "--json")
	if err != nil {
		return fail(1, "%v", err)
	}
	var lines struct {
		SSHConfig string `json:"ssh_config"`
	}
	if err := json.Unmarshal(sc, &lines); err != nil {
		return fail(1, "the entry point's answer to ssh-config: %v", err)
	}
	if err := sshsetup.Check(lines.SSHConfig, domain.Domain); err != nil {
		return fail(1, "%v", err)
	}
	// ssh reaches a sandbox through this trajrl, which pins the entry
	// point's key itself: nothing of the entry point is in ssh's files.
	installed, err := sshsetup.Localize(lines.SSHConfig, selfPath())
	if err != nil {
		return fail(1, "%v", err)
	}
	if err := sshsetup.Install(false, domain.Domain, installed, legacyPin(old), *sshDir, os.Stdout, os.Stderr); err != nil {
		return fail(1, "the installer: %v", err)
	}
	c.Domain, c.EntryName, c.SSHConfig, c.SSHDir = domain.Domain, "", installed, *sshDir
	if err := c.save(); err != nil {
		return fail(1, "%v", err)
	}
	if strings.Contains(lines.SSHConfig, "\n    StrictHostKeyChecking yes\n") {
		// Owner-held keys: the platform has no sandbox's host key, so an
		// older setup's KnownHostsCommand asking it for one fails every
		// plain "ssh root@NAME.DOMAIN".
		path := filepath.Join(sshDirOf(*sshDir), "config")
		changed, backup, err := sshsetup.DropKnownHostsCommand(path, domain.Domain)
		if err != nil {
			return fail(1, "%s: %v", path, err)
		}
		if len(changed) > 0 {
			fmt.Printf("Commented out in %s (backup: %s), as the platform holds no host keys of your sandboxes:\n", path, backup)
			for _, l := range changed {
				fmt.Printf("  %s\n", l)
			}
		}
	}
	fmt.Printf("Log in to a sandbox of yours: ssh root@NAME.%s (or: %s ssh NAME)\n", domain.Domain, prog)
	return 0
}

// legacyPin is the known_hosts line an older setup pinned the entry
// point's key with in ssh's files, under the name its ProxyJump lines gave
// the entry point (config.EntryName); "" if it pinned none.
func legacyPin(c *config) string {
	if c == nil || c.EntryName == "" || c.EntryKey == "" {
		return ""
	}
	return c.EntryName + " " + c.EntryKey
}

var proxySelf string

// selfPath is the path of this trajrl for ssh's ProxyCommand: the one
// found on PATH where that is this same program (a link a package manager
// keeps across upgrades), otherwise the program's own path.
func selfPath() string {
	if proxySelf != "" {
		return proxySelf
	}
	exe, err := os.Executable()
	if err != nil {
		exe = prog
	}
	if lp, err := exec.LookPath(prog); err == nil {
		if abs, err := filepath.Abs(lp); err == nil {
			a, errA := os.Stat(abs)
			b, errB := os.Stat(exe)
			if errA == nil && errB == nil && os.SameFile(a, b) {
				return abs
			}
		}
	}
	return exe
}

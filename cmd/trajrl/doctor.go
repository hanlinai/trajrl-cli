package main

// trajrl doctor (#118 B51): a self-check of this machine's setup. Each
// check is ok, warn or fail, with a one-line fix; exit 1 on any fail. The
// platform's notices (whoami --json) are lines of their own, info. The
// entry point is asked at most three times (whoami --json, plain whoami
// where that failed, ssh-key statement --json), each time given up after
// doctorTimeout. Nothing is changed and no passphrase is asked.

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/cli/keycmd"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/sshsetup"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// doctorTimeout bounds each question to the entry point.
var doctorTimeout = 10 * time.Second

// check is one line of doctor's.
type check struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // ok, warn, fail; info for a notice
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

type doctorReport struct {
	OK     bool    `json:"ok"`
	Checks []check `json:"checks"`
}

// doctorCmd is "doctor [--json]".
func doctorCmd(args []string) int {
	fs := flag.NewFlagSet(prog+" doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "as JSON")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		return fail(2, "usage: %s doctor [--json]", prog)
	}
	rep := doctor()
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(rep)
	} else {
		for _, c := range rep.Checks {
			fmt.Printf("%-4s  %-12s  %s\n", c.Status, c.Name, c.Message)
			if c.Fix != "" {
				fmt.Printf("%-4s  %-12s  fix: %s\n", "", "", c.Fix)
			}
		}
	}
	if !rep.OK {
		return 1
	}
	return 0
}

// doctor runs every check.
func doctor() doctorReport {
	var rep doctorReport
	add := func(name, status, msg, fix string) {
		rep.Checks = append(rep.Checks, check{Name: name, Status: status, Message: msg, Fix: fix})
	}
	setup := prog + " setup -entry HOST:PORT -entry-key 'ssh-ed25519 AAAA...' (the line on the website's Settings page)"

	// The configuration.
	c, err := loadConfig()
	switch {
	case err != nil && strings.Contains(err.Error(), "is not set up"):
		add("config", "fail", configPath()+" does not exist: this machine is not set up", setup)
	case err != nil:
		add("config", "fail", err.Error(), "run "+setup+" again, or fix the file")
	case c.Entry == "" || c.EntryKey == "":
		add("config", "fail", configPath()+" names no entry point or no entry key", "run "+setup+" again")
	case c.Domain == "":
		add("config", "warn", configPath()+": no domain for sandbox names, so ssh NAME cannot work", "run "+prog+" setup again (without flags it uses what it saved)")
	default:
		add("config", "ok", fmt.Sprintf("%s: entry point %s, domain %s", configPath(), c.Entry, c.Domain), "")
	}
	if c == nil {
		c = &config{}
	}

	// Your SSH key.
	keyOK := false
	if file, locked := c.identityFile(); file != "" {
		b, err := os.ReadFile(file)
		var pm *ssh.PassphraseMissingError
		switch {
		case err != nil:
			add("ssh-key", "fail", err.Error(), "give the key file again: "+prog+" setup -i KEYFILE")
		default:
			if _, err = ssh.ParsePrivateKey(b); errors.As(err, &pm) {
				add("ssh-key", "fail", file+" has a passphrase, which "+prog+" does not ask for", "load it into your SSH agent: ssh-add "+file)
			} else if err != nil {
				add("ssh-key", "fail", file+": "+err.Error(), "give another key file: "+prog+" setup -i KEYFILE")
			} else {
				add("ssh-key", "ok", file, "")
				keyOK = true
			}
		}
	} else if userverify.AgentHasKeys() {
		add("ssh-key", "ok", "your SSH agent's keys", "")
		keyOK = true
	} else {
		add("ssh-key", "fail", noKey(locked).Error(), "make one with ssh-keygen -t ed25519, and link its .pub on the website")
	}

	// The entry point: reached, its key the pinned one, your key known.
	account, reached := "", false
	switch {
	case c.Entry == "" || c.EntryKey == "":
		add("entry", "warn", "not checked: no entry point configured", setup)
	case !keyOK:
		add("entry", "warn", "not checked: no SSH key to log in with", "see ssh-key above")
	default:
		out, said, err := entryOutputWithin(c, doctorTimeout, "whoami", "--json")
		if err != nil && !errors.Is(err, errNoAnswer) {
			// An entry point older than whoami --json, or one that
			// cannot be reached: the plain question says which.
			out, said, err = entryOutputWithin(c, doctorTimeout, "whoami")
		}
		switch {
		case errors.Is(err, errNoAnswer):
			add("entry", "fail", fmt.Sprintf("%s did not answer within %s", c.Entry, doctorTimeout),
				"check your network; if your SSH key is not linked to an account, the entry point waits for it: link it on the website, or "+prog+" register NAME --invite CODE")
		case err != nil && strings.Contains(said, "host key mismatch"):
			add("entry", "fail", c.Entry+" answered with another host key than the one pinned in "+configPath(),
				"compare with the entry point's key on the website's Settings page; if it changed there, run "+setup)
		case err != nil:
			add("entry", "fail", oneLine(err.Error()), "check the entry point's address and your SSH key, then "+prog+" setup again")
		default:
			w, ok := parseWhoami(out)
			if !ok {
				w.Name = strings.TrimSpace(string(out))
			}
			account, reached = w.Name, true
			add("entry", "ok", fmt.Sprintf("%s answered with the pinned host key; you are %s", c.Entry, account), "")
			// What the platform has to tell the account: no fix, not a
			// failure.
			for _, n := range w.Notices {
				add("notice", "info", n, "")
			}
		}
	}

	// Your ssh's lines for "ssh root@NAME.DOMAIN": setup's, through trajrl
	// proxy. An older setup's go through the entry point with ProxyJump,
	// which it no longer answers.
	if c.Domain != "" {
		path := filepath.Join(sshDirOf(c.SSHDir), "config")
		again := prog + " setup (run it again: it replaces the lines)"
		switch shape, err := sshsetup.Installed(path, c.Domain); {
		case err != nil:
			add("ssh-config", "warn", oneLine(err.Error()), again)
		case shape == sshsetup.Legacy:
			add("ssh-config", "warn", fmt.Sprintf("%s: an older setup's lines for *.%s go through the entry point with ProxyJump, which it no longer answers: ssh root@NAME.%s fails (%s ssh NAME works)", path, c.Domain, c.Domain, prog), again)
		case shape == sshsetup.NotInstalled:
			add("ssh-config", "warn", fmt.Sprintf("%s has no lines of setup's for *.%s: ssh root@NAME.%s (and VS Code, scp, git) cannot reach your sandboxes (%s ssh NAME can)", path, c.Domain, c.Domain, prog), prog+" setup")
		default:
			add("ssh-config", "ok", fmt.Sprintf("%s: ssh root@NAME.%s goes through %s proxy", path, c.Domain, prog), "")
		}
	}

	// The owner's key file.
	kf := ownerkey.KeyFileIn(keycmd.DefaultDir())
	if err := ownerkey.KeyFileShape(kf); errors.Is(err, os.ErrNotExist) {
		add("owner-key", "warn", "no key file at "+kf+": you cannot create, start or unlock a sandbox here",
			prog+" key init (a new key), or "+prog+" key restore (from your recovery phrase)")
	} else if err != nil {
		add("owner-key", "fail", oneLine(err.Error()), "restore it from your recovery phrase: "+prog+" key restore")
	} else if fi, _ := os.Stat(kf); runtime.GOOS != "windows" && fi != nil && fi.Mode().Perm()&0o077 != 0 {
		add("owner-key", "warn", fmt.Sprintf("%s can be read by others (mode %v)", kf, fi.Mode().Perm()), "chmod 600 "+kf)
	} else {
		add("owner-key", "ok", kf+" (sealed under your passphrase; your written recovery phrase is not checked here)", "")
	}

	// The recovery key of the account's statement of keys.
	if !reached {
		add("recovery-key", "warn", "not checked: the entry point was not reached", "fix entry above, then "+prog+" doctor again")
	} else if out, _, err := entryOutputWithin(c, doctorTimeout, "ssh-key", "statement", "--json"); err != nil {
		add("recovery-key", "warn", "not checked: "+oneLine(err.Error()), prog+" keys list")
	} else if l, err := keycmd.LatestStatement(out, keycmd.DefaultDir(), io.Discard); err != nil {
		add("recovery-key", "warn", "not checked: "+oneLine(err.Error()), prog+" keys list")
	} else if l.Signed == "" {
		add("recovery-key", "warn", l.Account+" has no signed statement of keys yet, so no recovery key", prog+" recovery-key init")
	} else if l.Statement.Recovery == "" {
		add("recovery-key", "warn", fmt.Sprintf("statement %d of %s's keys has no recovery key: a lost laptop loses its sandboxes", l.Statement.Seq, l.Account),
			prog+" recovery-key init, then "+prog+" keys sync --all")
	} else {
		add("recovery-key", "ok", fmt.Sprintf("statement %d of %s's keys names a recovery key; %s keys status shows which sandboxes applied it", l.Statement.Seq, l.Account, prog), "")
	}

	// The launch policies.
	files, err := policies()
	var bad, good []string
	for _, f := range files {
		if _, perr := attest.LoadPolicy(f); perr != nil {
			bad = append(bad, filepath.Base(f))
		} else {
			good = append(good, strings.TrimSuffix(filepath.Base(f), ".json"))
		}
	}
	switch {
	case err != nil:
		add("policies", "fail", err.Error(), prog+" policy list")
	case len(bad) > 0:
		add("policies", "fail", fmt.Sprintf("not usable in %s: %s", policyDir(), strings.Join(bad, " ")), prog+" policy rm NAME, then "+prog+" policy add FILE")
	case len(good) == 0:
		add("policies", "warn", "no launch policy in "+policyDir()+": new, start, unlock and verify need one", prog+" policy add FILE")
	default:
		add("policies", "ok", strings.Join(good, " "), "")
	}

	// The version: the entry point has no command that names one.
	add("version", "ok", prog+" "+version+" (the entry point reports no version to compare it with)", "")

	rep.OK = true
	for _, ch := range rep.Checks {
		rep.OK = rep.OK && ch.Status != "fail"
	}
	return rep
}

// oneLine is the first line of s.
func oneLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

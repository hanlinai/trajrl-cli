package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/cli/keycmd"
	"github.com/hanlinai/trajrl-cli/internal/cli/verifycmd"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// verifyCmd is "verify NAME [-owner] [--json]": sbxverify, with the entry
// point, your key and the policies from trajrl's configuration. "verify
// --all" runs it again for every running sandbox of "ls --json" and fails
// if any one does.
func verifyCmd(args []string) int {
	var rest []string
	all := false
	for _, a := range args[1:] {
		if a == "--all" || a == "-all" {
			all = true
			continue
		}
		rest = append(rest, a)
	}
	c := loadConfigOrEmpty()
	if all {
		return verifyAll(c, rest)
	}
	pols, err := policies()
	if err != nil {
		return fail(1, "%v", err)
	}
	id, _ := c.identityFile()
	verifycmd.MainWith(rest, verifycmd.Options{Prog: prog, Entry: c.Entry, EntryKey: c.EntryKey, Identity: id,
		Policies: pols, NoPolicy: noPolicy(), ArgsAfterName: true, OwnerDir: keycmd.DefaultDir()})
	return 0
}

func verifyAll(c *config, rest []string) int {
	owner, pass := false, false
	for _, a := range rest {
		switch {
		case a == "-owner" || a == "--owner" || strings.HasPrefix(a, "-owner-key") || strings.HasPrefix(a, "--owner-key"):
			owner = true
		case strings.HasPrefix(a, "-passphrase-file") || strings.HasPrefix(a, "--passphrase-file"):
			pass = true
		}
	}
	if owner && !pass && os.Getenv(ownerkey.PassphraseFileEnv) == "" {
		// Each sandbox's check is a process of its own: it asks for no
		// passphrase (exit status 3, as with no terminal).
		return fail(clierr.NeedsOwner, "verify --all -owner asks for no passphrase: give -passphrase-file FILE or %s", ownerkey.PassphraseFileEnv)
	}
	out, err := entryOutput(c, "ls", "--json")
	if err != nil {
		return fail(255, "%v", err)
	}
	var list []struct {
		Name  string `json:"name"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return fail(255, "ls --json: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		return fail(255, "%v", err)
	}
	var failed []string
	n := 0
	for _, v := range list {
		if v.State != "running" {
			continue
		}
		n++
		cmd := exec.Command(self, append([]string{"verify", v.Name}, rest...)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				return fail(255, "%v", err)
			}
			failed = append(failed, v.Name)
		}
	}
	if len(failed) > 0 {
		return fail(1, "%d of %d running sandboxes NOT VERIFIED: %s", len(failed), n, strings.Join(failed, " "))
	}
	fmt.Fprintf(os.Stderr, "%s: %d running sandboxes, every one VERIFIED\n", prog, n)
	return 0
}

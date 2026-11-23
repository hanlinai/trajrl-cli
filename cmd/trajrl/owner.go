package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/cli/keycmd"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
	"github.com/hanlinai/trajrl-cli/internal/sshsetup"
)

// ownerState is the record of sbxkey's own directory (keycmd), where it
// is; a missing one is empty.
func ownerState() (*ownerkey.State, error) {
	d := keycmd.DefaultDir()
	return ownerkey.OpenState(filepath.Join(d, "sandboxes.json"), filepath.Join(d, "known_hosts"))
}

// verifiedHostKey is the SSH host key of the sandbox name that a check on
// this machine vouched for: sbxverify's record, or the owner's record of
// the first boot it unlocked after verifying the TD's quote. A record
// without a policy (a rehearsal's, with no quote) vouches for nothing.
func verifiedHostKey(name string) (string, error) {
	if ps, err := sbxapi.LoadPins(sbxapi.DefaultPinFile()); err == nil {
		if p, ok := ps.Sandboxes[name]; ok && p.HostKey != "" {
			return p.HostKey, nil
		}
	}
	st, err := ownerState()
	if err != nil {
		return "", err
	}
	if r := st.ByName(name); r != nil && r.SSHHostKey != "" && r.Policy != "" {
		return r.SSHHostKey, nil
	}
	return "", fmt.Errorf("no host key of %s was verified on this machine: run %s verify %s first", name, prog, name)
}

// rehearsalHostKey is set only in a binary built with the tag "rehearsal"
// (rehearsal.go): a host key of name that nothing attested, where no
// verified one is on record, or "".
var rehearsalHostKey func(name string) string

// sshCmd is "ssh NAME [-- ARGS...]": the system's ssh to root@NAME.DOMAIN
// through the entry point (by trajrl proxy, as in the lines setup
// installed), accepting only the host key verified here, or for a
// colleague's sandbox shared with you (NAME-OWNER), the one its owner gave
// you (known-hosts --import, shared.go).
func sshCmd(args []string) int {
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return fail(2, "usage: %s ssh NAME [-- ARGS...]", prog)
	}
	name, rest := args[1], args[2:]
	if len(rest) > 0 {
		if rest[0] != "--" {
			return fail(2, "usage: %s ssh NAME [-- ARGS...]", prog)
		}
		rest = rest[1:]
	}
	if !ownerkey.ValidName(name) {
		return fail(2, "%q is not a sandbox name", name)
	}
	c, err := loadConfig()
	if err != nil {
		return fail(255, "%v", err)
	}
	code, err := sandboxSSH(c, name, nil, rest, os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		return fail(255, "%v", err)
	}
	return code
}

// sandboxSSH runs the system's ssh to root@NAME.DOMAIN with the remote
// command remote (none: a login), the ssh options opts first, accepting
// only the host key verified here (or a shared sandbox's, given by its
// owner). An error: ssh was not run, or could not be; otherwise ssh's exit
// status.
func sandboxSSH(c *config, name string, opts, remote []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if c.Domain == "" {
		return 0, fmt.Errorf("the entry point named no domain for sandbox names: run %s setup", prog)
	}
	key, err := verifiedHostKey(name)
	if err != nil {
		if k, ok := sharedHostKey(c, name); ok {
			fmt.Fprintf(stderr, "%s: %s is a sandbox shared with you: its host key is the one its owner gave you (%s), not one verified on this machine\n", prog, name, sharedHostsPath())
			key, err = k, nil
		}
	}
	if err != nil && rehearsalHostKey != nil {
		// Only a binary built with the tag "rehearsal" gets here.
		if k := rehearsalHostKey(name); k != "" {
			key, err = k, nil
		}
	}
	if err != nil {
		return 0, err
	}
	host := name + "." + c.Domain
	line, err := ownerkey.KnownHostsLine([]string{host}, key)
	if err != nil {
		return 0, err
	}
	f, err := os.CreateTemp("", "trajrl-known-hosts-")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(line + "\n"); err != nil {
		f.Close()
		return 0, err
	}
	f.Close()
	argv := append(append([]string(nil), opts...), "-o", `UserKnownHostsFile="`+filepath.ToSlash(f.Name())+`"`, "-o", "StrictHostKeyChecking=yes")
	// Through this trajrl (trajrl proxy), whatever ssh's files say: an
	// older setup's ProxyJump lines, or none, do not stand in the way.
	if p, err := sshsetup.ProxyProgram(selfPath(), runtime.GOOS); err == nil {
		argv = append(argv, "-o", "ProxyCommand="+p+" proxy %h %p")
	}
	argv = append(argv, "root@"+host)
	cmd := exec.Command("ssh", append(argv, remote...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
}

// apiFallback is where exec and cp find the pinned key of a sandbox
// sbxverify's record does not have: the owner's record of the TD it
// unlocked, by name, and the sandbox's host name at the web router from
// "show NAME --json", whose ID must be the record's. The key is never the
// platform's (show's host_key, known-hosts): a sandbox with none on record
// is refused.
func apiFallback(c *config) func(name string) (string, string, error) {
	return func(name string) (string, string, error) {
		verify := fmt.Sprintf("run %s verify %s (it records the host key the TD vouches for)", prog, name)
		if strings.Contains(name, ".") || !ownerkey.ValidName(name) {
			return "", "", fmt.Errorf("no record of %s: name the sandbox by its name, or %s", name, verify)
		}
		st, err := ownerState()
		if err != nil {
			return "", "", err
		}
		r := st.ByName(name)
		switch {
		case r == nil:
			return "", "", fmt.Errorf("no record of %s on this machine: %s", name, verify)
		case r.SSHHostKey == "":
			return "", "", fmt.Errorf("your record has no host key of %s (its first boot was confirmed elsewhere): %s", name, verify)
		case r.Policy == "":
			return "", "", fmt.Errorf("your record of %s was made without a quote (a rehearsal): %s", name, verify)
		}
		out, err := entryOutput(c, "show", name, "--json")
		if err != nil {
			return "", "", err
		}
		var v struct {
			ID       string `json:"id"`
			HTTPSURL string `json:"https_url"`
		}
		if err := json.Unmarshal(out, &v); err != nil {
			return "", "", fmt.Errorf("show %s: %w", name, err)
		}
		if v.ID != r.ID {
			return "", "", fmt.Errorf("the platform's %s is %s, your record's is %s: %s", name, v.ID, r.ID, verify)
		}
		u, err := url.Parse(v.HTTPSURL)
		if v.HTTPSURL == "" || err != nil || u.Hostname() == "" {
			return "", "", fmt.Errorf("the platform names no https_url for %s: %s", name, verify)
		}
		return r.SSHHostKey, u.Hostname(), nil
	}
}

// waitsForKey is how exec and cp explain a sandbox's API that was not
// reached: if the platform shows name waiting for its owner's key, the
// error that says so, with exit status 3 (clierr.NeedsOwner); otherwise
// nil.
func waitsForKey(c *config) func(name string) error {
	return func(name string) error {
		if c.Entry == "" || !ownerkey.ValidName(name) {
			return nil
		}
		out, _, err := entryOutputWithin(c, 15*time.Second, "show", name, "--json")
		if err != nil {
			return nil
		}
		var v struct {
			State string `json:"state"`
		}
		if json.Unmarshal(out, &v) != nil || v.State != stateWaitingForKey {
			return nil
		}
		return clierr.With(clierr.NeedsOwner, fmt.Errorf("%s waits for its owner's key: run %s unlock %s", name, prog, name))
	}
}

// renameCmd is "rename OLD NEW". If the platform's NEW is the sandbox your
// record has as OLD (renamed at the platform already, say on the website),
// only your record follows; otherwise the platform renames it first.
func renameCmd(args []string) int {
	if len(args) != 3 {
		return fail(2, "usage: %s rename OLD NEW", prog)
	}
	old, name := args[1], args[2]
	c, err := loadConfig()
	if err != nil {
		return fail(255, "%v", err)
	}
	st, err := ownerState()
	if err != nil {
		return fail(1, "%v", err)
	}
	r := st.ByName(old)
	done := false
	if r != nil {
		if out, err := entryOutput(c, "show", name, "--json"); err == nil {
			var v struct {
				ID string `json:"id"`
			}
			done = json.Unmarshal(out, &v) == nil && v.ID == r.ID
		}
	}
	if !done {
		if code := forward(c, []string{"rename", old, name}, os.Stdin, os.Stdout, os.Stderr); code != 0 {
			return code
		}
	}
	if r == nil {
		return 0
	}
	keycmd.MainWith([]string{"rename", old, name}, keyOptions(c, false))
	return 0
}

//go:build rehearsal

// REHEARSAL ONLY. NOT FOR ANY REAL USE.
//
// Built only with the Go build tag "rehearsal" (go build -tags rehearsal
// ./cmd/sbxverify), which tests/rehearsal.sh -owner-keys and
// tests/oci-rehearsal.sh do into their work directories, never into out/bin.
// It adds -dev-insecure-rehearsal: a sandbox that is not a TD (the emulated
// rehearsal's guests) is not refused for having no quote; the image it
// names is compared with the owner's record WITHOUT ATTESTATION, and the
// result is never VERIFIED (internal/userverify/rehearsal.go). The host key
// that check's SSH session saw goes to a file of its own,
// rehearsal_known_hosts next to the record of verified keys, marked NOT
// ATTESTED on every line: trajrl ssh in a rehearsal build reads it (the
// emulated stage has no quote to verify a host key with). A normal build
// has neither the flag, nor the file, nor the code behind them
// (TestBuildTagDefaultHasNoRehearsalImage, cmd/trajrl's
// TestBuildTagDefaultHasNoRehearsal).

package verifycmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

func init() {
	rehearsalFlags = func(fs *flag.FlagSet) func() {
		on := fs.Bool("dev-insecure-rehearsal", false, "REHEARSAL ONLY: a sandbox that gives no quote is compared with your record WITHOUT ATTESTATION; never VERIFIED")
		return func() {
			if !*on {
				return
			}
			fmt.Fprintln(os.Stderr, prog+": *** -dev-insecure-rehearsal: A SANDBOX WITHOUT A QUOTE IS CHECKED WITHOUT ATTESTATION. NOT FOR ANY REAL USE ***")
			userverify.AllowUnattestedRehearsal()
		}
	}
	rehearsalRecord = func(out io.Writer, record, name, sandboxID, hostKey string) {
		file := RehearsalKnownHosts(record)
		if err := recordRehearsalHostKey(file, name, sandboxID, hostKey); err != nil {
			fmt.Fprintf(os.Stderr, "%s: the host key could not be recorded in %s: %v\n", prog, file, err)
			return
		}
		fmt.Fprintf(out, "  REHEARSAL, host key NOT attested: the key this session saw is recorded in %s (not in %s): %s\n", file, filepath.Base(record), hostKey)
	}
}

// rehearsalMark ends every line of the rehearsal's known-hosts file.
const rehearsalMark = "REHEARSAL-NOT-ATTESTED"

// RehearsalKnownHosts is the rehearsal's known-hosts file that goes with
// the record of verified keys at record: rehearsal_known_hosts beside it.
func RehearsalKnownHosts(record string) string {
	return filepath.Join(filepath.Dir(record), "rehearsal_known_hosts")
}

func recordRehearsalHostKey(file, name, sandboxID, hostKey string) error {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
	if err != nil {
		return err
	}
	if name == "" || strings.ContainsAny(name, " \t\r\n,#") {
		return fmt.Errorf("%q is not a sandbox name", name)
	}
	old, err := os.ReadFile(file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var b strings.Builder
	b.WriteString("# REHEARSAL ONLY, NOT FOR ANY REAL USE: host keys seen by trajrl verify -dev-insecure-rehearsal,\n" +
		"# of sandboxes that gave no quote. NOT ATTESTED: whatever answered was believed.\n")
	for _, l := range strings.Split(string(old), "\n") {
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") && f[0] != name {
			b.WriteString(l + "\n")
		}
	}
	fmt.Fprintf(&b, "%s %s %s %s\n", name, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), rehearsalMark, sandboxID)
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// RehearsalHostKey is the host key the rehearsal's known-hosts file has
// for the sandbox name, "type base64", or "" with none. NOT ATTESTED.
func RehearsalHostKey(file, name string) (string, error) {
	b, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || f[0] != name || f[3] != rehearsalMark {
			continue
		}
		key := f[1] + " " + f[2]
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
			return "", fmt.Errorf("%s: %s's line: %w", file, name, err)
		}
		return key, nil
	}
	return "", nil
}

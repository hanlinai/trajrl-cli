package keycmd

// trajrl new|start|unlock NAME --json (docs/cli.md, "For programs"): the
// one object a program reads on stdout after an unlock, for the Python SDK.

import (
	"encoding/json"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// BootResult is what new, start and unlock print with --json. Every field
// is always there; one that is not known is null.
type BootResult struct {
	// Name is the sandbox's name.
	Name string `json:"name"`
	// State is the sandbox's state at the platform after the unlock (show
	// NAME --json), or null if it could not be read.
	State *string `json:"state"`
	// Verified: the TD's quote was verified (Intel's signature, the TCB,
	// one of your policies, this sandbox, this session) and the disk secret
	// sent on it.
	Verified bool `json:"verified"`
	// HostKeySHA256 is the SHA256 fingerprint of the SSH host key pinned
	// for the sandbox (the one its TD reported at its first boot), as ssh
	// prints it ("SHA256:..."), or null if none is pinned.
	HostKeySHA256 *string `json:"host_key_sha256"`
	// Boot is the boot epoch confirmed: 1 at the first boot, one more at
	// every boot after it.
	Boot *uint64 `json:"boot"`
}

// bootResultOf is the result of the unlock res of name, with the state the
// platform shows (nil: unknown) and hostKey, the pinned key's line ("":
// none).
func bootResultOf(name string, state *string, res *ownerkey.Outcome, hostKey string) BootResult {
	r := BootResult{Name: name, State: state}
	if res == nil {
		return r
	}
	r.Verified = res.Released && res.Mode == proto.ModeTDX && res.Quote != nil
	if res.Epoch > 0 {
		e := res.Epoch
		r.Boot = &e
	}
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey)); err == nil {
		fp := ssh.FingerprintSHA256(k)
		r.HostKeySHA256 = &fp
	}
	return r
}

// writeBootJSON prints r as one line.
func writeBootJSON(w io.Writer, r BootResult) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

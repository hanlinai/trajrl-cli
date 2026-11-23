//go:build rehearsal

// REHEARSAL ONLY. NOT FOR ANY REAL USE.
//
// Built only with the Go build tag "rehearsal" (go build -tags rehearsal
// ./cmd/sbxkey), which tests/rehearsal.sh -owner-keys does into its work
// directory, never into out/bin. It adds -dev-insecure-rehearsal to start,
// unlock and new: a TD that offers no quote (the emulated rehearsal's
// dev-insecure guest, which is not a TD) is given its disk secret WITHOUT
// ATTESTATION. A normal build has neither the flag nor the code behind it
// (internal/ownerkey/evidence_rehearsal.go); TestBuildTagDefaultHasNoRehearsal
// checks both builds.

package keycmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

func init() {
	rehearsalUsage = `
REHEARSAL BUILD (-tags rehearsal), NOT FOR ANY REAL USE:
  -dev-insecure-rehearsal                              (start, unlock, new) give a TD that offers no quote
                                                       its disk secret WITHOUT ATTESTATION
`
	rehearsalFlags = func(fs *flag.FlagSet) func() {
		on := fs.Bool("dev-insecure-rehearsal", false, "REHEARSAL ONLY: a TD that offers no quote is given its disk secret WITHOUT ATTESTATION")
		return func() {
			if !*on {
				return
			}
			fmt.Fprintln(os.Stderr, "sbxkey: *** -dev-insecure-rehearsal: DISK SECRETS ARE SENT WITHOUT ATTESTATION. NOT FOR ANY REAL USE ***")
			ownerkey.AllowUnattestedRehearsal()
		}
	}
}

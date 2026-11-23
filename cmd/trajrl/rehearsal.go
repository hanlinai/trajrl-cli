//go:build rehearsal

// REHEARSAL ONLY. NOT FOR ANY REAL USE.
//
// Built only with the Go build tag "rehearsal" (go build -tags rehearsal
// ./cmd/trajrl), for the emulated rehearsal and the emulated stage, whose
// guests are not TDs and give no quote. A normal build has none of this
// (TestBuildTagDefaultHasNoRehearsal):
//
//   - trajrl ssh NAME, with no verified host key of NAME on record, takes
//     the one trajrl verify -dev-insecure-rehearsal saw
//     (verifycmd.RehearsalKnownHosts), or else the owner's record of a boot
//     unlocked without a quote, and says loudly that it is NOT attested;
//   - trajrl -dev-insecure-rehearsal (or trajrl tui -dev-insecure-rehearsal)
//     is the screen, whose unlock, start, new and verify then run with
//     -dev-insecure-rehearsal.

package main

import (
	"fmt"
	"os"

	"github.com/hanlinai/trajrl-cli/internal/cli/verifycmd"
	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
)

const rehearsalFlag = "-dev-insecure-rehearsal"

func init() {
	rehearsalHostKey = func(name string) string {
		file := verifycmd.RehearsalKnownHosts(sbxapi.DefaultPinFile())
		key, err := verifycmd.RehearsalHostKey(file, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		}
		from := file
		if key == "" {
			if st, err := ownerState(); err == nil {
				if r := st.ByName(name); r != nil && r.SSHHostKey != "" && r.Policy == "" {
					key, from = r.SSHHostKey, "your record of a boot unlocked without a quote"
				}
			}
		}
		if key != "" {
			fmt.Fprintf(os.Stderr, "%s: *** REHEARSAL, host key NOT attested: %s's key is the one from %s. NOT FOR ANY REAL USE ***\n", prog, name, from)
		}
		return key
	}
	rehearsalScreen = func(args []string) []string {
		switch {
		case len(args) == 1 && args[0] == rehearsalFlag:
			args = nil
		case len(args) == 2 && args[0] == "tui" && args[1] == rehearsalFlag:
			args = args[:1]
		default:
			return args
		}
		fmt.Fprintf(os.Stderr, "%s: *** %s: the screen's unlock, start, new and verify run with %s. NOT FOR ANY REAL USE ***\n", prog, rehearsalFlag, rehearsalFlag)
		screenFlags = map[string][]string{}
		for _, c := range []string{"unlock", "start", "new", "verify"} {
			screenFlags[c] = []string{rehearsalFlag}
		}
		return args
	}
}

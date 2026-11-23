//go:build rehearsal

// REHEARSAL ONLY. NOT FOR ANY REAL USE.
//
// This file exists only in a binary built with the Go build tag "rehearsal"
// (go build -tags rehearsal), which tests/rehearsal.sh -owner-keys builds
// into its work directory and nothing ships. A normal build does not
// contain it: evidence.go stands in its place, and no flag or setting there
// reaches this code (TestBuildTagDefaultHasNoRehearsal).
//
// The emulated rehearsal's guests are not TDs and have no quote: the
// dev-insecure boot (internal/guest, BootConfig.DevInsecure) offers evidence
// of mode proto.ModeDev with an empty quote. Once AllowUnattestedRehearsal
// is called, such evidence is accepted and the disk secret is released
// marked proto.ModeDev, WITHOUT ATTESTATION. Everything else of the unlock
// (the owner's record, boot epochs, first boot, host key pinning) is the
// normal one, which is what the rehearsal exercises.

package ownerkey

import (
	"errors"
	"sync/atomic"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

var unattestedRehearsal atomic.Bool

// AllowUnattestedRehearsal makes every Unlock of this process accept a TD
// that offers no quote (proto.ModeDev). REHEARSAL ONLY: it exists only in a
// binary built with the tag "rehearsal".
func AllowUnattestedRehearsal() { unattestedRehearsal.Store(true) }

func (u *Unlock) checkEvidence(ev *proto.Msg, nonce, exporter []byte) (string, *attest.Result, error) {
	if ev.Mode != proto.ModeDev || !unattestedRehearsal.Load() {
		return u.verifyQuote(ev, nonce, exporter)
	}
	// Development-mode evidence carries nothing to check; a quote with it
	// would mean that the guest and this tool disagree on the mode.
	if len(ev.Quote) != 0 {
		return "", nil, errors.New("the TD offered development-mode evidence with a quote in it")
	}
	return proto.ModeDev, nil, nil
}

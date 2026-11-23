//go:build rehearsal

// REHEARSAL ONLY. NOT FOR ANY REAL USE.
//
// This file exists only in a binary built with the Go build tag "rehearsal"
// (go build -tags rehearsal ./cmd/sbxverify), which tests/rehearsal.sh
// -owner-keys and tests/oci-rehearsal.sh build into their work directories
// and nothing ships (release/build-owner-tools.sh refuses such a binary). A
// normal build has noquote.go in its place.
//
// The emulated rehearsal's guests are not TDs and give no quote. Once
// AllowUnattestedRehearsal is called, Check goes on without one: it reads
// the image the sandbox names and compares it with the owner's record
// (Target.OwnerImage), so that the rehearsal exercises the owner's side of
// the image check (#112). NOTHING IS ATTESTED: no quote, no RTMR3, so the
// image the sandbox names is not authenticated either. The report says so
// (Report.Rehearsal), and sbxverify never prints VERIFIED for it.

package userverify

import (
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

var unattestedRehearsal atomic.Bool

// AllowUnattestedRehearsal makes Check go on, for a sandbox that is not a
// TD, without a quote. REHEARSAL ONLY.
func AllowUnattestedRehearsal() { unattestedRehearsal.Store(true) }

func noQuoteAllowed() bool { return unattestedRehearsal.Load() }

func noQuoteCheck(c *ssh.Client, t Target, rep *Report) (*Report, error) {
	rep.Rehearsal = true
	img, err := sandboxImage(c)
	if err != nil {
		return rep, err
	}
	if !proto.ValidImageMeasure(img) {
		return rep, fmt.Errorf("the sandbox names its image %.80q, which is neither %q nor a sha256 digest", img, proto.ImageBase)
	}
	rep.Image = img
	if t.OwnerImage != nil {
		if rep.ImageNote, err = t.OwnerImage(rep.SandboxID, img); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

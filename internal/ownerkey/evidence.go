//go:build !rehearsal

package ownerkey

import (
	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// checkEvidence, in every normal build, is verifyQuote and nothing else. A
// binary built with the tag "rehearsal" has evidence_rehearsal.go instead;
// this build has no code that releases a secret without a verified quote
// (TestBuildTagDefaultHasNoRehearsal checks the built binaries).
func (u *Unlock) checkEvidence(ev *proto.Msg, nonce, exporter []byte) (string, *attest.Result, error) {
	return u.verifyQuote(ev, nonce, exporter)
}

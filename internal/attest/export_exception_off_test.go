//go:build !tcbexception

package attest

import "testing"

// AnException is a TCB exception for a test to hand a verifier. This build
// cannot load one (exception_off.go); what a caller can still set is the
// empty value, and a verifier given it refuses every quote.
func AnException(*testing.T) *TCBException { return &TCBException{} }

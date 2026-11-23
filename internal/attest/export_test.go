package attest

import (
	"testing"
	"time"

	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// Exports for broker_e2e_test.go (package attest_test), which puts the real
// verifier behind a real broker. This file is compiled only into this
// package's own tests: no other package can reach these.

const (
	HWSandboxID       = hwSandboxID
	HWOtherSandboxID  = "sbx-67393a1db4989930"
	HWStrictPolicy    = "../../docs/evidence/alibaba-ebmg8i/launch-policy.json"
	HWAcceptedQuote   = hwQuote
	HWAuditedQuoteSHA = "362dd2dc0c8a64b4f4b8e5b678d228da0a2ec79ad9df91725aa0fda3260f23f2"
)

// HWVerifier is the production verifier reading Intel's recorded collateral
// at the time of the hardware run, trusting Intel's root.
func HWVerifier(t *testing.T, pol *Policy, x *TCBException) *TDX {
	return hwVerifier(t, pol, x, hwTime)
}

// StandIn is the hardware TD's quote under the stand-in PKI.
type StandIn struct{ f *fakePKI }

// NewStandIn rates the platform fully current, or, with asRated, as Intel
// really rated it (TDX module OutOfDate).
func NewStandIn(t *testing.T, asRated bool) (*StandIn, *Policy) {
	raw, pol, _ := hwPolicy(t)
	f := newFakePKI(t, raw, hwCollat, hwTime)
	if !asRated {
		f.allCurrent()
	}
	return &StandIn{f}, pol
}

func (s *StandIn) Verifier(pol *Policy, x *TCBException) *TDX {
	v := s.f.verifier(pol)
	v.Exception = x
	return v
}

// IntelRootVerifier is the same verifier (the stand-in's clock and recorded
// collateral, so no network) except that it trusts Intel's root, as the
// production verifier does, instead of the stand-in's.
func (s *StandIn) IntelRootVerifier(pol *Policy) *TDX {
	v := s.f.verifier(pol)
	v.roots = nil
	return v
}

// Quote is what the TD would be given for this REPORTDATA: the hardware TD's
// measurements and identity, the session's report data, signed by the stand-in
// quoting enclave. rtmr3 simulates a TD whose boot stage is over.
func (s *StandIn) Quote(rd [64]byte, rtmr3 []byte) []byte {
	return s.f.quote(func(q any) {
		b := q.(*pb.QuoteV4).GetTdQuoteBody()
		b.ReportData = rd[:]
		if rtmr3 != nil {
			b.Rtmrs[3] = rtmr3
		}
	})
}

func (s *StandIn) Advance(d time.Duration) { s.f.now = s.f.now.Add(d) }

package attest

import (
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// Exports for custodian_e2e_test.go (package attest_test), which puts the
// real verifier behind the custodians' tool. Like export_test.go, this file
// is compiled only into this package's own tests.

// BrokerQuote is the quote of a TD that is nobody's sandbox: the hardware
// TD's measurements, MRCONFIGID zero (the hardware TD was launched for a
// sandbox; a broker is not), the given REPORTDATA, signed by the stand-in
// quoting enclave. edit, if given, changes the body before it is signed:
// another image, a register extended, a debug TD.
func (s *StandIn) BrokerQuote(rd [64]byte, edit func(body *pb.TDQuoteBody)) []byte {
	return s.f.quote(func(q any) {
		b := q.(*pb.QuoteV4).GetTdQuoteBody()
		b.ReportData = rd[:]
		b.MrConfigId = make([]byte, 48)
		if edit != nil {
			edit(b)
		}
	})
}

// Rate changes how the stand-in's collateral rates one of "platform",
// "module" (the TDX module) or "qe" (the quoting enclave), at every level.
func (s *StandIn) Rate(what, status string) {
	switch what {
	case "platform":
		setStatus(levels(s.f.tcbInfo), status)
	case "module":
		setStatus(levels(s.f.module()), status)
	case "qe":
		setStatus(levels(s.f.qeIdentity), status)
	default:
		s.f.t.Fatalf("Rate(%q)", what)
	}
}

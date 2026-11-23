package attest

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/testing/testdata"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// Fixtures, all carrying genuine Intel signatures:
//
//   - testdata.RawQuote, testdata.RawQuoteV5: go-tdx-guest's samples (Sapphire
//     Rapids). Not from this prototype's TD.
//   - testdata/alibaba-g8i-quote-v5*.bin: taken on 2026-11-10 from a TD run by
//     Alibaba Cloud (ecs.g8i.xlarge) through this prototype's own TDREPORT and
//     configfs-tsm code. MRSERVICETD is non-zero. Not a TD this prototype
//     launched.
//   - the hardware TD's own quote: see tcb_test.go.
//
// The verifier has no mode without Intel's collateral, so the tests in this
// file that are about launch policy call checkPolicy directly: they say
// nothing about authenticity. Authenticity and TCB are tested in tcb_test.go
// (Intel's root, recorded collateral) and rejection_test.go (stand-in PKI).

const anySandbox = "sbx-0000000000000001"

// sampleV4 is testdata.RawQuote without the 39 non-zero bytes that follow the
// signed quote in the library's sample file. The verifier refuses the file as
// shipped (see TestBytesAfterTheQuoteRefused).
var sampleV4 = testdata.RawQuote[:len(testdata.RawQuote)-39]

// Bytes after the signed quote are covered by no signature. Zero padding is
// tolerated because quote generation services add it; anything else is refused
// before any other check.
func TestBytesAfterTheQuoteRefused(t *testing.T) {
	q, err := abi.QuoteToProto(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := supported(q); err == nil || !strings.Contains(err.Error(), "not zero padding") {
		t.Fatalf("the sample quote with 39 unsigned non-zero bytes after it was accepted: %v", err)
	}
	if _, _, err := supported(mustProto(t, sampleV4)); err != nil {
		t.Fatalf("the same quote without them: %v", err)
	}
	hw, pol, rd := hwPolicy(t)
	if n := len(mustProto(t, hw).(*pb.QuoteV4).GetExtraBytes()); n != 70 {
		t.Fatalf("hardware quote has %d padding bytes, expected the 70 zeros QGS appends", n)
	}
	junk := append(append([]byte(nil), hw...), 0x01)
	if _, err := hwVerifier(t, pol, nil, hwTime).Verify(context.Background(), junk, rd, hwSandboxID); err == nil || !strings.Contains(err.Error(), "malformed quote") {
		t.Fatalf("hardware quote with one extra non-zero byte was not refused as malformed: %v", err)
	}
}

func mustProto(t *testing.T, raw []byte) any {
	t.Helper()
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func parse(t *testing.T, raw []byte) (any, tdBody) {
	t.Helper()
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := supported(q)
	if err != nil {
		t.Fatal(err)
	}
	return q, b
}

// exactPolicy is the policy that describes the quote exactly, naming no
// service TD and not binding MRCONFIGID.
func exactPolicy(t *testing.T, raw []byte) *Policy {
	_, b := parse(t, raw)
	h := hex.EncodeToString
	return &Policy{MRTD: h(b.GetMrTd()), RTMR0: h(b.GetRtmrs()[0]), RTMR1: h(b.GetRtmrs()[1]), RTMR2: h(b.GetRtmrs()[2]),
		TDAttributes: h(b.GetTdAttributes()), XFAM: h(b.GetXfam())}
}

func reportDataOf(t *testing.T, raw []byte) [64]byte {
	_, b := parse(t, raw)
	return [64]byte(b.GetReportData())
}

// policyVerdict applies the launch policy alone to a quote.
func policyVerdict(t *testing.T, raw []byte, pol *Policy, rd [64]byte, sandbox string) error {
	t.Helper()
	pb, err := pol.decode()
	if err != nil {
		t.Fatal(err)
	}
	q, body := parse(t, raw)
	return checkPolicy(q, body, pb, pol.BindMRConfigID, rd, sandbox, make([]byte, 48))
}

func flipHex(s string) string {
	b, _ := hex.DecodeString(s)
	b[len(b)-1] ^= 0x80
	return hex.EncodeToString(b)
}

func TestExactPolicyMatches(t *testing.T) {
	for name, raw := range map[string][]byte{"v4": sampleV4, "v5": testdata.RawQuoteV5} {
		if err := policyVerdict(t, raw, exactPolicy(t, raw), reportDataOf(t, raw), anySandbox); err != nil {
			t.Errorf("%s: the policy describing the quote exactly does not match it: %v", name, err)
		}
	}
}

func TestPolicyMismatchRejected(t *testing.T) {
	cases := map[string]func(*Policy){
		"mrtd":   func(p *Policy) { p.MRTD = flipHex(p.MRTD) },
		"rtmr0":  func(p *Policy) { p.RTMR0 = flipHex(p.RTMR0) },
		"rtmr1":  func(p *Policy) { p.RTMR1 = flipHex(p.RTMR1) },
		"rtmr2":  func(p *Policy) { p.RTMR2 = flipHex(p.RTMR2) },
		"xfam":   func(p *Policy) { p.XFAM = flipHex(p.XFAM) },
		"attrs":  func(p *Policy) { p.TDAttributes = flipHex(p.TDAttributes) },
		"mrseam": func(p *Policy) { p.MRSeam = strings.Repeat("ab", 48) },
		// The sample TDs were launched with MRCONFIGID = 0, so they are not
		// bound to any sandbox.
		"mrconfigid": func(p *Policy) { p.BindMRConfigID = true },
		// The policy expects a service TD; the v5 sample TD has none. (v4
		// bodies have no such field.)
		"mr_service_td": func(p *Policy) { p.MRServiceTD = strings.Repeat("ab", 48) },
	}
	for ver, raw := range map[string][]byte{"v4": sampleV4, "v5": testdata.RawQuoteV5} {
		for name, mutate := range cases {
			if ver == "v4" && name == "mr_service_td" {
				continue
			}
			t.Run(ver+"/"+name, func(t *testing.T) {
				pol := exactPolicy(t, raw)
				mutate(pol)
				if err := policyVerdict(t, raw, pol, reportDataOf(t, raw), anySandbox); err == nil {
					t.Fatal("mismatch not rejected")
				}
			})
		}
	}
}

func TestWrongReportDataRejected(t *testing.T) {
	for ver, raw := range map[string][]byte{"v4": sampleV4, "v5": testdata.RawQuoteV5} {
		rd := reportDataOf(t, raw)
		rd[63] ^= 1
		if err := policyVerdict(t, raw, exactPolicy(t, raw), rd, anySandbox); err == nil || !strings.Contains(err.Error(), "REPORT_DATA") {
			t.Errorf("%s: quote accepted for a REPORTDATA it does not carry: %v", ver, err)
		}
	}
}

func TestDebugPolicyRefused(t *testing.T) {
	pol := exactPolicy(t, sampleV4)
	pol.TDAttributes = "0100000000000000"
	if _, err := pol.decode(); err == nil {
		t.Fatal("policy permitting a DEBUG TD was accepted")
	}
}

func TestIncompletePolicyRefused(t *testing.T) {
	for _, drop := range []func(*Policy){
		func(p *Policy) { p.MRTD = "" }, func(p *Policy) { p.RTMR0 = "" }, func(p *Policy) { p.RTMR1 = "" },
		func(p *Policy) { p.RTMR2 = "" }, func(p *Policy) { p.TDAttributes = "" }, func(p *Policy) { p.XFAM = "" },
	} {
		pol := exactPolicy(t, sampleV4)
		drop(pol)
		if _, err := pol.decode(); err == nil {
			t.Fatal("policy with an unset reference value was accepted")
		}
	}
}

func alibabaQuote(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/alibaba-g8i-quote-v5.bin")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func v5Body(t *testing.T, raw []byte) *pb.TDQuoteBodyV5 {
	t.Helper()
	q, _ := parse(t, raw)
	v5, ok := q.(*pb.QuoteV5)
	if !ok || v5.GetTdQuoteBodyDescriptor().GetTdQuoteBodyType() != bodyTDX15 {
		t.Fatalf("fixture is not a v5 quote with a TDX 1.5 body: %T", q)
	}
	return v5.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
}

// A TD with a service TD bound to it (here: whatever Alibaba Cloud binds) must
// be refused unless the policy names that binding.
func TestBoundServiceTDRefusedUnlessNamed(t *testing.T) {
	raw := alibabaQuote(t)
	b := v5Body(t, raw)
	if bytes.Equal(b.GetMrServiceTd(), make([]byte, 48)) {
		t.Fatal("fixture has no service TD bound")
	}
	pol := exactPolicy(t, raw)
	err := policyVerdict(t, raw, pol, reportDataOf(t, raw), anySandbox)
	if err == nil || !strings.Contains(err.Error(), "MR_SERVICE_TD") {
		t.Fatalf("TD with a bound service TD was not refused on MR_SERVICE_TD: %v", err)
	}
	pol.MRServiceTD = hex.EncodeToString(b.GetMrServiceTd())
	if err := policyVerdict(t, raw, pol, reportDataOf(t, raw), anySandbox); err != nil {
		t.Fatalf("policy naming the service TD still refused: %v", err)
	}
}

// The second Alibaba fixture is the same TD after this prototype's
// guest.ExtendRTMR3 ran in it: the quote a workload would get once the boot
// stage has closed the attestation window. It must not unlock anything.
func TestQuoteAfterBootStageRefused(t *testing.T) {
	raw, err := os.ReadFile("testdata/alibaba-g8i-quote-v5-rtmr3-extended.bin")
	if err != nil {
		t.Fatal(err)
	}
	b := v5Body(t, raw)
	before := v5Body(t, alibabaQuote(t))
	for i := 0; i < 3; i++ {
		if !bytes.Equal(b.GetRtmrs()[i], before.GetRtmrs()[i]) {
			t.Fatalf("fixtures differ in RTMR%d; they must differ in RTMR3 only", i)
		}
	}
	// One extension of an all-zero register: SHA-384(0^48 || digest).
	done := proto.RTMR3BootDone()
	want := sha512.Sum384(append(make([]byte, 48), done[:]...))
	if !bytes.Equal(b.GetRtmrs()[3], want[:]) {
		t.Fatalf("RTMR3 = %x, want %x", b.GetRtmrs()[3], want)
	}
	pol := exactPolicy(t, raw)
	pol.MRServiceTD = hex.EncodeToString(b.GetMrServiceTd())
	err = policyVerdict(t, raw, pol, reportDataOf(t, raw), anySandbox)
	if err == nil || !strings.Contains(err.Error(), "RTMR") {
		t.Fatalf("quote taken after the boot stage was not refused on RTMR3: %v", err)
	}
}

// --- Intel's signatures, verified against Intel's root ---

// A quote Intel's quoting enclave signed, with one bit changed anywhere in
// what is signed, fails signature verification. The policy follows the change,
// so nothing but the signature can object.
func TestTamperedGenuineQuoteRejected(t *testing.T) {
	genuine, _, _ := hwPolicy(t)
	// Offsets in a v4 quote: 48-byte header, then the TD quote body; MRTD sits
	// at body+136, REPORTDATA at body+520. The last case is in the signature.
	for name, off := range map[string]int{"mrtd": 48 + 136, "report_data": 48 + 520, "signature": 48 + 584 + 4 + 10} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), genuine...)
			raw[off] ^= 0x01
			pol := exactPolicy(t, raw)
			pol.BindMRConfigID = true
			_, err := hwVerifier(t, pol, nil, hwTime).Verify(context.Background(), raw, reportDataOf(t, raw), hwSandboxID)
			if err == nil || !strings.Contains(err.Error(), "authenticity/TCB") || strings.Contains(err.Error(), "TDX module TCB") {
				t.Fatalf("tampered quote not rejected by signature verification: %v", err)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// Intel's certificates and collateral have validity periods; outside them the
// same quote is refused.
func TestGenuineQuoteOutsideValidityRejected(t *testing.T) {
	raw, pol, rd := hwPolicy(t)
	for name, at := range map[string]time.Time{
		"a month after the collateral's nextUpdate": time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC),
		"after the PCK certificate expired":         time.Date(2053, 7, 1, 0, 0, 0, 0, time.UTC),
		"before the PCK certificate was issued":     time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		// The TDX module level would refuse too, but only after these checks:
		// a refusal that names it means they did not refuse.
		_, err := hwVerifier(t, pol, nil, at).Verify(context.Background(), raw, rd, hwSandboxID)
		if err == nil || !strings.Contains(err.Error(), "authenticity/TCB") || strings.Contains(err.Error(), "TDX module TCB") {
			t.Errorf("%s: not refused on validity: %v", name, err)
		}
	}
}

// Without Intel's collateral there is no verdict: each fetch failing refuses.
func TestGenuineQuoteWithoutCollateralRefused(t *testing.T) {
	raw, pol, rd := hwPolicy(t)
	for _, part := range []string{"/tcb?fmspc=", "/qe/identity", "pckcrl", "IntelSGXRootCA"} {
		v := hwVerifier(t, pol, nil, hwTime)
		g := v.getter.(*replayGetter)
		asked := false
		g.fail = func(url string) error {
			if strings.Contains(url, part) {
				asked = true
				return os.ErrDeadlineExceeded
			}
			return nil
		}
		_, err := v.Verify(context.Background(), raw, rd, hwSandboxID)
		if !asked {
			t.Errorf("%s was never requested", part)
		}
		if err == nil || !strings.Contains(err.Error(), "authenticity/TCB") {
			t.Errorf("quote accepted although %s could not be fetched: %v", part, err)
		}
	}
}

// --- live Intel PCS ---

// TestStrictOnline runs the production verifier, untouched, against Intel PCS.
// Every fixture is from a platform Intel rates out of date, so the correct
// outcome is a refusal from the TCB evaluation, i.e. after the chain, CRLs and
// signatures passed. Skipped unless TDX_TEST_ONLINE is set.
func TestStrictOnline(t *testing.T) {
	if os.Getenv("TDX_TEST_ONLINE") == "" {
		t.Skip("set TDX_TEST_ONLINE=1 to query Intel PCS")
	}
	hw, _, _ := hwPolicy(t)
	for name, raw := range map[string][]byte{"go-tdx-guest sample": sampleV4, "Alibaba g8i guest": alibabaQuote(t), "hardware TD": hw} {
		t.Run(name, func(t *testing.T) {
			pol := exactPolicy(t, raw)
			if q, _ := parse(t, raw); q != nil {
				if v5, ok := q.(*pb.QuoteV5); ok {
					pol.MRServiceTD = hex.EncodeToString(v5.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5().GetMrServiceTd())
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			res, err := (&TDX{Policy: pol}).Verify(ctx, raw, reportDataOf(t, raw), anySandbox)
			if err == nil {
				t.Fatal("a platform Intel rates out of date passed the production verifier")
			}
			t.Logf("refused: %v", err)
			if !strings.Contains(err.Error(), "authenticity/TCB") || !strings.Contains(strings.ToLower(err.Error()), "tcb") {
				t.Errorf("refusal did not come from TCB evaluation: %v", err)
			}
			_ = res
		})
	}
}

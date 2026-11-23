package attest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/google/go-tdx-guest/proto/tdx"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// The rejection matrix. Every row is one condition under which the verifier
// must not return a verdict that releases a key, the stage that must refuse,
// and a fragment of the reason. Rows marked "control" must be accepted; they
// show that the rows around them are refused for the stated reason and not
// because the harness is broken.
//
// The quotes are this prototype's own hardware TD quote (v4) and the Alibaba
// guest quote (v5, TDX 1.5 body), re-signed under the stand-in PKI of
// fakepki_test.go so that conditions Intel's real PKI never hands out can be
// produced. Rows that need nothing of the kind are also tested against
// Intel's root in attest_test.go and tcb_test.go.

const (
	stMalformed = "malformed quote"
	stAuth      = "quote authenticity/TCB"
	stPolicy    = "quote policy"
	stAccept    = ""
)

type rcase struct {
	f       *fakePKI
	pol     *Policy
	rd      [64]byte
	sandbox string
	mut     func(q any)         // edits the quote before it is signed
	post    func([]byte) []byte // edits the signed quote
	ver     func(*TDX)          // edits the verifier
	at      func(time.Time) time.Time
}

type row struct {
	name  string
	setup func(*rcase)
	stage string
	want  string
}

func v4body(q any) *pb.TDQuoteBody { return q.(*pb.QuoteV4).GetTdQuoteBody() }

func flipAt(off int) func([]byte) []byte {
	return func(b []byte) []byte { b[off] ^= 0x01; return b }
}

func (c *rcase) body(f func(*pb.TDQuoteBody)) { c.mut = func(q any) { f(v4body(q)) } }

func failOn(part string) func(string) error {
	return func(u string) error {
		if strings.Contains(u, part) {
			return errors.New("collateral service unreachable")
		}
		return nil
	}
}

func spaceIn(part string) func(string, []byte) []byte {
	// One space inserted inside the signed JSON: same meaning, other bytes.
	return func(u string, body []byte) []byte {
		if strings.Contains(u, part) {
			return []byte(strings.Replace(string(body), `"id":`, `"id": `, 1))
		}
		return body
	}
}

func runRows(t *testing.T, rows []row, newCase func(t *testing.T) *rcase) {
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.name] {
			t.Fatalf("duplicate row %q", r.name)
		}
		seen[r.name] = true
		t.Run(r.name, func(t *testing.T) {
			c := newCase(t)
			if r.setup != nil {
				r.setup(c)
			}
			raw := c.f.quote(c.mut)
			if c.post != nil {
				raw = c.post(raw)
			}
			v := c.f.verifier(c.pol)
			if c.at != nil {
				at := c.at(c.f.now)
				v.now = func() time.Time { return at }
			}
			if c.ver != nil {
				c.ver(v)
			}
			res, err := v.Verify(context.Background(), raw, c.rd, c.sandbox)
			if r.stage == stAccept {
				if err != nil {
					t.Fatalf("control refused: %v", err)
				}
				t.Logf("ACCEPTED (control)%s", map[bool]string{true: " under: " + res.TCBException}[res.TCBException != ""])
				return
			}
			if err == nil {
				t.Fatalf("ACCEPTED; must be refused at %q", r.stage)
			}
			if !strings.HasPrefix(err.Error(), r.stage) {
				t.Fatalf("refused at the wrong stage (want %q): %v", r.stage, err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(r.want)) {
				t.Fatalf("refused for another reason (want %q): %v", r.want, err)
			}
			// A refusal on TCB grounds must not read as if an exception had
			// applied. (A refusal on policy after the TCB stage passed under
			// an exception does carry it: the audit entry then shows both.)
			if r.stage != stPolicy && res != nil && res.TCBException != "" {
				t.Errorf("a refusal claims an exception: %q", res.TCBException)
			}
			msg := err.Error()
			if len(msg) > 230 {
				msg = msg[:230] + "…"
			}
			t.Logf("refused: %s", msg)
		})
	}
}

// hwCase: the hardware TD's quote on a platform rated fully current.
func hwCase(t *testing.T) *rcase {
	raw, pol, rd := hwPolicy(t)
	return &rcase{f: newFakePKI(t, raw, hwCollat, hwTime).allCurrent(), pol: pol, rd: rd, sandbox: hwSandboxID}
}

func TestRejectionMatrix(t *testing.T) {
	const qeReport = 48 + 584 + 4 + 64 + 64 + 6 // offset of the QE report in a v4 quote
	statuses := []string{"OutOfDate", "OutOfDateConfigurationNeeded", "ConfigurationNeeded", "SWHardeningNeeded",
		"ConfigurationAndSWHardeningNeeded", "Revoked", "NotAStatusIntelPublishes"}

	rows := []row{
		{"control: current platform, matching policy, right sandbox and session", nil, stAccept, ""},

		// --- the quote is not a well-formed quote ---
		{"empty evidence", func(c *rcase) { c.post = func([]byte) []byte { return nil } }, stMalformed, ""},
		{"truncated to 100 bytes", func(c *rcase) { c.post = func(b []byte) []byte { return b[:100] } }, stMalformed, ""},
		{"truncated to header and body, no signature", func(c *rcase) { c.post = func(b []byte) []byte { return b[:48+584] } }, stMalformed, ""},
		// The quote ends in 70 bytes of zero padding; one byte more cuts into
		// the certificate chain.
		{"last byte of the signed data missing", func(c *rcase) { c.post = func(b []byte) []byte { return b[:len(b)-71] } }, stMalformed, ""},
		{"one non-zero byte appended", func(c *rcase) { c.post = func(b []byte) []byte { return append(b, 0x5a) } }, stMalformed, "not zero padding"},
		{"quote version 3", func(c *rcase) { c.post = func(b []byte) []byte { b[0] = 3; return b } }, stMalformed, ""},
		{"quote version 6", func(c *rcase) { c.post = func(b []byte) []byte { b[0] = 6; return b } }, stMalformed, ""},
		{"attestation key type not ECDSA-256", func(c *rcase) { c.post = func(b []byte) []byte { b[2] = 3; return b } }, stMalformed, ""},
		{"TEE type not TDX", func(c *rcase) { c.post = func(b []byte) []byte { b[4] = 0; return b } }, stMalformed, ""},

		// --- the quote is not what a genuine quoting enclave signed ---
		{"one bit of MRTD changed after signing", func(c *rcase) { c.post = flipAt(48 + 136) }, stAuth, "signature"},
		{"one bit of REPORTDATA changed after signing", func(c *rcase) { c.post = flipAt(48 + 520) }, stAuth, "signature"},
		{"one bit of the quote signature changed", func(c *rcase) { c.post = flipAt(48 + 584 + 4 + 10) }, stAuth, "signature"},
		{"one bit of the QE report changed", func(c *rcase) { c.post = flipAt(qeReport + 100) }, stAuth, ""},
		{"attestation key the QE report does not vouch for", func(c *rcase) { c.f.detachAttKey = true }, stAuth, ""},
		{"PCK chain from a root the verifier does not trust", func(c *rcase) {
			other := newFakePKI(c.f.t, c.f.genuine, hwCollat, hwTime)
			c.ver = func(v *TDX) { p := x509.NewCertPool(); p.AddCert(other.root); v.roots = p }
		}, stAuth, "certificate"},
		{"stand-in PKI presented to a verifier that trusts Intel's root", func(c *rcase) {
			c.ver = func(v *TDX) { v.roots = nil }
		}, stAuth, "certificate"},
		{"PCK certificate expired", func(c *rcase) {
			c.at = func(now time.Time) time.Time { return now.AddDate(6, 0, 0) }
		}, stAuth, ""},
		{"PCK certificate not yet valid", func(c *rcase) {
			c.at = func(now time.Time) time.Time { return now.AddDate(-2, 0, 0) }
		}, stAuth, ""},

		// --- revocation ---
		{"PCK certificate revoked", func(c *rcase) { c.f.pckRevoked = []*big.Int{c.f.pck.SerialNumber} }, stAuth, "revoked"},
		{"PCK platform CA revoked", func(c *rcase) { c.f.rootRevoked = []*big.Int{c.f.inter.SerialNumber} }, stAuth, "revoked"},
		{"TCB signing certificate revoked", func(c *rcase) { c.f.rootRevoked = []*big.Int{c.f.tcbCert.SerialNumber} }, stAuth, "revoked"},
		{"control: an unrelated serial on both CRLs", func(c *rcase) {
			c.f.pckRevoked, c.f.rootRevoked = []*big.Int{big.NewInt(999)}, []*big.Int{big.NewInt(998)}
		}, stAccept, ""},
		{"PCK CRL expired", func(c *rcase) { c.f.pckCRLNext = c.f.now.Add(-time.Minute) }, stAuth, "expired"},
		{"root CA CRL expired", func(c *rcase) { c.f.rootCRLNext = c.f.now.Add(-time.Minute) }, stAuth, "expired"},
		{"PCK CRL not signed by the PCK CA", func(c *rcase) { c.f.pckCRLKey = newKey(c.f.t) }, stAuth, "CRL"},

		// --- collateral missing, stale or not Intel's ---
		{"TCB info cannot be fetched", func(c *rcase) { c.f.fail = failOn("/tcb?fmspc=") }, stAuth, "unreachable"},
		{"QE identity cannot be fetched", func(c *rcase) { c.f.fail = failOn("/qe/identity") }, stAuth, "unreachable"},
		{"PCK CRL cannot be fetched", func(c *rcase) { c.f.fail = failOn("pckcrl") }, stAuth, "unreachable"},
		{"root CA CRL cannot be fetched", func(c *rcase) { c.f.fail = failOn("IntelSGXRootCA") }, stAuth, "unreachable"},
		{"TCB info past its nextUpdate", func(c *rcase) { c.f.tcbInfo["nextUpdate"] = "2026-11-10T12:00:00Z" }, stAuth, "expired"},
		{"QE identity past its nextUpdate", func(c *rcase) { c.f.qeIdentity["nextUpdate"] = "2026-11-10T12:00:00Z" }, stAuth, "expired"},
		{"TCB info altered after it was signed", func(c *rcase) { c.f.tamper = spaceIn("/tcb?fmspc=") }, stAuth, "tcb"},
		{"QE identity altered after it was signed", func(c *rcase) { c.f.tamper = spaceIn("/qe/identity") }, stAuth, ""},
		{"TCB info for another platform family", func(c *rcase) { c.f.tcbInfo["fmspc"] = "00806F050000" }, stAuth, "fmspc"},
		{"TCB info for another PCE", func(c *rcase) { c.f.tcbInfo["pceId"] = "FFFF" }, stAuth, "pce"},
		{"TCB info that is SGX's, not TDX's", func(c *rcase) { c.f.tcbInfo["id"] = "SGX" }, stAuth, ""},
		{"TCB info with no level this platform meets", func(c *rcase) {
			for _, l := range levels(c.f.tcbInfo) {
				for _, comp := range l.(map[string]any)["tcb"].(map[string]any)["sgxtcbcomponents"].([]any) {
					comp.(map[string]any)["svn"] = 255
				}
			}
		}, stAuth, ""},

		// --- quoting enclave ---
		{"quoting enclave TCB OutOfDate", func(c *rcase) { setStatus(levels(c.f.qeIdentity), "OutOfDate") }, stAuth, "OutOfDate"},
		{"quoting enclave TCB Revoked", func(c *rcase) { setStatus(levels(c.f.qeIdentity), "Revoked") }, stAuth, "Revoked"},
		{"quoting enclave is not the one Intel's identity names", func(c *rcase) {
			c.f.qeIdentity["mrsigner"] = strings.Repeat("00", 32)
		}, stAuth, "mrsigner"},

		// --- TDX module identity ---
		{"collateral has no identity for this TDX module version", func(c *rcase) {
			c.f.module()["id"] = "TDX_7F"
		}, stAuth, "TDX module identity"},
		{"TDX module signer is not the identity's (per-version entry)", func(c *rcase) {
			c.f.module()["mrsigner"] = strings.Repeat("11", 48)
		}, stAuth, "MRSIGNERSEAM"},
		{"TDX module attributes are not the identity's (per-version entry)", func(c *rcase) {
			c.f.module()["attributes"] = "0000000000000001"
		}, stAuth, "SEAMATTRIBUTES"},
		{"TDX module signer is not Intel's (top-level entry)", func(c *rcase) {
			c.f.tcbInfo["tdxModule"].(map[string]any)["mrsigner"] = strings.Repeat("11", 48)
		}, stAuth, "MRSIGNERSEAM"},

		// --- launch policy, identity and session (on an authentic quote) ---
		{"DEBUG TD", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.TdAttributes[0] |= 1 }) }, stPolicy, "DEBUG"},
		{"TD attributes differ from the policy", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.TdAttributes[3] ^= 0x10 }) }, stPolicy, "TD_ATTRIBUTES"},
		{"XFAM differs from the policy", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.Xfam[1] ^= 0x04 }) }, stPolicy, "XFAM"},
		{"MRTD differs (other firmware)", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.MrTd[0] ^= 1 }) }, stPolicy, "MR_TD"},
		{"RTMR0 differs (other VM shape)", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.Rtmrs[0][0] ^= 1 }) }, stPolicy, "RTMR"},
		{"RTMR1 differs (other UKI)", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.Rtmrs[1][0] ^= 1 }) }, stPolicy, "RTMR"},
		{"RTMR2 differs (other kernel, initrd or command line)", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.Rtmrs[2][0] ^= 1 }) }, stPolicy, "RTMR"},
		{"RTMR3 not zero (boot stage already over)", func(c *rcase) {
			c.body(func(b *pb.TDQuoteBody) { d := proto.RTMR3BootDone(); b.Rtmrs[3] = d[:] })
		}, stPolicy, "RTMR"},
		{"MRCONFIGID zero (TD created without a sandbox identity)", func(c *rcase) {
			c.body(func(b *pb.TDQuoteBody) { b.MrConfigId = make([]byte, 48) })
		}, stPolicy, "MR_CONFIG_ID"},
		{"MRCONFIGID of another sandbox", func(c *rcase) {
			c.body(func(b *pb.TDQuoteBody) { id := proto.MRConfigID("sbx-67393a1db4989930"); b.MrConfigId = id[:] })
		}, stPolicy, "MR_CONFIG_ID"},
		{"quote of this sandbox presented for another sandbox", func(c *rcase) { c.sandbox = "sbx-67393a1db4989930" }, stPolicy, "MR_CONFIG_ID"},
		{"MROWNER set", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.MrOwner[0] = 1 }) }, stPolicy, "MR_OWNER"},
		{"MROWNERCONFIG set", func(c *rcase) { c.body(func(b *pb.TDQuoteBody) { b.MrOwnerConfig[0] = 1 }) }, stPolicy, "MR_OWNER_CONFIG"},
		{"REPORTDATA of another session or nonce", func(c *rcase) { c.rd[0] ^= 1 }, stPolicy, "REPORT_DATA"},
		{"quoting enclave vendor is not Intel", func(c *rcase) {
			c.mut = func(q any) { q.(*pb.QuoteV4).GetHeader().QeVendorId[0] ^= 1 }
		}, stPolicy, "QE_VENDOR_ID"},
		{"policy pins another TDX module build (MRSEAM)", func(c *rcase) { p := *c.pol; p.MRSeam = strings.Repeat("ab", 48); c.pol = &p }, stPolicy, "MR_SEAM"},
	}
	// --- platform TCB level: anything but UpToDate ---
	for _, s := range statuses {
		rows = append(rows, row{"platform TCB " + s, func(c *rcase) { setStatus(levels(c.f.tcbInfo), s) }, stAuth, ""})
	}
	// --- TDX module TCB level: anything but UpToDate ---
	for _, s := range statuses {
		rows = append(rows, row{"TDX module TCB " + s, func(c *rcase) { setStatus(levels(c.f.module()), s) }, stAuth, ""})
	}
	runRows(t, rows, hwCase)
}

// Version 5 quotes with a TDX 1.5 body. The library refuses an out-of-date
// TDX module for these only in one special case; the verifier must refuse it
// always.
func TestRejectionMatrixV5(t *testing.T) {
	newCase := func(t *testing.T) *rcase {
		raw, err := os.ReadFile("testdata/alibaba-g8i-quote-v5.bin")
		if err != nil {
			t.Fatal(err)
		}
		pol := exactPolicy(t, raw)
		pol.MRServiceTD = v5ServiceTD(t, raw)
		return &rcase{f: newFakePKI(t, raw, hwCollat, hwTime).anyPlatform(), pol: pol, rd: reportDataOf(t, raw), sandbox: anySandbox}
	}
	v5 := func(q any) *pb.TDQuoteBodyV5 { return q.(*pb.QuoteV5).GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5() }
	rows := []row{
		{"control: v5 quote, current platform, policy names the service TD", nil, stAccept, ""},
		// The library refuses an out-of-date module for these quotes in one
		// case only: when the host's current module (TEE_TCB_SVN2) already
		// meets the newest platform level, so that relaunching the TD would
		// fix it. That is the first row.
		{"v5: TDX module TCB OutOfDate, host already updated (library refuses too)", func(c *rcase) {
			setStatus(levels(c.f.module()), "OutOfDate", "INTEL-SA-01192")
		}, stAuth, ""},
		// When the host itself is behind the newest platform level's TDX
		// component, the library accepts. The module check here is what refuses.
		{"v5: TDX module TCB OutOfDate, host not updated (library accepts)", func(c *rcase) {
			setStatus(levels(c.f.module()), "OutOfDate", "INTEL-SA-01192")
			old := levels(c.f.tcbInfo)[0].(map[string]any)
			raw, _ := json.Marshal(old)
			var newest map[string]any
			json.Unmarshal(raw, &newest)
			newest["tcb"].(map[string]any)["tdxtcbcomponents"].([]any)[2].(map[string]any)["svn"] = 255
			c.f.tcbInfo["tcbLevels"] = []any{newest, old}
		}, stAuth, "TDX module TCB"},
		{"v5: TDX module TCB Revoked", func(c *rcase) { setStatus(levels(c.f.module()), "Revoked") }, stAuth, "TDX module TCB"},
		{"v5: platform TCB OutOfDate", func(c *rcase) { setStatus(levels(c.f.tcbInfo), "OutOfDate") }, stAuth, "OutOfDate"},
		{"v5: service TD bound that the policy does not name", func(c *rcase) { p := *c.pol; p.MRServiceTD = ""; c.pol = &p }, stPolicy, "MR_SERVICE_TD"},
		{"v5: DEBUG TD", func(c *rcase) { c.mut = func(q any) { v5(q).TdAttributes[0] |= 1 } }, stPolicy, "DEBUG"},
		{"v5: RTMR3 not zero", func(c *rcase) { c.mut = func(q any) { v5(q).Rtmrs[3][0] = 1 } }, stPolicy, "RTMR"},
		{"v5: one bit of MRSERVICETD changed after signing", func(c *rcase) { c.post = flipAt(54 + 600) }, stAuth, "signature"},
		{"v5: body type the verifier does not know", func(c *rcase) { c.post = func(b []byte) []byte { b[48] = 9; return b } }, stMalformed, ""},
		{"v5: one non-zero byte appended", func(c *rcase) { c.post = func(b []byte) []byte { return append(b, 1) } }, stMalformed, "not zero padding"},
	}
	runRows(t, rows, newCase)
}

func v5ServiceTD(t *testing.T, raw []byte) string {
	t.Helper()
	b := v5Body(t, raw)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 96)
	for _, x := range b.GetMrServiceTd() {
		out = append(out, hexdigits[x>>4], hexdigits[x&15])
	}
	return string(out)
}

// Several launch policies: a quote must match one of them in full. This is
// what lets an image be replaced by its successor, or several VM shapes be
// served, without loosening anything.
func TestSeveralPolicies(t *testing.T) {
	raw, current, rd := hwPolicy(t)
	current.Name = "image-1"
	f := newFakePKI(t, raw, hwCollat, hwTime).allCurrent()
	// A second image: other UKI, hence other RTMR1 and RTMR2.
	next := *current
	next.Name, next.RTMR1, next.RTMR2 = "image-2", strings.Repeat("11", 48), strings.Repeat("22", 48)
	asImage2 := func(q any) {
		b := v4body(q)
		b.Rtmrs[1], b.Rtmrs[2] = bytes.Repeat([]byte{0x11}, 48), bytes.Repeat([]byte{0x22}, 48)
	}
	verify := func(mut func(any), policies ...*Policy) (*Result, error) {
		v := f.verifier(policies[0])
		v.Also = policies[1:]
		return v.Verify(context.Background(), f.quote(mut), rd, hwSandboxID)
	}

	for name, mut := range map[string]func(any){"image-1": nil, "image-2": asImage2} {
		res, err := verify(mut, current, &next)
		if err != nil || res.Policy != name {
			t.Errorf("a TD of %s with both policies in force: policy %q, %v", name, res.Policy, err)
		}
	}
	// With only its predecessor's policy in force, the new image is refused,
	// and the other way round: listing a policy is what admits an image.
	if _, err := verify(asImage2, current); err == nil || !strings.HasPrefix(err.Error(), stPolicy) {
		t.Errorf("image-2 under image-1's policy alone: %v", err)
	}
	if _, err := verify(nil, &next); err == nil || !strings.HasPrefix(err.Error(), stPolicy) {
		t.Errorf("image-1 under image-2's policy alone: %v", err)
	}
	// A third image matches neither, and the refusal says how it differs
	// from each.
	_, err := verify(func(q any) { v4body(q).Rtmrs[1] = bytes.Repeat([]byte{0x33}, 48) }, current, &next)
	if err == nil || !strings.Contains(err.Error(), "matches none of the 2 launch policies") ||
		!strings.Contains(err.Error(), "image-1: ") || !strings.Contains(err.Error(), "image-2: ") {
		t.Errorf("a third image: %v", err)
	}
	// Values of different policies do not combine: RTMR1 of one image with
	// RTMR2 of the other is no image at all.
	if res, err := verify(func(q any) { v4body(q).Rtmrs[1] = bytes.Repeat([]byte{0x11}, 48) }, current, &next); err == nil {
		t.Errorf("RTMR1 of image-2 with RTMR2 of image-1 was accepted as %q", res.Policy)
	}
	// Listing a policy admits nothing but its measurements: identity,
	// session, boot stage and TCB are as strict as with one policy.
	for name, c := range map[string]struct {
		mut     func(any)
		sandbox string
		stage   string
	}{
		"another sandbox":     {asImage2, "sbx-67393a1db4989930", stPolicy},
		"boot stage over":     {func(q any) { asImage2(q); d := proto.RTMR3BootDone(); v4body(q).Rtmrs[3] = d[:] }, hwSandboxID, stPolicy},
		"DEBUG TD of image-2": {func(q any) { asImage2(q); v4body(q).TdAttributes[0] |= 1 }, hwSandboxID, stPolicy},
	} {
		v := f.verifier(current)
		v.Also = []*Policy{&next}
		if _, err := v.Verify(context.Background(), f.quote(c.mut), rd, c.sandbox); err == nil || !strings.HasPrefix(err.Error(), c.stage) {
			t.Errorf("%s with two policies: %v", name, err)
		}
	}
	setStatus(levels(f.module()), "OutOfDate", "INTEL-SA-01192")
	if _, err := verify(asImage2, current, &next); err == nil || !strings.HasPrefix(err.Error(), stAuth) {
		t.Errorf("out-of-date TDX module with two policies: %v", err)
	}
	setStatus(levels(f.module()), "UpToDate")

	// Policies must be told apart, and each must be complete.
	unnamed := *current
	unnamed.Name = ""
	twin := next
	twin.Name = current.Name
	incomplete := next
	incomplete.Name, incomplete.RTMR2 = "image-3", ""
	for name, set := range map[string][]*Policy{"an unnamed policy": {current, &unnamed}, "two policies of one name": {current, &twin},
		"an incomplete policy": {current, &incomplete}, "a missing policy": {current, nil}} {
		if _, err := verify(nil, set...); err == nil {
			t.Errorf("%s was accepted in a set", name)
		}
	}
}

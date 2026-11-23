package attest

import (
	"bytes"
	"context"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/verify"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// Check is one line of an explanation: one thing a verifier establishes about
// a quote, and whether it held.
type Check struct {
	What   string
	OK     bool
	Detail string
}

// ExplainRunning says, check by check, what VerifyRunning looks at in a quote
// from a running sandbox and which of those hold. It is for a person reading a
// refusal: "everything matches except how Intel rates the TDX module" and
// "the measurements are another image's" are different situations, and the
// one-line error does not tell them apart.
//
// It decides nothing. The verdict is VerifyRunning's alone; no caller may
// release, accept or report as verified on the strength of this list. To be
// able to describe an out-of-date platform at all, the list is built with a
// pass that does not stop at the TCB rating (as Inspect does); that pass feeds
// these lines and nothing else.
func (v *TDX) ExplainRunning(ctx context.Context, raw []byte, reportData [64]byte, sandboxID, image string) []Check {
	var out []Check
	add := func(what string, err error, detail string) bool {
		c := Check{What: what, OK: err == nil, Detail: detail}
		if err != nil {
			c.Detail = err.Error()
		}
		out = append(out, c)
		return err == nil
	}
	quote, err := abi.QuoteToProto(raw)
	var body tdBody
	if err == nil {
		_, body, err = supported(quote)
	}
	if !add("the evidence is a TDX quote in a format every check covers", err, "") {
		return out
	}
	res := describe(raw, quote)
	o, c := v.options()
	o.DisableTcbStatusCheck = true
	if !add("signed by a genuine Intel platform: certificate chain to the trusted root, revocation lists, signed and current collateral, quoting enclave identity",
		verify.TdxQuoteContext(ctx, quote, o), "") {
		return out
	}
	strict, _ := v.options()
	add("Intel rates the platform (microcode, SGX, PCE, the TDX components the CPU reports) UpToDate", verify.TdxQuoteContext(ctx, quote, strict), "")
	lvl, _, rateErr := rate(quote, body, o, c, res)
	if add("the TDX module is Intel's (signer and attributes of the module identity in the collateral)", rateErr, "") {
		var qe, mod error
		if res.QETCBStatus != upToDate {
			qe = fmt.Errorf("rated %q", res.QETCBStatus)
		}
		add("Intel rates the quoting enclave UpToDate", qe, "")
		if string(lvl.TcbStatus) != upToDate {
			mod = fmt.Errorf("rated %q (level dated %s, open advisories %v)", lvl.TcbStatus, lvl.TcbDate, lvl.AdvisoryIDs)
		}
		add("Intel rates the TDX module UpToDate", mod, fmt.Sprintf("TEE_TCB_SVN %x", body.GetTeeTcbSvn()))
	}

	// The launch policy: the one that matches in full if there is one,
	// otherwise the first, field by field.
	policies := append([]*Policy{v.Policy}, v.Also...)
	after := proto.RTMR3Running(proto.RTMR3BootDone(), image)
	var pol *Policy
	var pb *policyBytes
	var whole error
	for _, p := range policies {
		if p == nil {
			continue
		}
		d, err := p.decode()
		if err != nil {
			continue
		}
		err = checkPolicy(quote, body, d, p.BindMRConfigID, reportData, sandboxID, after[:])
		if pol == nil || err == nil {
			pol, pb, whole = p, d, err
		}
		if err == nil {
			break
		}
	}
	if pol == nil {
		add("a launch policy to compare with", fmt.Errorf("none given"), "")
		return out
	}
	same := func(got, want []byte) error {
		if !bytes.Equal(got, want) {
			return fmt.Errorf("the quote has %x, expected %x", got, want)
		}
		return nil
	}
	name := pol.Name
	if name == "" {
		name = "(unnamed)"
	}
	var dbg error
	if a := body.GetTdAttributes(); len(a) != 8 || a[0]&1 != 0 {
		dbg = fmt.Errorf("TD_ATTRIBUTES %x", a)
	}
	add("not a debug TD (the host cannot read its memory)", dbg, "")
	add("firmware: MRTD is launch policy "+name+"'s", same(body.GetMrTd(), pb.mrtd), "")
	r := body.GetRtmrs()
	for len(r) < 4 {
		r = append(r, nil)
	}
	add("VM shape: RTMR0 is the policy's", same(r[0], pb.rtmr0), "")
	add("kernel, initrd and command line (with the root filesystem's hash): RTMR1 is the policy's", same(r[1], pb.rtmr1), "")
	add("boot stub measurements: RTMR2 is the policy's", same(r[2], pb.rtmr2), "")
	add("the measured boot stage is closed, the root is the image the sandbox names ("+image+") and nothing was added since: RTMR3", same(r[3], after[:]), "")
	if pol.BindMRConfigID {
		id := proto.MRConfigID(sandboxID)
		add("launched for this sandbox and no other: MRCONFIGID", same(body.GetMrConfigId(), id[:]), sandboxID)
	}
	add("made for this request: the quote carries the nonce chosen here and the SSH host key this session saw", same(body.GetReportData(), reportData[:]), "")
	add("every field of launch policy "+name+", as the verifier itself compares them", whole, "")
	return out
}

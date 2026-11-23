package keycmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// firstQuote20261113 is what the verifier read from the first quote of the
// hardware run of 2026-11-13 (docs/evidence/alibaba-ebmg8i-2026-11-13/
// first-quote-audit.json, its "quote"): a real TD's boot quote, which was
// refused (Intel rated the TDX module OutOfDate).
const firstQuote20261113 = `{"quote_sha256":"3d02a2c4fee17353984fdd9f65aee722d739afafedff6fbf152f2dc93a8d78ca","quote_version":4,"mrtd":"f9286d8bdd70ddd37d2affa7cd6e41deb7895a6bcdf0fc71d7182a3f6a5f06caf61b328fd5d168d54aa67e480a4ca2a3","rtmrs":["4820aa0debdfcb609ec15f8d3e60afe2358c9927e8d5749574f38db7450f69280573747dbcbdee230248e259aecac457","58ef5e7903f14043d3e9b9a72e0643ed3eb123b439d7345eda093779c9e3cacfaa9a444cf0f366b33d12f09b88fe901c","d383a43d65bb224be356df8b46aef49250858b4687290a787d370dde43ac2ab79aa2c1fe1a10e2f07b888f4942922478","000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],"td_attributes":"0000001000000000","xfam":"e702000000000000","mrconfigid":"2f76c468af2cba431205bc1b09ee59e51cd28757207d8a66b3a70ed23bcd2c48e15b935ce86b89e8d3bf486d4b0a1144","mr_seam":"27b67e0b20508f0acfb8a99df4283a7c86ae569d85d556a91d4eb20e56b5d42d5e65b31a3a6996e8e461f104f32fdeec","tee_tcb_svn":"0a010400000000000000000000000000","report_data":"010a37ea46656d4c8f9bc163e9f38151e3e031bed58a6f346a9595201d3e121358ba6d8bbff68f2834e68b12a1bfd9e544eb1b70c2f488cbcddd841606e52783","platform_tcb":"UpToDate","tdx_module_tcb_status":"OutOfDate","tdx_module_tcb_date":"2025-05-14T00:00:00Z","tdx_module_advisory_ids":["INTEL-SA-01192","INTEL-SA-01245","INTEL-SA-01312"],"qe_tcb_status":"UpToDate","fmspc":"90c06f000000"}`

// A refused unlock prints the refused quote's own values as one line of
// JSON, for trajrl only; an unlock that released, one that succeeded, and
// one that never saw a quote print nothing. The line is output: the
// outcome it is given is not changed.
func TestRefusedQuote(t *testing.T) {
	was := ownerkey.Tool
	defer func() { ownerkey.Tool = was }()
	var q attest.Result
	if err := json.Unmarshal([]byte(firstQuote20261113), &q); err != nil {
		t.Fatal(err)
	}
	refusal := errors.New(`the TD's quote does not verify: quote authenticity/TCB: TDX module TCB is "OutOfDate"`)
	refused := &ownerkey.Outcome{SandboxID: "sbx-24d9e41f834a2aeb", Quote: &q}

	ownerkey.Tool = "trajrl"
	var b bytes.Buffer
	refusedQuote(&b, refused, refusal)
	line := b.String()
	if !strings.HasPrefix(line, RefusedQuotePrefix) || !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("not one line with the prefix: %q", line)
	}
	var got attest.Result
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, RefusedQuotePrefix)), &got); err != nil {
		t.Fatalf("what follows the prefix is not JSON: %v\n%s", err, line)
	}
	if !reflect.DeepEqual(got, q) {
		t.Errorf("the line does not carry the quote's values:\n got %+v\nwant %+v", got, q)
	}
	// The values a launch policy is drafted from, under the names
	// tests/policy-from-quote.py reads.
	var m map[string]any
	json.Unmarshal([]byte(strings.TrimPrefix(line, RefusedQuotePrefix)), &m)
	for _, k := range []string{"mrtd", "rtmrs", "td_attributes", "xfam", "mrconfigid", "platform_tcb", "tdx_module_tcb_status", "qe_tcb_status", "fmspc", "tee_tcb_svn"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the line has no %q", k)
		}
	}
	if rt, _ := m["rtmrs"].([]any); len(rt) != 4 {
		t.Errorf("rtmrs: %v", m["rtmrs"])
	}
	if !reflect.DeepEqual(*refused.Quote, q) || refused.Released {
		t.Error("the outcome was changed")
	}

	// A quote that did not authenticate has no rating, and the line shows none.
	unauth := q
	unauth.PlatformTCB, unauth.ModuleTCBStatus, unauth.QETCBStatus, unauth.FMSPC = "", "", "", ""
	b.Reset()
	refusedQuote(&b, &ownerkey.Outcome{Quote: &unauth}, refusal)
	if s := b.String(); !strings.HasPrefix(s, RefusedQuotePrefix) || strings.Contains(strings.TrimPrefix(s, RefusedQuotePrefix), "platform_tcb") {
		t.Errorf("an unauthenticated quote: %q", s)
	}

	for name, c := range map[string]struct {
		tool string
		res  *ownerkey.Outcome
		err  error
	}{
		"sbxkey prints what it always printed": {"sbxkey", refused, refusal},
		"an unlock that succeeded":             {"trajrl", &ownerkey.Outcome{Quote: &q, Released: true}, nil},
		"a failure after the release":          {"trajrl", &ownerkey.Outcome{Quote: &q, Released: true}, refusal},
		"no quote was seen":                    {"trajrl", &ownerkey.Outcome{}, refusal},
		"no outcome":                           {"trajrl", nil, refusal},
	} {
		ownerkey.Tool = c.tool
		b.Reset()
		refusedQuote(&b, c.res, c.err)
		if b.Len() != 0 {
			t.Errorf("%s: printed %q", name, b.String())
		}
	}
}

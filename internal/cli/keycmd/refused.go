package keycmd

// What a refused unlock says about the quote it refused (#141).

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// RefusedQuotePrefix starts the one line trajrl prints on stderr when an
// unlock is refused before anything was released: after it, the refused
// quote's own values as one JSON object (attest.Result).
const RefusedQuotePrefix = "  refused quote (read-only; nothing in it was accepted; authenticated only if it names platform_tcb): "

// refusedQuote prints that line for the unlock res that ended in err: the
// measurements the TD's quote carries (MRTD, the RTMRs, the TD attributes,
// XFAM, MRCONFIGID) and, where the quote got that far, how Intel rates the
// platform. The verifier fills platform_tcb only once Intel's signature
// chain and collateral verified, so a quote without it is not authenticated.
//
// It is output and nothing else: no check is skipped or relaxed for it, the
// unlock stays refused, and no secret was sent. It is what a launch policy
// for a new machine model is drafted from: RTMR0, the TD attributes and XFAM
// come from the VMM and the processor and are known from no other source
// (tests/policy-from-quote.py, tests/hw-n2n.sh first-quote); and it tells an
// owner whose policy no longer matches what their TD measured.
//
// trajrl only: sbxkey prints what it always printed (#123, Acceptance 3).
func refusedQuote(w io.Writer, res *ownerkey.Outcome, err error) {
	if err == nil || res == nil || res.Released || res.Quote == nil || ownerkey.Tool == "sbxkey" {
		return
	}
	b, jerr := json.Marshal(res.Quote)
	if jerr != nil {
		return
	}
	fmt.Fprintf(w, "%s%s\n", RefusedQuotePrefix, b)
}

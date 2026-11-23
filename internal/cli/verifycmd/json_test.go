package verifycmd

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// -json (#58): one object with the verdict, the reason, the sandbox, when
// it was checked and the verifier's result as it is; a refusal still
// carries the quote, which is what host-admit reads the rating from.
func TestJSONVerdict(t *testing.T) {
	q := &attest.Result{QuoteSHA256: "3d02", MRTD: "f928", RTMRs: []string{"48", "58", "d3", "00"}, TeeTcbSvn: "0a010400000000000000000000000000",
		PlatformTCB: "UpToDate", ModuleTCBStatus: "UpToDate", QETCBStatus: "UpToDate", Policy: "image-r8", FMSPC: "90c06f000000"}
	at := time.Date(2026, 11, 17, 9, 0, 0, 0, time.FixedZone("CET", 3600))
	rep := &userverify.Report{SandboxID: "sbx-24d9e41f834a2aeb", Quote: q, UnlockedByOwner: true}

	decode := func(v Verdict) map[string]any {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	ok := decode(verdictOf(rep, nil, "", at))
	if ok["verdict"] != "VERIFIED" || ok["sandbox_id"] != "sbx-24d9e41f834a2aeb" || ok["checked_at"] != "2026-11-17T08:00:00Z" || ok["reason"] != nil {
		t.Fatalf("VERIFIED: %v", ok)
	}
	quote, _ := ok["quote"].(map[string]any)
	for k, want := range map[string]string{"fmspc": "90c06f000000", "tee_tcb_svn": "0a010400000000000000000000000000", "platform_tcb": "UpToDate",
		"tdx_module_tcb_status": "UpToDate", "qe_tcb_status": "UpToDate", "mrtd": "f928", "policy": "image-r8"} {
		if quote[k] != want {
			t.Errorf("quote.%s = %v, want %s", k, quote[k], want)
		}
	}
	if r, _ := quote["rtmrs"].([]any); len(r) != 4 {
		t.Errorf("quote.rtmrs: %v", quote["rtmrs"])
	}
	if _, has := quote["tcb_exception"]; has {
		t.Errorf("quote.tcb_exception without one: %v", quote)
	}

	// Refused: Intel rates the module out of date. The quote is there.
	bad := *q
	bad.ModuleTCBStatus, bad.Policy = "OutOfDate", ""
	no := decode(verdictOf(&userverify.Report{Quote: &bad}, errors.New(`quote authenticity/TCB: TDX module TCB is "OutOfDate"`), "sbx-24d9e41f834a2aeb", at))
	if no["verdict"] != "NOT VERIFIED" || no["sandbox_id"] != "sbx-24d9e41f834a2aeb" || no["reason"] != `quote authenticity/TCB: TDX module TCB is "OutOfDate"` || no["unlocked_by_owner"] != nil {
		t.Fatalf("NOT VERIFIED: %v", no)
	}
	if quote, _ := no["quote"].(map[string]any); quote["tdx_module_tcb_status"] != "OutOfDate" || quote["fmspc"] != "90c06f000000" {
		t.Fatalf("NOT VERIFIED without its quote: %v", no)
	}
	// Refused before any quote: the object is still whole, quote null.
	none := decode(verdictOf(nil, errors.New("connection refused"), "sbx-1", at))
	if q, has := none["quote"]; !has || q != nil || none["verdict"] != "NOT VERIFIED" || none["sandbox_id"] != "sbx-1" {
		t.Fatalf("no report: %v", none)
	}
}

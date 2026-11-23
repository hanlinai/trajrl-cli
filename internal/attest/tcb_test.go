package attest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify/trust"
)

// These tests use a quote this prototype's own TD produced and a broker
// accepted: Cloud Hypervisor on an Alibaba Cloud ecs.ebmg8i.48xlarge,
// 2026-11-10T12:34:05Z, sandbox sbx-b69ca8dfd1e7d6a4. It is the last of the
// eight releases made before the verifier checked the TDX module's TCB level
// (entry 17 of docs/evidence/alibaba-ebmg8i/broker-audit.jsonl). Intel's
// collateral for that platform, as served on that day, is replayed from
// testdata so the outcome does not drift: platform level UpToDate, TDX module
// (1.5, SVN 10) OutOfDate. Signatures are Intel's and are verified against
// Intel's root: nothing here uses the stand-in PKI.
//
// TDX_RECORD_PCS=1 re-records the collateral from Intel PCS.

const (
	hwQuote     = "testdata/ebmg8i-cloud-hypervisor-td-quote-v4.bin"
	hwCollat    = "testdata/pcs-collateral-2026-11-10.json"
	hwSandboxID = "sbx-b69ca8dfd1e7d6a4"
)

var hwTime = time.Date(2026, time.November, 10, 12, 40, 0, 0, time.UTC)

type pcsResponse struct {
	Header map[string][]string `json:"header"`
	Body   []byte              `json:"body"`
}

// replayGetter answers collateral requests from a recording.
type replayGetter struct {
	t        *testing.T
	path     string
	recorded map[string]pcsResponse
	live     trust.HTTPSGetter
	fail     func(url string) error
}

func (g *replayGetter) Get(url string) (map[string][]string, []byte, error) {
	if g.fail != nil {
		if err := g.fail(url); err != nil {
			return nil, nil, err
		}
	}
	if r, ok := g.recorded[url]; ok {
		return r.Header, r.Body, nil
	}
	if g.live == nil {
		return nil, nil, fmt.Errorf("no recorded PCS response for %s", url)
	}
	h, b, err := g.live.Get(url)
	if err != nil {
		return nil, nil, err
	}
	g.recorded[url] = pcsResponse{h, b}
	out, _ := json.MarshalIndent(g.recorded, "", " ")
	if err := os.WriteFile(g.path, out, 0o644); err != nil {
		g.t.Fatal(err)
	}
	return h, b, nil
}

func replay(t *testing.T, path string) *replayGetter {
	t.Helper()
	g := &replayGetter{t: t, path: path, recorded: map[string]pcsResponse{}}
	if os.Getenv("TDX_RECORD_PCS") != "" {
		g.live = trust.DefaultHTTPSGetter()
		return g
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &g.recorded); err != nil {
		t.Fatal(err)
	}
	return g
}

// hwVerifier is the production verifier with two substitutions: Intel's
// collateral comes from the recording and the clock is pinned. The root of
// trust is Intel's.
func hwVerifier(t *testing.T, pol *Policy, x *TCBException, at time.Time) *TDX {
	return &TDX{Policy: pol, Exception: x, getter: replay(t, hwCollat), now: func() time.Time { return at }}
}

// hwPolicy is the launch policy the broker ran with on the hardware.
func hwPolicy(t *testing.T) (raw []byte, pol *Policy, rd [64]byte) {
	t.Helper()
	raw, err := os.ReadFile(hwQuote)
	if err != nil {
		t.Fatal(err)
	}
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	b := q.(*pb.QuoteV4).GetTdQuoteBody()
	h := hex.EncodeToString
	pol = &Policy{MRTD: h(b.GetMrTd()), RTMR0: h(b.GetRtmrs()[0]), RTMR1: h(b.GetRtmrs()[1]), RTMR2: h(b.GetRtmrs()[2]),
		TDAttributes: h(b.GetTdAttributes()), XFAM: h(b.GetXfam()), BindMRConfigID: true}
	return raw, pol, [64]byte(b.GetReportData())
}

// The default configuration refuses the evidence the hardware produced.
func TestOutOfDateTDXModuleRefused(t *testing.T) {
	raw, pol, rd := hwPolicy(t)
	res, err := hwVerifier(t, pol, nil, hwTime).Verify(context.Background(), raw, rd, hwSandboxID)
	if err == nil {
		t.Fatal("a TD on an out-of-date TDX module was accepted by the strict policy")
	}
	if !strings.Contains(err.Error(), "authenticity/TCB") || !strings.Contains(err.Error(), "TDX module TCB") {
		t.Fatalf("refusal did not come from the TDX module level: %v", err)
	}
	if res.PlatformTCB != "UpToDate" || res.ModuleTCBStatus != "OutOfDate" || res.QETCBStatus != "UpToDate" || res.FMSPC != "90c06f000000" {
		t.Errorf("unexpected rating: platform %q, module %q, QE %q, FMSPC %q", res.PlatformTCB, res.ModuleTCBStatus, res.QETCBStatus, res.FMSPC)
	}
	if res.TCBException != "" {
		t.Errorf("a refusal claims an exception: %q", res.TCBException)
	}
	t.Logf("refused: %v", err)
}

// A launch policy cannot carry an exception: the policy file that was used on
// the hardware, which has one inline, no longer loads.
func TestPolicyFileCannotCarryException(t *testing.T) {
	const historical = "../../docs/evidence/alibaba-ebmg8i/launch-policy-with-tcb-exception.json"
	if _, err := LoadPolicy(historical); err == nil || !strings.Contains(err.Error(), "allow_tdx_module_tcb") {
		t.Fatalf("policy with an inline TCB exception was loaded: %v", err)
	}
	// The same policy without the exception is the strict one, and loads.
	if _, err := LoadPolicy("../../docs/evidence/alibaba-ebmg8i/launch-policy.json"); err != nil {
		t.Fatal(err)
	}
}

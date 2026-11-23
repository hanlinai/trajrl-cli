// Package attest verifies Intel TDX quotes against Intel's PKI and collateral
// and against this prototype's launch policy. It runs off-host, in the key
// broker, and trusts nothing the host supplies.
package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// Policy holds the reference values a TD must match. All values are hex.
// Every field except MRSeam is mandatory: an unset field is a load error, not
// "don't care".
type Policy struct {
	// Name identifies the policy in the audit log when the broker accepts
	// more than one (an image being replaced by its successor, or several VM
	// shapes). LoadPolicy defaults it to the file's name.
	Name string `json:"name,omitempty"`
	// MRTD measures the TD firmware image as loaded by the VMM.
	MRTD string `json:"mrtd"`
	// RTMR0: firmware configuration (TD HOB, ACPI). Tied to the VM shape.
	RTMR0 string `json:"rtmr0"`
	// RTMR1: the UKI (kernel + initrd + cmdline) and boot-disk GPT.
	RTMR1 string `json:"rtmr1"`
	// RTMR2: measurements made by the UKI stub / kernel EFI stub.
	RTMR2 string `json:"rtmr2"`
	// TDAttributes is the exact 8-byte ATTRIBUTES value. DEBUG is refused
	// regardless of what is written here.
	TDAttributes string `json:"td_attributes"`
	XFAM         string `json:"xfam"`
	// BindMRConfigID requires MRCONFIGID == proto.MRConfigID(sandbox). With
	// false, MRCONFIGID must be zero and identity rests on REPORTDATA alone.
	BindMRConfigID bool `json:"bind_mrconfigid"`
	// MRSeam optionally pins the TDX module build; normally left to Intel's
	// TCB info.
	MRSeam string `json:"mr_seam,omitempty"`
	// MRServiceTD is the expected MRSERVICETD of a TDX 1.5 quote: the digest
	// of the service TDs bound to this TD (e.g. a migration TD). Unset means
	// none may be bound: the field must be zero.
	MRServiceTD string `json:"mr_service_td,omitempty"`
}

type policyBytes struct {
	mrtd, rtmr0, rtmr1, rtmr2, attrs, xfam, mrseam, mrservicetd []byte
}

func (p *Policy) decode() (*policyBytes, error) {
	dec := func(name, s string, n int, optional bool) ([]byte, error) {
		if s == "" && optional {
			return nil, nil
		}
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != n {
			return nil, fmt.Errorf("policy %s: want %d hex bytes", name, n)
		}
		return b, nil
	}
	var b policyBytes
	var err error
	if b.mrtd, err = dec("mrtd", p.MRTD, 48, false); err != nil {
		return nil, err
	}
	if b.rtmr0, err = dec("rtmr0", p.RTMR0, 48, false); err != nil {
		return nil, err
	}
	if b.rtmr1, err = dec("rtmr1", p.RTMR1, 48, false); err != nil {
		return nil, err
	}
	if b.rtmr2, err = dec("rtmr2", p.RTMR2, 48, false); err != nil {
		return nil, err
	}
	if b.attrs, err = dec("td_attributes", p.TDAttributes, 8, false); err != nil {
		return nil, err
	}
	if b.xfam, err = dec("xfam", p.XFAM, 8, false); err != nil {
		return nil, err
	}
	if b.mrseam, err = dec("mr_seam", p.MRSeam, 48, true); err != nil {
		return nil, err
	}
	if b.mrservicetd, err = dec("mr_service_td", p.MRServiceTD, 48, true); err != nil {
		return nil, err
	}
	if b.mrservicetd == nil {
		b.mrservicetd = make([]byte, 48)
	}
	if b.attrs[0]&1 != 0 {
		return nil, errors.New("policy td_attributes has the DEBUG bit set")
	}
	return &b, nil
}

func LoadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// A launch policy cannot carry a TCB exception. The field that once did
	// is refused by name, so an old policy file fails loudly instead of
	// loading with its exception silently dropped or silently honoured.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if _, ok := keys["allow_tdx_module_tcb"]; ok {
		return nil, fmt.Errorf("policy %s: allow_tdx_module_tcb is not part of a launch policy; "+
			"a TCB exception is a separate, explicitly enabled file (see docs/validation.md)", path)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var p Policy
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if _, err := p.decode(); err != nil {
		return nil, err
	}
	if p.Name == "" {
		p.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return &p, nil
}

// Result is what a verification established; it goes to the audit log.
type Result struct {
	QuoteSHA256  string   `json:"quote_sha256"`
	QuoteVersion uint32   `json:"quote_version,omitempty"`
	MRTD         string   `json:"mrtd,omitempty"`
	RTMRs        []string `json:"rtmrs,omitempty"`
	TDAttributes string   `json:"td_attributes,omitempty"`
	XFAM         string   `json:"xfam,omitempty"`
	MRConfigID   string   `json:"mrconfigid,omitempty"`
	MRSeam       string   `json:"mr_seam,omitempty"`
	TeeTcbSvn    string   `json:"tee_tcb_svn,omitempty"`
	// TDX 1.5 quote bodies only.
	TeeTcbSvn2  string `json:"tee_tcb_svn2,omitempty"`
	MRServiceTD string `json:"mr_service_td,omitempty"`
	ReportData  string `json:"report_data,omitempty"`
	// How Intel's collateral rates the platform. Intel publishes two levels
	// for a TDX platform and both count: the platform level (microcode, SGX,
	// PCE and the TDX components the CPU reports) and, for TDX module 1.x and
	// later, the level of the TDX module itself.
	// PlatformTCB is "UpToDate", or the reason the platform level failed.
	PlatformTCB       string   `json:"platform_tcb,omitempty"`
	ModuleTCBStatus   string   `json:"tdx_module_tcb_status,omitempty"`
	ModuleTCBDate     string   `json:"tdx_module_tcb_date,omitempty"`
	ModuleAdvisoryIDs []string `json:"tdx_module_advisory_ids,omitempty"`
	QETCBStatus       string   `json:"qe_tcb_status,omitempty"`
	// Policy names the launch policy the quote matched, on acceptance.
	Policy string `json:"policy,omitempty"`
	// FMSPC is the platform family the collateral was issued for.
	FMSPC string `json:"fmspc,omitempty"`
	// TCBException is set when the verdict relied on an experimental TCB
	// exception; it names what was tolerated and why.
	TCBException string `json:"tcb_exception,omitempty"`
}

// Verifier decides whether a quote entitles sandboxID to its secret.
type Verifier interface {
	Verify(ctx context.Context, quote []byte, reportData [64]byte, sandboxID string) (*Result, error)
}

// TDX is the production verifier. It always verifies the PCK chain to Intel's
// root, fetches TCB info, QE identity and CRLs from Intel PCS, checks
// revocation, and requires the platform level, the quoting enclave and the TDX
// module all to be UpToDate. There is no setting that turns any of that off.
type TDX struct {
	Policy *Policy
	// Also lists further launch policies that are accepted as well. A quote
	// must match one policy in full: every policy is complete in itself, and
	// values from different policies never combine. Authenticity and TCB are
	// established once, before any policy is looked at, and do not depend on
	// which policy matches.
	Also []*Policy
	// Exception, if set, tolerates one named out-of-date TDX module level for
	// the sandboxes it lists, until it expires. It exists only in the
	// validation build (tag tcbexception, exception_on.go) and is nil in a
	// normal deployment; in any other build TCBException is empty and a
	// verifier given one refuses every quote (exception_off.go).
	Exception *TCBException
	// Collateral, if set, caches Intel's collateral between verifications
	// (see CollateralCache); it is meant to be shared by every verifier the
	// broker builds, across policy reloads. Nil: every verification fetches
	// its collateral from Intel, as before. A cache fetches through its own
	// upstream getter, not through the getter test seam below.
	Collateral *CollateralCache

	// Test seams. They are unexported: nothing outside this package can
	// redirect the collateral source, the clock or the root of trust, and
	// none of them can switch a check off.
	getter trust.HTTPSGetter
	now    func() time.Time
	roots  *x509.CertPool
}

func (v *TDX) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

// capture records the TCB info response the library fetched, so the checks the
// library does not make can be applied to the very bytes whose signature it
// verified.
type capture struct {
	inner trust.HTTPSGetter
	mu    sync.Mutex
	tcb   []byte
}

func (c *capture) keep(url string, body []byte, err error) {
	if err == nil && strings.Contains(url, "/tcb?fmspc=") {
		c.mu.Lock()
		c.tcb = body
		c.mu.Unlock()
	}
}

func (c *capture) Get(url string) (map[string][]string, []byte, error) {
	h, b, err := c.inner.Get(url)
	c.keep(url, b, err)
	return h, b, err
}

func (c *capture) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	h, b, err := trust.GetWith(ctx, c.inner, url)
	c.keep(url, b, err)
	return h, b, err
}

func (c *capture) tcbInfo() (*pcs.TcbInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.tcb) == 0 {
		return nil, errors.New("no TCB info was fetched")
	}
	var info pcs.TdxTcbInfo
	if err := json.Unmarshal(c.tcb, &info); err != nil {
		return nil, fmt.Errorf("TCB info: %w", err)
	}
	return &info.TcbInfo, nil
}

// options are the library options every verification runs with.
func (v *TDX) options() (*verify.Options, *capture) {
	inner := v.getter
	if inner == nil {
		inner = BoundedGetter()
	}
	if v.Collateral != nil {
		inner = v.Collateral.at(v.clock)
	}
	c := &capture{inner: inner}
	o := verify.DefaultOptions()
	o.GetCollateral = true
	o.CheckRevocations = true
	o.DisableTcbStatusCheck = false
	o.Getter = c
	o.TrustedRoots = v.roots // nil: the Intel SGX Root CA embedded in the library
	at := v.clock()
	o.Now = &verify.TimeSet{PckCertChain: at, TcbInfo: at, QeIdentity: at, PckCrl: at, RootCaCrl: at}
	return o, c
}

// tdBody is the part of a quote body common to the v4 format and both v5
// body types.
type tdBody interface {
	GetMrTd() []byte
	GetRtmrs() [][]byte
	GetTdAttributes() []byte
	GetXfam() []byte
	GetMrConfigId() []byte
	GetMrSeam() []byte
	GetMrSignerSeam() []byte
	GetSeamAttributes() []byte
	GetTeeTcbSvn() []byte
	GetReportData() []byte
}

// TD quote body types of a v5 quote (Intel TDX DCAP quote format).
const (
	bodyTDX10 = 2
	bodyTDX15 = 3
)

// padding refuses bytes after the signed quote unless they are zeros. Nothing
// signs them. Quote generation services do pad with zeros (Intel's QGS appends
// 70 to the quotes of the hardware run), so zeros are tolerated; anything else
// is data the host attached to a genuine quote and is refused.
func padding(extra []byte) error {
	for _, b := range extra {
		if b != 0 {
			return fmt.Errorf("%d unsigned bytes follow the quote and they are not zero padding", len(extra))
		}
	}
	return nil
}

// supported returns the quote's body if its format is one the checks below
// cover: v4, or v5 carrying a TDX 1.0 or TDX 1.5 body.
func supported(quote any) (uint32, tdBody, error) {
	switch q := quote.(type) {
	case *pb.QuoteV4:
		if err := padding(q.GetExtraBytes()); err != nil {
			return 0, nil, err
		}
		if q.GetTdQuoteBody() == nil {
			return 0, nil, errors.New("quote has no body")
		}
		return 4, q.GetTdQuoteBody(), nil
	case *pb.QuoteV5:
		if err := padding(q.GetExtraBytes()); err != nil {
			return 0, nil, err
		}
		d := q.GetTdQuoteBodyDescriptor()
		if t := d.GetTdQuoteBodyType(); t != bodyTDX10 && t != bodyTDX15 {
			return 0, nil, fmt.Errorf("unsupported v5 quote body type %d", t)
		}
		if d.GetTdQuoteBodyV5() == nil {
			return 0, nil, errors.New("quote has no body")
		}
		return 5, d.GetTdQuoteBodyV5(), nil
	}
	return 0, nil, fmt.Errorf("unsupported quote format %T", quote)
}

func describe(raw []byte, quote any) *Result {
	sum := sha256.Sum256(raw)
	r := &Result{QuoteSHA256: hex.EncodeToString(sum[:])}
	ver, b, err := supported(quote)
	if err != nil {
		return r
	}
	r.QuoteVersion = ver
	r.MRTD = hex.EncodeToString(b.GetMrTd())
	for _, m := range b.GetRtmrs() {
		r.RTMRs = append(r.RTMRs, hex.EncodeToString(m))
	}
	r.TDAttributes = hex.EncodeToString(b.GetTdAttributes())
	r.XFAM = hex.EncodeToString(b.GetXfam())
	r.MRConfigID = hex.EncodeToString(b.GetMrConfigId())
	r.MRSeam = hex.EncodeToString(b.GetMrSeam())
	r.TeeTcbSvn = hex.EncodeToString(b.GetTeeTcbSvn())
	r.ReportData = hex.EncodeToString(b.GetReportData())
	if q, ok := quote.(*pb.QuoteV5); ok && q.GetTdQuoteBodyDescriptor().GetTdQuoteBodyType() == bodyTDX15 {
		v5 := q.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
		r.TeeTcbSvn2 = hex.EncodeToString(v5.GetTeeTcbSvn2())
		r.MRServiceTD = hex.EncodeToString(v5.GetMrServiceTd())
	}
	return r
}

var intelQEVendorID = []byte{0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07}

const upToDate = string(pcs.TcbComponentStatusUpToDate)

// Verify releases nothing unless the quote is authentic, the platform is one
// Intel rates as current, and the TD is the measured boot chain of sandboxID
// in the session reportData commits to.
func (v *TDX) Verify(ctx context.Context, raw []byte, reportData [64]byte, sandboxID string) (*Result, error) {
	return v.verify(ctx, raw, reportData, sandboxID, make([]byte, 48))
}

// VerifyRunning is for a sandbox's owner, not for the broker: it checks a
// quote taken from a sandbox that has finished booting. Everything Verify
// requires is required here too, with one difference: RTMR3 must have the
// value of a completed boot of a sandbox the broker unlocked whose root is
// image (#112): proto.RTMR3Running(proto.RTMR3BootDone(), image), image being
// the digest the running TD reports, or proto.ImageBase. The equality makes
// that report authentic. No key is ever released on such a quote; Verify
// refuses it for exactly that register.
func (v *TDX) VerifyRunning(ctx context.Context, raw []byte, reportData [64]byte, sandboxID, image string) (*Result, error) {
	if !proto.ValidImageMeasure(image) {
		return nil, fmt.Errorf("the sandbox names its image %.80q, which is neither %q nor a sha256 digest", image, proto.ImageBase)
	}
	after := proto.RTMR3Running(proto.RTMR3BootDone(), image)
	return v.verify(ctx, raw, reportData, sandboxID, after[:])
}

// VerifyRunningAs is VerifyRunning for a sandbox its owner unlocked with
// their own key: RTMR3 must be exactly rtmr3, the value that unlock and the
// image leave (proto.RTMR3Running of proto.RTMR3OwnerUnlock and the image,
// ownerkey.ExpectedRTMR3), which only a TD given the owner's disk secret
// shows, and only with that image as its root. Everything else is as
// VerifyRunning.
func (v *TDX) VerifyRunningAs(ctx context.Context, raw []byte, reportData [64]byte, sandboxID string, rtmr3 [48]byte) (*Result, error) {
	return v.verify(ctx, raw, reportData, sandboxID, rtmr3[:])
}

func (v *TDX) verify(ctx context.Context, raw []byte, reportData [64]byte, sandboxID string, rtmr3 []byte) (*Result, error) {
	policies := append([]*Policy{v.Policy}, v.Also...)
	decoded := make([]*policyBytes, len(policies))
	seen := map[string]bool{}
	for i, p := range policies {
		if p == nil {
			return nil, errors.New("no launch policy")
		}
		var err error
		if decoded[i], err = p.decode(); err != nil {
			return nil, err
		}
		if len(policies) > 1 && (p.Name == "" || seen[p.Name]) {
			return nil, fmt.Errorf("with several launch policies each needs a name of its own (%q)", p.Name)
		}
		seen[p.Name] = true
	}
	if v.Exception != nil {
		if err := v.Exception.check(); err != nil {
			return nil, err
		}
	}
	quote, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("malformed quote: %w", err)
	}
	// Refuse any format the checks below do not cover, rather than half-check it.
	_, body, err := supported(quote)
	if err != nil {
		return nil, fmt.Errorf("malformed quote: %w", err)
	}
	res := describe(raw, quote)
	if err := v.authenticate(ctx, quote, body, res, sandboxID); err != nil {
		return res, fmt.Errorf("quote authenticity/TCB: %w", err)
	}
	var mismatches []string
	for i, p := range policies {
		err := checkPolicy(quote, body, decoded[i], p.BindMRConfigID, reportData, sandboxID, rtmr3)
		if err == nil {
			res.Policy = p.Name
			return res, nil
		}
		if len(policies) == 1 {
			return res, fmt.Errorf("quote policy: %w", err)
		}
		mismatches = append(mismatches, fmt.Sprintf("%s: %v", p.Name, err))
	}
	return res, fmt.Errorf("quote policy: the quote matches none of the %d launch policies: %s", len(policies), strings.Join(mismatches, " | "))
}

// authenticate establishes that the quote was signed by a genuine quoting
// enclave on a platform whose every TCB level Intel currently rates UpToDate
// (or whose TDX module level is exactly what v.Exception names).
func (v *TDX) authenticate(ctx context.Context, quote any, body tdBody, res *Result, sandboxID string) error {
	o, c := v.options()
	// Chain to the root, CRLs, signed and unexpired collateral, quote and QE
	// report signatures, QE identity, platform TCB level, QE TCB level.
	if err := verify.TdxQuoteContext(ctx, quote, o); err != nil {
		return err
	}
	res.PlatformTCB = upToDate
	lvl, info, err := rate(quote, body, o, c, res)
	if err != nil {
		return err
	}
	// The library has enforced the quoting enclave's level; it is asserted
	// here as well so that this function does not depend on a library option.
	if res.QETCBStatus != upToDate {
		return fmt.Errorf("quoting enclave TCB is %q", res.QETCBStatus)
	}
	return v.moduleTCB(body, lvl, info, res, sandboxID)
}

// rate reads, from collateral the library has just verified, how Intel rates
// the quoting enclave and the TDX module, and checks the module's identity.
// It fills res and returns the TDX module's matched level (for a TDX 1.0
// module, which has no level of its own, the platform's).
func rate(quote any, body tdBody, o *verify.Options, c *capture, res *Result) (pcs.TcbLevel, *pcs.TcbInfo, error) {
	lvl, qe, err := verify.SupportedTcbLevelsFromCollateral(quote, o)
	res.QETCBStatus = string(qe.TcbStatus)
	if err != nil {
		return lvl, nil, fmt.Errorf("tcb level: %w", err)
	}
	info, err := c.tcbInfo()
	if err != nil {
		return lvl, nil, err
	}
	res.FMSPC = strings.ToLower(info.Fmspc)
	svn := body.GetTeeTcbSvn()
	if len(svn) != 16 {
		return lvl, nil, fmt.Errorf("TEE_TCB_SVN has %d bytes", len(svn))
	}
	// TEE_TCB_SVN[1] is the TDX module major version. From 1 on, the module
	// has its own identity and TCB levels in the collateral and lvl is that
	// level. The library compares the quote with the collateral's top-level
	// tdxModule entry only; the entry for this module version is compared here.
	if svn[1] == 0 {
		return lvl, info, nil
	}
	id := "TDX_" + hex.EncodeToString(svn[1:2])
	var ident *pcs.TdxModuleIdentity
	for i := range info.TdxModuleIdentities {
		if strings.EqualFold(info.TdxModuleIdentities[i].ID, id) {
			ident = &info.TdxModuleIdentities[i]
		}
	}
	if ident == nil {
		return lvl, nil, fmt.Errorf("collateral has no TDX module identity %s", id)
	}
	if len(ident.Mrsigner.Bytes) == 0 || !bytes.Equal(body.GetMrSignerSeam(), ident.Mrsigner.Bytes) {
		return lvl, nil, fmt.Errorf("MRSIGNERSEAM %x is not the signer of TDX module identity %s", body.GetMrSignerSeam(), id)
	}
	attrs, mask, want := body.GetSeamAttributes(), ident.AttributesMask.Bytes, ident.Attributes.Bytes
	if len(mask) != len(attrs) || len(want) != len(attrs) || len(attrs) == 0 {
		return lvl, nil, fmt.Errorf("TDX module identity %s: malformed attributes", id)
	}
	for i := range attrs {
		if attrs[i]&mask[i] != want[i] {
			return lvl, nil, fmt.Errorf("SEAMATTRIBUTES %x do not match TDX module identity %s", attrs, id)
		}
	}
	res.ModuleTCBStatus, res.ModuleTCBDate, res.ModuleAdvisoryIDs = string(lvl.TcbStatus), lvl.TcbDate, lvl.AdvisoryIDs
	return lvl, info, nil
}

// moduleTCB refuses unless the TDX module's level is UpToDate or exactly what
// the experimental exception names. The library does not make this check for
// v4 quotes or TDX 1.0 bodies, and only partly for TDX 1.5 bodies.
func (v *TDX) moduleTCB(body tdBody, lvl pcs.TcbLevel, info *pcs.TcbInfo, res *Result, sandboxID string) error {
	if string(lvl.TcbStatus) == upToDate {
		return nil
	}
	if body.GetTeeTcbSvn()[1] == 0 {
		// Unreachable while the library enforces the platform level; kept so
		// that an out-of-date TDX 1.0 module can never fall through.
		return fmt.Errorf("TDX TCB is %q", lvl.TcbStatus)
	}
	refusal := fmt.Errorf("TDX module TCB is %q (level dated %s, open advisories %v)", lvl.TcbStatus, lvl.TcbDate, lvl.AdvisoryIDs)
	if v.Exception == nil {
		return refusal
	}
	tolerated, err := v.Exception.covers(info.Fmspc, body.GetTeeTcbSvn(), lvl, sandboxID, v.clock())
	if err != nil {
		return fmt.Errorf("%w; %w", refusal, err)
	}
	res.TCBException = tolerated
	return nil
}

// checkPolicy compares an authenticated quote with the launch policy and with
// the identity and session it must be bound to.
func checkPolicy(quote any, body tdBody, pol *policyBytes, bindMRConfigID bool, reportData [64]byte, sandboxID string, rtmr3 []byte) error {
	// DEBUG is refused here as well as by the library option below: a debug
	// TD's memory is readable by the host.
	if a := body.GetTdAttributes(); len(a) != 8 || a[0]&1 != 0 {
		return fmt.Errorf("TD_ATTRIBUTES %x: DEBUG is set or the field is malformed", a)
	}
	zero48 := make([]byte, 48)
	mrConfigID := zero48
	if bindMRConfigID {
		id := proto.MRConfigID(sandboxID)
		mrConfigID = id[:]
	}
	opts := &validate.Options{
		HeaderOptions: validate.HeaderOptions{QeVendorID: intelQEVendorID},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			TdAttributes:  pol.attrs,
			Xfam:          pol.xfam,
			MrTd:          pol.mrtd,
			MrSeam:        pol.mrseam,
			MrConfigID:    mrConfigID,
			MrOwner:       zero48,
			MrOwnerConfig: zero48,
			// Checked by the library for TDX 1.5 bodies only; the older
			// bodies have no such field and no service-TD binding.
			MrServiceTd:             pol.mrservicetd,
			Rtmrs:                   [][]byte{pol.rtmr0, pol.rtmr1, pol.rtmr2, rtmr3},
			ReportData:              reportData[:],
			EnableTdDebugCheck:      true,
			EnableTdMigratableCheck: true,
		},
	}
	return validate.TdxQuote(quote, opts)
}

// Inspect authenticates a quote and reports what it contains and how Intel
// currently rates its TCB, without applying launch policy. It is a diagnostic
// for operators (e.g. to read golden measurements or see why the strict TCB
// check fails) and never gates key release.
func Inspect(ctx context.Context, raw []byte) (*Result, error) {
	quote, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("malformed quote: %w", err)
	}
	_, body, err := supported(quote)
	if err != nil {
		return nil, fmt.Errorf("malformed quote: %w", err)
	}
	res := describe(raw, quote)
	v := &TDX{}
	// Authenticity alone first, so that an out-of-date platform can still be
	// described. This relaxed pass feeds the report below and nothing else.
	o, c := v.options()
	o.DisableTcbStatusCheck = true
	if err := verify.TdxQuoteContext(ctx, quote, o); err != nil {
		return res, fmt.Errorf("quote authenticity: %w", err)
	}
	lvl, info, rateErr := rate(quote, body, o, c, res)
	var moduleErr error
	if rateErr == nil {
		moduleErr = v.moduleTCB(body, lvl, info, res, "")
	}
	// The platform level and the quoting enclave, as the library rates them.
	strict, _ := v.options()
	platformErr := verify.TdxQuoteContext(ctx, quote, strict)
	res.PlatformTCB = upToDate
	if platformErr != nil {
		res.PlatformTCB = platformErr.Error()
	}
	if err := errors.Join(platformErr, rateErr, moduleErr); err != nil {
		return res, fmt.Errorf("authentic, but the broker would refuse it: %w", err)
	}
	return res, nil
}

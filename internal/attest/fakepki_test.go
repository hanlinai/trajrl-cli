package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
)

// fakePKI is a stand-in for Intel's attestation PKI and collateral service,
// for tests only. It takes a genuine quote and re-signs it under keys made
// here: a root, a PCK platform CA, a PCK certificate carrying the genuine
// certificate's SGX extension, and a TCB signing certificate. It then serves
// TCB info, QE identity and CRLs signed by those keys.
//
// What that buys: refusal conditions that cannot be produced with material
// Intel signed. Nobody outside Intel can make a quote from a revoked PCK
// certificate, collateral that rates a platform Revoked, or a quote from a
// DEBUG TD on demand.
//
// What it does not show: anything about Intel's real PKI. A verifier that has
// not been handed fakePKI's root refuses all of it (see the "untrusted root"
// rows), and the only way to hand it over is an unexported field of TDX.
type fakePKI struct {
	t   *testing.T
	now time.Time

	rootKey, interKey, pckKey, tcbKey, attKey *ecdsa.PrivateKey
	root, inter, pck, tcbCert                 *x509.Certificate

	genuine []byte // the genuine quote this PKI re-signs

	// Collateral as served. Tests edit these before verifying.
	tcbInfo, qeIdentity     map[string]any
	rootRevoked, pckRevoked []*big.Int
	rootCRLNext, pckCRLNext time.Time
	// fail makes a fetch fail; tamper edits a response after it was signed.
	fail   func(url string) error
	tamper func(url string, body []byte) []byte
	// crlSigner, if set, signs the PCK CRL instead of the PCK CA key.
	pckCRLKey *ecdsa.PrivateKey
	// detachAttKey signs the quote with a key the QE report does not vouch for.
	detachAttKey bool

	urlTCB, urlQE, urlPckCRL, urlRootCRL string
	fetched                              []string
}

var oidSGXExtensions = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signedData(q any) *pb.Ecdsa256BitQuoteV4AuthData {
	switch x := q.(type) {
	case *pb.QuoteV4:
		return x.GetSignedData()
	case *pb.QuoteV5:
		return x.GetSignedData()
	}
	return nil
}

// genuinePCK returns the PCK leaf certificate inside a genuine quote.
func genuinePCK(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	chain := signedData(q).GetCertificationData().GetQeReportCertificationData().GetPckCertificateChainData().GetPckCertChain()
	block, _ := pem.Decode(chain)
	if block == nil {
		t.Fatal("no PCK certificate in the quote")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// newFakePKI builds the PKI around a genuine quote. collateral is a recording
// of Intel's responses (see tcb_test.go) used as the starting point for what
// is served; now is the time verification will be pinned to.
func newFakePKI(t *testing.T, genuine []byte, collateral string, now time.Time) *fakePKI {
	t.Helper()
	f := &fakePKI{t: t, now: now, genuine: genuine,
		rootCRLNext: now.Add(30 * 24 * time.Hour), pckCRLNext: now.Add(30 * 24 * time.Hour)}
	f.rootKey, f.interKey, f.pckKey, f.tcbKey, f.attKey = newKey(t), newKey(t), newKey(t), newKey(t), newKey(t)

	// Recorded Intel responses: the URLs to answer, and the JSON to start from.
	raw, err := os.ReadFile(collateral)
	if err != nil {
		t.Fatal(err)
	}
	var recorded map[string]pcsResponse
	if err := json.Unmarshal(raw, &recorded); err != nil {
		t.Fatal(err)
	}
	inner := func(body []byte, name string) map[string]any {
		var outer map[string]json.RawMessage
		if err := json.Unmarshal(body, &outer); err != nil {
			t.Fatal(err)
		}
		d := json.NewDecoder(bytes.NewReader(outer[name]))
		d.UseNumber()
		var m map[string]any
		if err := d.Decode(&m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for u, r := range recorded {
		switch {
		case strings.Contains(u, "/tcb?fmspc="):
			f.tcbInfo = inner(r.Body, "tcbInfo")
		case strings.Contains(u, "/qe/identity"):
			f.urlQE, f.qeIdentity = u, inner(r.Body, "enclaveIdentity")
		case strings.Contains(u, "pckcrl"):
			f.urlPckCRL = u
		default:
			f.urlRootCRL = u
		}
	}
	if f.tcbInfo == nil || f.qeIdentity == nil || f.urlPckCRL == "" || f.urlRootCRL == "" {
		t.Fatalf("%s lacks one of: TCB info, QE identity, PCK CRL, root CRL", collateral)
	}

	// The platform is whatever the genuine PCK certificate says it is.
	real := genuinePCK(t, genuine)
	ext, err := pcs.PckCertificateExtensions(real)
	if err != nil {
		t.Fatal(err)
	}
	f.tcbInfo["fmspc"], f.tcbInfo["pceId"] = strings.ToUpper(ext.FMSPC), strings.ToUpper(ext.PCEID)
	f.urlTCB = pcs.TcbInfoURL(ext.FMSPC)
	var sgx pkix.Extension
	for _, e := range real.Extensions {
		if e.Id.Equal(oidSGXExtensions) {
			sgx = e
		}
	}
	if sgx.Id == nil {
		t.Fatal("genuine PCK certificate has no SGX extension")
	}

	from, to := now.AddDate(-1, 0, 0), now.AddDate(5, 0, 0)
	mk := func(cn string, serial int64, ca bool, pub *ecdsa.PublicKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, extra ...pkix.Extension) *x509.Certificate {
		ski := sha256.Sum256(rawPub(pub))
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial),
			Subject:   pkix.Name{CommonName: cn, Organization: []string{"Test stand-in, not Intel"}},
			NotBefore: from, NotAfter: to, BasicConstraintsValid: true, IsCA: ca, SubjectKeyId: ski[:20],
			CRLDistributionPoints: []string{f.urlRootCRL}, ExtraExtensions: extra}
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		if ca {
			tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	// The names are the ones the verifier requires of Intel's certificates.
	f.root = mk("Intel SGX Root CA", 1, true, &f.rootKey.PublicKey, nil, f.rootKey)
	f.inter = mk("Intel SGX PCK Platform CA", 2, true, &f.interKey.PublicKey, f.root, f.rootKey)
	f.pck = mk("Intel SGX PCK Certificate", 3, false, &f.pckKey.PublicKey, f.inter, f.interKey, sgx)
	f.tcbCert = mk("Intel SGX TCB Signing", 4, false, &f.tcbKey.PublicKey, f.root, f.rootKey)
	return f
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func signRaw(t *testing.T, key *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

// rawPub is the 64-byte X||Y form a quote carries its attestation key in.
func rawPub(k *ecdsa.PublicKey) []byte {
	b, err := k.Bytes() // 0x04 || X || Y
	if err != nil {
		panic(err)
	}
	return b[1:]
}

// quote returns the genuine quote re-signed under this PKI, after mut (if any)
// has edited its header or body. Everything Intel-signed in the original is
// replaced; the TD measurements and the QE report's identity fields are kept.
func (f *fakePKI) quote(mut func(q any)) []byte {
	f.t.Helper()
	q, err := abi.QuoteToProto(f.genuine)
	if err != nil {
		f.t.Fatal(err)
	}
	if mut != nil {
		mut(q)
	}
	sd := signedData(q)
	cd := sd.GetCertificationData()
	qr := cd.GetQeReportCertificationData()
	pc := qr.GetPckCertificateChainData()

	chain := append(append(pemCert(f.pck), pemCert(f.inter)...), pemCert(f.root)...)
	delta := int64(len(chain)) - int64(pc.GetSize())
	pc.PckCertChain, pc.Size = chain, uint32(len(chain))
	cd.Size = uint32(int64(cd.GetSize()) + delta)
	switch x := q.(type) {
	case *pb.QuoteV4:
		x.SignedDataSize = uint32(int64(x.GetSignedDataSize()) + delta)
	case *pb.QuoteV5:
		x.SignedDataSize = int32(int64(x.GetSignedDataSize()) + delta)
	}

	// The QE report vouches for the attestation key: its report data is
	// SHA-256(attestation key || QE auth data). The PCK key signs the QE report.
	sd.EcdsaAttestationKey = rawPub(&f.attKey.PublicKey)
	h := sha256.Sum256(append(append([]byte(nil), sd.EcdsaAttestationKey...), qr.GetQeAuthData().GetData()...))
	qr.QeReport.ReportData = append(h[:], make([]byte, 32)...)
	qe, err := abi.EnclaveReportToAbiBytes(qr.GetQeReport())
	if err != nil {
		f.t.Fatal(err)
	}
	qr.QeReportSignature = signRaw(f.t, f.pckKey, qe)

	signer := f.attKey
	if f.detachAttKey {
		signer = newKey(f.t)
		sd.EcdsaAttestationKey = rawPub(&signer.PublicKey)
	}
	raw, err := abi.QuoteToAbiBytes(q)
	if err != nil {
		f.t.Fatal(err)
	}
	signed := 48 + 584 // v4: header and TD quote body
	if v5, ok := q.(*pb.QuoteV5); ok {
		signed = 48 + 2 + 4 + int(v5.GetTdQuoteBodyDescriptor().GetTdQuoteBodySize())
	}
	sd.Signature = signRaw(f.t, signer, raw[:signed])
	if raw, err = abi.QuoteToAbiBytes(q); err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fakePKI) signedJSON(name string, m map[string]any) []byte {
	inner, err := json.Marshal(m)
	if err != nil {
		f.t.Fatal(err)
	}
	return []byte(fmt.Sprintf(`{%q:%s,"signature":%q}`, name, inner, hex.EncodeToString(signRaw(f.t, f.tcbKey, inner))))
}

func (f *fakePKI) crl(issuer *x509.Certificate, key *ecdsa.PrivateKey, revoked []*big.Int, next time.Time) []byte {
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.now.Add(-time.Hour), NextUpdate: next}
	for _, s := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: s, RevocationTime: f.now.Add(-2 * time.Hour)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return der
}

// Get answers the verifier's collateral requests (trust.HTTPSGetter).
func (f *fakePKI) Get(u string) (map[string][]string, []byte, error) {
	f.fetched = append(f.fetched, u)
	if f.fail != nil {
		if err := f.fail(u); err != nil {
			return nil, nil, err
		}
	}
	chain := func(signer *x509.Certificate) []string {
		return []string{url.QueryEscape(string(append(pemCert(signer), pemCert(f.root)...)))}
	}
	var h map[string][]string
	var body []byte
	switch u {
	case f.urlTCB:
		h, body = map[string][]string{pcs.TcbInfoIssuerChainPhrase: chain(f.tcbCert)}, f.signedJSON("tcbInfo", f.tcbInfo)
	case f.urlQE:
		h, body = map[string][]string{pcs.SgxQeIdentityIssuerChainPhrase: chain(f.tcbCert)}, f.signedJSON("enclaveIdentity", f.qeIdentity)
	case f.urlPckCRL:
		key := f.interKey
		if f.pckCRLKey != nil {
			key = f.pckCRLKey
		}
		h, body = map[string][]string{pcs.SgxPckCrlIssuerChainPhrase: chain(f.inter)}, f.crl(f.inter, key, f.pckRevoked, f.pckCRLNext)
	case f.urlRootCRL:
		body = f.crl(f.root, f.rootKey, f.rootRevoked, f.rootCRLNext)
	default:
		return nil, nil, fmt.Errorf("fakePKI: unexpected request for %s", u)
	}
	if f.tamper != nil {
		body = f.tamper(u, body)
	}
	return h, body, nil
}

// verifier returns a TDX verifier that trusts this PKI's root instead of
// Intel's and reads this PKI's collateral, at the pinned time. Nothing else
// about it differs from the production verifier.
func (f *fakePKI) verifier(pol *Policy) *TDX {
	pool := x509.NewCertPool()
	pool.AddCert(f.root)
	return &TDX{Policy: pol, getter: f, now: func() time.Time { return f.now }, roots: pool}
}

// --- edits to the served collateral ---

func levels(m map[string]any) []any { return m["tcbLevels"].([]any) }

func setStatus(lv []any, status string, advisories ...string) {
	for _, l := range lv {
		l.(map[string]any)["tcbStatus"] = status
		ids := []any{}
		for _, a := range advisories {
			ids = append(ids, a)
		}
		l.(map[string]any)["advisoryIDs"] = ids
	}
}

// module returns the collateral's identity entry for TDX module major version 1.
func (f *fakePKI) module() map[string]any {
	for _, i := range f.tcbInfo["tdxModuleIdentities"].([]any) {
		if m := i.(map[string]any); m["id"] == "TDX_01" {
			return m
		}
	}
	f.t.Fatal("collateral has no TDX_01 module identity")
	return nil
}

// allCurrent rates every level of the platform, the TDX module and the
// quoting enclave UpToDate: the platform Intel would describe if the hardware
// behind the genuine quote had been fully patched.
func (f *fakePKI) allCurrent() *fakePKI {
	setStatus(levels(f.tcbInfo), "UpToDate")
	setStatus(levels(f.module()), "UpToDate")
	setStatus(levels(f.qeIdentity), "UpToDate")
	return f
}

// anyPlatform replaces the platform TCB levels with a single level that every
// platform meets, so that a quote from other hardware than the recording's
// can be rated. Used for the v5 fixture.
func (f *fakePKI) anyPlatform() *fakePKI {
	zeros := func() []any {
		out := make([]any, 16)
		for i := range out {
			out[i] = map[string]any{"svn": 0}
		}
		return out
	}
	f.tcbInfo["tcbLevels"] = []any{map[string]any{
		"tcb":     map[string]any{"sgxtcbcomponents": zeros(), "pcesvn": 0, "tdxtcbcomponents": zeros()},
		"tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate", "advisoryIDs": []any{}}}
	f.module()["tcbLevels"] = []any{map[string]any{
		"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate", "advisoryIDs": []any{}}}
	f.qeIdentity["tcbLevels"] = []any{map[string]any{
		"tcb": map[string]any{"isvsvn": 0}, "tcbDate": "2026-01-01T00:00:00Z", "tcbStatus": "UpToDate", "advisoryIDs": []any{}}}
	return f
}

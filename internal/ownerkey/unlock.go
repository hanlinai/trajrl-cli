package ownerkey

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// Timeouts of an unlock session. Variables so that tests can shorten them;
// nothing else assigns to them.
var (
	// helloTimeout: the TD is already connected when the platform hands the
	// session over, so its handshake and hello come at once.
	helloTimeout = time.Minute
	// sessionTimeout: from the challenge to the evidence (the TD obtains a
	// quote), and the bound on the verification.
	sessionTimeout = 2 * time.Minute
	// bootTimeout: from the release to the TD's answer. A first boot formats
	// the disk and copies the base image first.
	bootTimeout = 2 * time.Hour
)

const maxLine = 64 << 10

// Unlock is one unlock of one sandbox: the server side of the guest's boot
// protocol (internal/guest), run by the owner's tool on the connection the
// platform relays from the TD.
type Unlock struct {
	// Verifier is the production verifier (attest.TDX with the owner's
	// launch policies). Nothing in a normal build of this package relaxes
	// it; only a binary built with the tag "rehearsal" can skip it, for a
	// TD that offers no quote at all (evidence_rehearsal.go).
	Verifier attest.Verifier
	Master   *Master
	State    *State
	// Name is the sandbox's name at the platform; SandboxID is the ID the
	// platform said the connection is from. The TD's own hello must name
	// the same ID, and its quote must prove it.
	Name      string
	SandboxID string
	// New: this unlock follows the sandbox's creation; a record of an
	// earlier sandbox of the same name is replaced instead of refused, and
	// a first boot (a blank disk formatted) is accepted.
	New bool
	// FirstBoot accepts a first boot without New (a sandbox created
	// elsewhere that has never booted). Otherwise a blank disk is refused:
	// the release says provisioned, and the guest does not format.
	FirstBoot bool
	// AuthorizedKeys and SetupScript are installed by a first boot only.
	AuthorizedKeys string
	SetupScript    string
	// Image and RegistryAuth (#38): the sandbox's own image, by digest
	// (proto.ParseImageRef), and the credential for its registry. Sent with
	// a first boot only, like the setup script; the TD pulls and verifies
	// the image itself. The platform never sees either.
	Image        string
	RegistryAuth string
	// AcceptOlder / AcceptNewer, if not 0, accept a disk at exactly this
	// boot epoch when it is older than the record (a snapshot the owner put
	// back on purpose) / newer (booted from another machine of the owner's).
	// A refused unlock says which number that would be.
	AcceptOlder, AcceptNewer uint64
	// KnownHosts are the host names the pinned SSH host key is written for
	// (default: Name).
	KnownHosts []string
	// WebNames (#113) are the sandbox's names at the platform's web router
	// that its web server may obtain certificates for (proto.CheckWebNames;
	// sbxkey takes them from the platform's view and keeps the sandbox's
	// own). Sent with every release, first boot or not, an empty list as
	// "web_names":[] (#118): the TD replaces the list on its disk with
	// them, and gets no certificate for any name when it is empty.
	WebNames []string
	// KeyStatement (#65) is the account's latest owner-signed statement of
	// SSH keys, as the platform relays it (sbxkey fetches it before every
	// unlock). Sent with every release; the sandbox applies it only if a
	// key it trusts signed it. Empty: none, the keys stay as they are.
	KeyStatement string
}

// Outcome is what an unlock established.
type Outcome struct {
	SandboxID string
	Quote     *attest.Result
	// Mode is the evidence the secret was released on: proto.ModeTDX, a
	// verified quote, in every normal build. Only a binary built with the
	// tag "rehearsal" can release on proto.ModeDev (no quote at all).
	Mode string
	// Released: the disk secret was sent (after a verified quote).
	Released bool
	// FirstBoot: the TD formatted a blank disk; HostKey is the SSH host key
	// it reported and KnownHostsLine the line pinned for it.
	FirstBoot      bool
	HostKey        string
	KnownHostsLine string
	// Epoch is the boot epoch confirmed.
	Epoch uint64
	// Notes are things the owner should know, in order.
	Notes []string
}

// errRefused is the only detail the TD is told on a refusal; the owner's
// tool reports the cause to the owner.
const errRefused = "key release refused"

// selfSigned makes the session's TLS certificate. Nothing pins it: the TD
// relies on the binding of its quote to this session's exporter, which this
// side checks against its own session.
func selfSigned() (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "tdx-sandbox owner unlock"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

func readMsg(r *bufio.Reader, want ...string) (*proto.Msg, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("the TD closed or went silent while %s was due: %w", strings.Join(want, " or "), err)
	}
	var m proto.Msg
	if json.Unmarshal(line, &m) != nil {
		return nil, fmt.Errorf("the TD sent something that is not a message (%s was due)", strings.Join(want, " or "))
	}
	for _, w := range want {
		if m.Type == w {
			return &m, nil
		}
	}
	if m.Type == proto.TypeError {
		return nil, fmt.Errorf("the TD reported an error: %.200q", m.Error)
	}
	return nil, fmt.Errorf("the TD sent %q, %s was due", m.Type, strings.Join(want, " or "))
}

// Serve runs the unlock on raw, the byte stream the platform relays from the
// TD, and closes it. An error means the sandbox was not unlocked; the
// outcome says how far it got (in particular whether the secret was sent).
func (u *Unlock) Serve(raw net.Conn) (*Outcome, error) {
	defer raw.Close()
	out := &Outcome{SandboxID: u.SandboxID}
	if u.Verifier == nil || u.Master == nil || u.State == nil {
		return out, errors.New("unlock: verifier, master secret and state are required")
	}
	if !proto.ValidSandboxID(u.SandboxID) {
		return out, fmt.Errorf("the platform named no valid sandbox ID (%q)", u.SandboxID)
	}
	if err := proto.CheckWebNames(u.WebNames); err != nil {
		return out, err
	}
	if len(u.KeyStatement) > proto.MaxKeyStatement {
		return out, fmt.Errorf("the key statement has %d bytes, more than %d", len(u.KeyStatement), proto.MaxKeyStatement)
	}
	cert, err := selfSigned()
	if err != nil {
		return out, err
	}
	c := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	defer c.Close()
	enc := json.NewEncoder(c)
	refuse := func(err error) (*Outcome, error) {
		enc.Encode(proto.Msg{Type: proto.TypeError, Error: errRefused})
		return out, err
	}

	c.SetDeadline(time.Now().Add(helloTimeout))
	if err := c.Handshake(); err != nil {
		return out, fmt.Errorf("TLS with the TD: %w", err)
	}
	st := c.ConnectionState()
	// The exporter of THIS side's session. A TD's quote is accepted only if
	// its report data commits to it: a host that terminates the TD's TLS
	// and opens its own session to this tool cannot bring a matching quote.
	exporter, err := st.ExportKeyingMaterial(proto.ExporterLabel, nil, proto.ExporterLen)
	if err != nil {
		return out, err
	}
	r := bufio.NewReaderSize(c, maxLine)

	hello, err := readMsg(r, proto.TypeHello)
	if err != nil {
		return out, err
	}
	// Epochs are what lets the owner's record catch a rolled-back disk: a
	// guest that does not speak them is not served.
	if hello.Version != proto.Version {
		return refuse(fmt.Errorf("the TD speaks protocol version %d; this tool requires %d", hello.Version, proto.Version))
	}
	if hello.SandboxID != u.SandboxID {
		return refuse(fmt.Errorf("the platform said this connection is from %s, the TD says it is %.40q", u.SandboxID, hello.SandboxID))
	}
	rec := u.State.Get(u.SandboxID)
	if rec != nil && rec.Name != u.Name {
		return refuse(fmt.Errorf("the platform says %q is %s, which your record knows as %q", u.Name, u.SandboxID, rec.Name))
	}
	if byName := u.State.ByName(u.Name); byName != nil && byName.ID != u.SandboxID && !u.New {
		return refuse(fmt.Errorf("the platform says %q is %s; your record says %q is %s. If %q was deleted and made again, unlock it with 'new' or remove its record", u.Name, u.SandboxID, u.Name, byName.ID, u.Name))
	}

	nonce := make([]byte, proto.NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return out, err
	}
	c.SetDeadline(time.Now().Add(sessionTimeout))
	if err := enc.Encode(proto.Msg{Type: proto.TypeChallenge, Nonce: nonce}); err != nil {
		return out, err
	}
	ev, err := readMsg(r, proto.TypeEvidence)
	if err != nil {
		return out, err
	}
	// checkEvidence is verifyQuote in every normal build (evidence.go);
	// only a binary built with the tag "rehearsal" has another
	// (evidence_rehearsal.go).
	mode, res, err := u.checkEvidence(ev, nonce, exporter)
	out.Quote, out.Mode = res, mode
	if err != nil {
		return refuse(err)
	}

	// Verified: this is a genuine TD of the expected image, launched as this
	// sandbox, in this very TLS session, before its boot stage ended.
	secret, err := u.Master.DiskSecret(u.SandboxID)
	if err != nil {
		return refuse(err)
	}
	// BindRTMR3: the TD commits RTMR3 to this secret, so a quote of the
	// running sandbox shows that the owner's key unlocked it (sbxverify
	// -owner-key).
	firstBootOK := u.New || u.FirstBoot
	// The web names go even when there are none: a guest of the image
	// revision 17 on refuses a release without the field (#118).
	webNames := u.WebNames
	if webNames == nil {
		webNames = []string{}
	}
	rel := proto.Msg{Type: proto.TypeRelease, Mode: mode, DiskSecret: secret,
		AuthorizedKeys: u.AuthorizedKeys, BindRTMR3: true, WebNames: webNames, KeyStatement: u.KeyStatement}
	if u.AcceptOlder != 0 && u.AcceptNewer != 0 {
		clear(secret)
		return refuse(errors.New("-accept-older and -accept-newer together: the disk is at one epoch"))
	}
	switch {
	case rec == nil || !rec.Provisioned:
		// No record on this machine: the disk is accepted at whatever epoch
		// it is (trust on first use). A blank one is formatted only if a
		// first boot was asked for.
		rel.EpochOverride = true
		rel.Provisioned = !firstBootOK
		if firstBootOK {
			rel.SetupScript = u.SetupScript
			rel.Image, rel.RegistryAuth = u.Image, u.RegistryAuth
		}
	default:
		rel.Epoch, rel.Provisioned = rec.Epoch, true
		switch {
		case u.AcceptOlder != 0 && u.AcceptOlder < rec.Epoch:
			rel.AcceptEpoch = u.AcceptOlder
		case u.AcceptOlder != 0:
			out.Notes = append(out.Notes, fmt.Sprintf("-accept-older %d ignored: your record is at boot %d, so a disk at %d is not older", u.AcceptOlder, rec.Epoch, u.AcceptOlder))
		case u.AcceptNewer != 0 && u.AcceptNewer > rec.Epoch+1:
			rel.AcceptEpoch = u.AcceptNewer
		case u.AcceptNewer != 0:
			out.Notes = append(out.Notes, fmt.Sprintf("-accept-newer %d ignored: your record is at boot %d, and a disk at %d needs no acceptance", u.AcceptNewer, rec.Epoch, u.AcceptNewer))
		}
	}
	if rec != nil && rec.Provisioned && u.SetupScript != "" {
		out.Notes = append(out.Notes, "the setup script was not sent: your record says this sandbox has had its first boot")
	}
	if rec != nil && rec.Provisioned && u.Image != "" {
		out.Notes = append(out.Notes, "the image was not sent: your record says this sandbox has had its first boot, and keeps the image it was created from")
	}
	c.SetDeadline(time.Now().Add(bootTimeout))
	err = enc.Encode(rel)
	clear(secret)
	if err != nil {
		return out, fmt.Errorf("sending the release: %w", err)
	}
	out.Released = true

	m, err := readMsg(r, proto.TypeProvisioned, proto.TypeEpoch, proto.TypeRollback, proto.TypeBlankDisk)
	if err != nil {
		return out, err
	}
	pol := ""
	if res != nil {
		pol = res.Policy
	}
	switch m.Type {
	case proto.TypeBlankDisk:
		why := "this unlock is not a first boot (that is '" + Command("new NAME") + "', or -first-boot for a sandbox that has never booted)"
		if rec != nil && rec.Provisioned {
			why = fmt.Sprintf("your record says it was provisioned (boot epoch %d)", rec.Epoch)
		}
		return out, fmt.Errorf("REFUSED: the platform gave %s a blank disk; %s. The TD did not format it and stops", u.Name, why)
	case proto.TypeProvisioned:
		return u.firstBoot(c, enc, rec, m, pol, out, firstBootOK)
	case proto.TypeRollback:
		return u.rollback(rec, m, pol, out)
	}
	// TypeEpoch: the disk opened and the guest moved its epoch on.
	next := m.Epoch
	if next == 0 || next >= 1<<62 {
		return refuse(fmt.Errorf("the TD reported boot epoch %d", next))
	}
	var note string
	switch {
	case rec == nil || !rec.Provisioned:
		note = fmt.Sprintf("trust on first use: this machine had no record of %s; its disk was accepted as it is (now at boot %d). A disk put back to an older copy before today cannot be told apart", u.Name, next)
		rec = &Record{ID: u.SandboxID, Name: u.Name, FirstUse: true}
	case next == rec.Epoch+1:
		// The disk was at the record's epoch, or one past it (a boot whose
		// confirmation was lost), or, older, at exactly the accepted one.
		if rel.AcceptEpoch != 0 && rel.AcceptEpoch < rec.Epoch {
			note = fmt.Sprintf("-accept-older %d: if the disk was at boot %d it was accepted; the record moves from %d to %d", rel.AcceptEpoch, rel.AcceptEpoch, rec.Epoch, next)
		}
	case rel.AcceptEpoch > rec.Epoch+1 && next == rel.AcceptEpoch+1:
		note = fmt.Sprintf("-accept-newer %d: %s's disk was at boot %d, newer than this machine's record (%d); the record now says %d", rel.AcceptEpoch, u.Name, rel.AcceptEpoch, rec.Epoch, next)
	default:
		return refuse(fmt.Errorf("the TD reported boot epoch %d; your record is at %d, which allows no such answer", next, rec.Epoch))
	}
	rec.Provisioned, rec.Epoch, rec.Policy = true, next, pol
	if err := u.State.Put(*rec, false); err != nil {
		return refuse(fmt.Errorf("the boot epoch could not be recorded, so the boot is not confirmed: %w", err))
	}
	if note != "" {
		out.Notes = append(out.Notes, note)
	}
	if rec.SSHHostKey == "" {
		out.Notes = append(out.Notes, "this machine has no SSH host key pinned for "+u.Name+" (its first boot was confirmed elsewhere). Check the sandbox with '"+VerifyOwnerCommand(u.Name)+"': it shows that the TD answering SSH holds the host key in its quote and was unlocked with your key, and prints that key")
	}
	out.Epoch = next
	if err := enc.Encode(proto.Msg{Type: proto.TypeAck}); err != nil {
		return out, fmt.Errorf("the boot epoch %d is recorded, the TD's confirmation was not delivered: %w", next, err)
	}
	return out, nil
}

// verifyQuote is the only check of a TD's evidence in a normal build: an
// attested TDX boot whose quote the owner's verifier accepts, bound to this
// sandbox, this challenge and this TLS session. There is no unattested path
// here, for any sandbox.
func (u *Unlock) verifyQuote(ev *proto.Msg, nonce, exporter []byte) (string, *attest.Result, error) {
	if ev.Mode != proto.ModeTDX {
		return "", nil, fmt.Errorf("the TD offered evidence of mode %.40q; only an attested TDX boot is unlocked", ev.Mode)
	}
	rd := proto.ReportData(u.SandboxID, nonce, exporter)
	ctx, cancel := context.WithTimeout(context.Background(), sessionTimeout/2)
	res, err := u.Verifier.Verify(ctx, ev.Quote, rd, u.SandboxID)
	cancel()
	if err != nil {
		return "", res, fmt.Errorf("the TD's quote does not verify: %w", err)
	}
	return proto.ModeTDX, res, nil
}

func (u *Unlock) firstBoot(c *tls.Conn, enc *json.Encoder, rec *Record, m *proto.Msg, pol string, out *Outcome, firstBootOK bool) (*Outcome, error) {
	out.FirstBoot = true
	refuse := func(err error) (*Outcome, error) {
		enc.Encode(proto.Msg{Type: proto.TypeError, Error: "first boot not confirmed by the owner"})
		return out, err
	}
	// The release said provisioned in both these cases, so a guest that
	// formatted anyway is not following the protocol.
	if rec != nil && rec.Provisioned {
		return refuse(fmt.Errorf("REFUSED: the platform gave %s a blank disk, and the TD formatted it although told the sandbox was provisioned (your record: boot epoch %d)", u.Name, rec.Epoch))
	}
	if !firstBootOK {
		return refuse(fmt.Errorf("REFUSED: the platform gave %s a blank disk, and the TD formatted it although no first boot was asked for", u.Name))
	}
	if m.Epoch != 1 {
		return refuse(fmt.Errorf("the TD reported its first boot at epoch %d, not 1", m.Epoch))
	}
	key := strings.TrimSpace(m.SSHHostPubKey)
	pk, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil || len(rest) != 0 || pk.Type() != ssh.KeyAlgoED25519 {
		return refuse(errors.New("the TD reported no valid SSH host key"))
	}
	key = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	hosts := u.KnownHosts
	if len(hosts) == 0 {
		hosts = []string{u.Name}
	}
	// The host key goes on record before the TD is told to go on: it is
	// what lets the owner tell this TD from any other the host could put in
	// its place afterwards.
	// Only the confirmed first boot of 'new' replaces a host key pinned
	// before (a sandbox of the same ID made anew).
	// So does the image it was asked to be made of (#112): its running TD
	// must show it in RTMR3, which sbxverify -owner-key checks.
	if err := u.State.Put(Record{ID: u.SandboxID, Name: u.Name, Provisioned: true, Epoch: 1, SSHHostKey: key, Policy: pol,
		Image: u.Image, ImageDigest: ImageDigestOf(u.Image)}, u.New); err != nil {
		return refuse(fmt.Errorf("the first boot could not be recorded, so it is not confirmed: %w", err))
	}
	line, err := u.State.PinHostKey(hosts, key)
	if err != nil {
		return refuse(fmt.Errorf("the SSH host key could not be pinned, so the first boot is not confirmed: %w", err))
	}
	out.HostKey, out.KnownHostsLine, out.Epoch = key, line, 1
	if err := enc.Encode(proto.Msg{Type: proto.TypeAck}); err != nil {
		return out, fmt.Errorf("the first boot is recorded, the TD's confirmation was not delivered: %w", err)
	}
	return out, nil
}

// rollback: the guest found its disk at another epoch than the record's (and
// not at one the owner accepted) and has stopped. It said so inside the
// attested session, so the epoch is the TD's own report. Nothing is
// confirmed; the owner is told the number that would accept the disk.
func (u *Unlock) rollback(rec *Record, m *proto.Msg, pol string, out *Outcome) (*Outcome, error) {
	d := m.Epoch
	if rec == nil {
		return out, fmt.Errorf("the TD refused its disk at boot epoch %d although this unlock accepted any", d)
	}
	given := ""
	switch {
	case u.AcceptOlder != 0:
		given = fmt.Sprintf(" (-accept-older %d was given; the disk is at %d.)", u.AcceptOlder, d)
	case u.AcceptNewer != 0:
		given = fmt.Sprintf(" (-accept-newer %d was given; the disk is at %d.)", u.AcceptNewer, d)
	}
	switch {
	case d < rec.Epoch:
		return out, fmt.Errorf("REFUSED: this disk is at boot %d; your record says %d (older by %d boots): the platform put back an older copy of %s's disk, and the sandbox stops.%s\nIf this is the snapshot you restored, run: %s", d, rec.Epoch, rec.Epoch-d, u.Name, given, Command(fmt.Sprintf("start %s -accept-older %d", u.Name, d)))
	case d > rec.Epoch+1:
		return out, fmt.Errorf("REFUSED: this disk is at boot %d, newer than your record %d; the sandbox stops.%s\nIf you started it from another machine of yours, run: %s", d, rec.Epoch, given, Command(fmt.Sprintf("start %s -accept-newer %d", u.Name, d)))
	}
	return out, fmt.Errorf("the TD refused its disk at boot epoch %d, which your record (%d) accepts", d, rec.Epoch)
}

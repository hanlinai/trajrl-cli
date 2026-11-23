package sbxapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func key(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	return priv, sp
}

// A TLS server presenting a certificate of srvKey, which records whether
// anything was read after the handshake.
func fakeServer(t *testing.T, srvKey ed25519.PrivateKey) (string, chan []byte) {
	t.Helper()
	cert, err := SelfSigned(srvKey, true)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan []byte, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				b, _ := io.ReadAll(io.LimitReader(c, 4096))
				got <- b
			}()
		}
	}()
	return l.Addr().String(), got
}

// The client accepts the server only with the pinned key, and sends nothing
// to another.
func TestPinRefusesOtherServerKey(t *testing.T) {
	user, _ := key(t)
	real, realPub := key(t)
	impostor, _ := key(t)
	addr, got := fakeServer(t, impostor)
	c := &Client{Addr: addr, ServerName: "web-alice.sbx.example", Pin: realPub, Key: user}
	_, err := c.Run(context.Background(), Exec{Argv: []string{"true"}}, io.Discard, io.Discard)
	if !errors.Is(err, ErrPin) {
		t.Fatalf("an impostor's key: %v", err)
	}
	if b := <-got; len(b) != 0 {
		t.Fatalf("the client sent %d bytes to an impostor", len(b))
	}
	// The same server with the real key gets the request.
	addr, got = fakeServer(t, real)
	c = &Client{Addr: addr, ServerName: "web-alice.sbx.example", Pin: realPub, Key: user}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.Run(ctx, Exec{Argv: []string{"true"}}, io.Discard, io.Discard)
	if b := <-got; !bytes.HasPrefix(b, []byte("POST /v1/exec HTTP/1.1")) {
		t.Fatalf("the pinned server got %q", b)
	}
	// Only Ed25519 pins.
	if _, err := ParsePin("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDGr1 x"); err == nil {
		t.Error("an RSA pin was taken")
	}
	if k, err := ParsePin("web-alice.sbx.example " + KeyLine(realPub)); err != nil || KeyLine(k) != KeyLine(realPub) {
		t.Errorf("a known_hosts line: %v", err)
	}
}

// The client's certificate is self-signed by the user's own SSH key and
// carries that key; it offers the API's ALPN name and nothing else.
func TestAuthClientCertificate(t *testing.T) {
	user, userPub := key(t)
	_, pin := key(t)
	c := &Client{Pin: pin, Key: user, ServerName: "x"}
	cfg, err := c.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != ALPN || cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("ALPN %v, min version %x", cfg.NextProtos, cfg.MinVersion)
	}
	k, err := CertKey(cfg.Certificates[0].Certificate[0])
	if err != nil || KeyLine(k) != KeyLine(userPub) {
		t.Fatalf("the certificate carries %v: %v", k, err)
	}
	// A certificate whose self-signature does not hold is not accepted as
	// one of the key it names.
	der := append([]byte(nil), cfg.Certificates[0].Certificate[0]...)
	der[len(der)-1] ^= 1
	if _, err := CertKey(der); err == nil {
		t.Error("a certificate with a broken signature was read as the key's")
	}
	// The SSH key file as ssh-keygen writes it.
	dir := t.TempDir()
	block, _ := ssh.MarshalPrivateKey(user, "")
	os.WriteFile(filepath.Join(dir, "id"), pem.EncodeToMemory(block), 0o600)
	t.Setenv("SSH_AUTH_SOCK", "")
	s, err := LoadKey(filepath.Join(dir, "id"))
	if err != nil || !bytes.Equal(s.Public().(ed25519.PublicKey), user.Public().(ed25519.PublicKey)) {
		t.Fatalf("LoadKey: %v", err)
	}
}

// sbxverify's record: written after a verification, found by the sandbox's
// name, its ID or its host name at the web router.
func TestPinRecord(t *testing.T) {
	_, pub := key(t)
	_, pub2 := key(t)
	f := filepath.Join(t.TempDir(), "sbx", "verified.json")
	ps, err := LoadPins(f)
	if err != nil || len(ps.Sandboxes) != 0 {
		t.Fatalf("no file: %v %v", ps, err)
	}
	if _, err := ps.Lookup("web"); err == nil || !strings.Contains(err.Error(), "run sbxverify") {
		t.Errorf("no record: %v", err)
	}
	p := Pin{Name: "web", ID: "sbx-0123456789abcdef", HostKey: KeyLine(pub), HTTPSURL: "https://web-alice.sbx.example", Verified: time.Now()}
	if err := RecordPin(f, p); err != nil {
		t.Fatal(err)
	}
	if err := RecordPin(f, Pin{Name: "db", ID: "sbx-1111111111111111", HostKey: KeyLine(pub2)}); err != nil {
		t.Fatal(err)
	}
	if err := RecordPin(f, Pin{Name: "x", ID: "y", HostKey: "not a key"}); err == nil {
		t.Error("a record without a key was written")
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	ps, _ = LoadPins(f)
	for _, name := range []string{"web", "sbx-0123456789abcdef", "web-alice.sbx.example"} {
		got, err := ps.Lookup(name)
		if err != nil || got.HostKey != KeyLine(pub) || got.Host() != "web-alice.sbx.example" {
			t.Errorf("lookup %s: %+v %v", name, got, err)
		}
	}
	// Verified again with another key (a new sandbox of the same name): the
	// record is replaced.
	p.HostKey = KeyLine(pub2)
	RecordPin(f, p)
	ps, _ = LoadPins(f)
	if got, _ := ps.Lookup("web"); got.HostKey != KeyLine(pub2) {
		t.Errorf("after a second verification: %+v", got)
	}
}

// A sandbox renamed (#72) and verified under its new name: its pin moves to
// the new name and its new host name, and the old name's pin, whose host
// name no longer reaches it, goes. Another sandbox's pin stays.
func TestPinRecordRename(t *testing.T) {
	_, pub := key(t)
	_, pub2 := key(t)
	f := filepath.Join(t.TempDir(), "verified.json")
	const id = "sbx-0123456789abcdef"
	RecordPin(f, Pin{Name: "web", ID: id, HostKey: KeyLine(pub), HTTPSURL: "https://web-alice.sbx.example"})
	RecordPin(f, Pin{Name: "db", ID: "sbx-1111111111111111", HostKey: KeyLine(pub2)})
	if err := RecordPin(f, Pin{Name: "site", ID: id, HostKey: KeyLine(pub), HTTPSURL: "https://site-alice.sbx.example"}); err != nil {
		t.Fatal(err)
	}
	ps, _ := LoadPins(f)
	if _, err := ps.Lookup("web"); err == nil {
		t.Error("the old name still has a pin")
	}
	for _, name := range []string{"site", id, "site-alice.sbx.example"} {
		if got, err := ps.Lookup(name); err != nil || got.Name != "site" || got.HostKey != KeyLine(pub) {
			t.Errorf("lookup %s: %+v %v", name, got, err)
		}
	}
	if _, err := ps.Lookup("db"); err != nil || len(ps.Sandboxes) != 2 {
		t.Errorf("another sandbox's pin: %v (%d pins)", err, len(ps.Sandboxes))
	}
}

// writeKey writes k as ssh-keygen does (OpenSSH format, no passphrase).
func writeKey(t *testing.T, path string, k crypto.Signer) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

// RSA (2048 bits or more) and ECDSA (P-256, P-384) user keys, besides
// Ed25519 (#118, #106): each loads from its key file, makes a certificate
// that carries it, and is refused below those sizes and on other curves.
func TestUserKeyTypes(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa3072, _ := rsa.GenerateKey(rand.Reader, 3072)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ed, _ := key(t)
	dir := t.TempDir()
	for name, k := range map[string]crypto.Signer{"rsa-2048": rsa2048, "rsa-3072": rsa3072, "ecdsa-p256": p256, "ecdsa-p384": p384, "ed25519": ed} {
		f := filepath.Join(dir, name)
		writeKey(t, f, k)
		s, err := LoadKey(f)
		if err != nil {
			t.Errorf("%s: LoadKey: %v", name, err)
			continue
		}
		want, _ := ssh.NewPublicKey(k.Public())
		_, pin := key(t)
		cfg, err := (&Client{Pin: pin, Key: s, ServerName: "x"}).TLSConfig()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got, err := CertKey(cfg.Certificates[0].Certificate[0])
		if err != nil || KeyLine(got) != KeyLine(want) {
			t.Errorf("%s: the certificate carries %v: %v", name, got, err)
		}
		// The certificate's self-signature is checked for every type.
		der := append([]byte(nil), cfg.Certificates[0].Certificate[0]...)
		der[len(der)-1] ^= 1
		if _, err := CertKey(der); err == nil {
			t.Errorf("%s: a certificate with a broken signature was read as the key's", name)
		}
	}
	// Refused: RSA under 2048 bits, ECDSA P-521.
	rsa1024, _ := rsa.GenerateKey(rand.Reader, 1024)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	for name, k := range map[string]crypto.Signer{"rsa-1024": rsa1024, "ecdsa-p521": p521} {
		f := filepath.Join(dir, name)
		writeKey(t, f, k)
		if _, err := LoadKey(f); err == nil {
			t.Errorf("%s: LoadKey took it", name)
		}
		if _, err := SelfSigned(k, false); err == nil {
			t.Errorf("%s: SelfSigned took it", name)
		}
		// A certificate made outside this package: CertKey refuses it too.
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CertKey(der); err == nil {
			t.Errorf("%s: CertKey took it", name)
		}
	}
	// No -i and no agent: the first of id_ed25519, id_ecdsa, id_rsa that
	// exists, as ssh picks one.
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.Mkdir(filepath.Join(home, ".ssh"), 0o700)
	if _, err := LoadKey(""); err == nil || !strings.Contains(err.Error(), "-i") {
		t.Errorf("no key at all: %v", err)
	}
	writeKey(t, filepath.Join(home, ".ssh", "id_rsa"), rsa2048)
	if s, err := LoadKey(""); err != nil || !s.Public().(*rsa.PublicKey).Equal(rsa2048.Public()) {
		t.Errorf("id_rsa alone: %v", err)
	}
	writeKey(t, filepath.Join(home, ".ssh", "id_ecdsa"), p256)
	if s, err := LoadKey(""); err != nil || !s.Public().(*ecdsa.PublicKey).Equal(p256.Public()) {
		t.Errorf("id_ecdsa before id_rsa: %v", err)
	}
}

// serveAgent runs an SSH agent holding keys on a unix socket and points
// SSH_AUTH_SOCK at it.
func serveAgent(t *testing.T, keys ...any) {
	t.Helper()
	ring := agent.NewKeyring()
	for _, k := range keys {
		if err := ring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(ring, c)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

// An SSH agent's key is used only if it is Ed25519 (an agent cannot sign
// as TLS 1.3 needs with RSA or ECDSA): an agent that holds only an RSA key
// leaves LoadKey to the key files, and one Ed25519 key among others is
// taken from the agent.
func TestAgentKeyTypes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.Mkdir(filepath.Join(home, ".ssh"), 0o700)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	writeKey(t, filepath.Join(home, ".ssh", "id_ecdsa"), p256)
	serveAgent(t, rsaKey)
	s, err := LoadKey("")
	if err != nil || !s.Public().(*ecdsa.PublicKey).Equal(p256.Public()) {
		t.Fatalf("an agent with only an RSA key: %v %T", err, s)
	}
	ed, edPub := key(t)
	serveAgent(t, rsaKey, ed)
	s, err = LoadKey("")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ssh.NewPublicKey(s.Public()); KeyLine(got) != KeyLine(edPub) {
		t.Fatalf("an agent with an Ed25519 key: took %T", s)
	}
	// It signs: a certificate made with it carries the agent's key.
	cert, err := SelfSigned(s, false)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := CertKey(cert.Certificate[0]); err != nil || KeyLine(k) != KeyLine(edPub) {
		t.Fatalf("the agent's certificate: %v", err)
	}
	ed2, _ := key(t)
	serveAgent(t, ed, ed2)
	if _, err := LoadKey(""); err == nil || !strings.Contains(err.Error(), "2 Ed25519 keys") {
		t.Fatalf("two Ed25519 keys in the agent: %v", err)
	}
}

// Package sbxapi is the client side of the HTTPS API that runs inside a
// sandbox (cmd/sandbox-api, issue #106): exec and files over mutual TLS that
// ends in the TD.
//
// Both ends are identified by SSH keys, never by anything the platform hands
// out:
//
//   - the server presents a certificate self-signed with the sandbox's SSH
//     host key (Ed25519). sbxverify proves that key belongs to the attested
//     TD (the quote's report data binds it) and records it; this package
//     accepts the server only if its key is that pin. No certificate
//     authority, no name check: the key is the identity.
//   - the client presents a certificate self-signed with the user's own SSH
//     key (Ed25519, RSA of 2048 bits or more, or ECDSA P-256 or P-384). The
//     server accepts it only if that key is in root's
//     authorized_keys inside the sandbox: the same rule as SSH, which only
//     someone with root in the sandbox can change.
//
// The platform's web router sees a TLS ClientHello with ALPN "sandbox-api/1"
// for NAME-ACCOUNT.DOMAIN and passes the bytes on to guest port 7443; it
// holds no certificate and reads nothing.
package sbxapi

import (
	"bufio"
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
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ALPN is the protocol name the web router routes to the API's port.
const ALPN = "sandbox-api/1"

// Port is the API's port inside the guest.
const Port = 7443

// MaxTimeout is the longest an exec may run, in seconds.
const MaxTimeout = 300

// SelfSigned makes a certificate for key, signed by key itself. The key must
// be one CheckKey accepts: Ed25519 (an ed25519.PrivateKey or a crypto.Signer
// whose public key is ed25519.PublicKey, such as a key held by an SSH
// agent), RSA of 2048 bits or more, or ECDSA P-256 or P-384. Only the key in
// it means anything; names and dates are filler, and generous dates keep a
// skewed clock from mattering.
func SelfSigned(key crypto.Signer, server bool) (tls.Certificate, error) {
	if err := CheckKey(key.Public()); err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	usage, cn := x509.ExtKeyUsageClientAuth, "sandbox-api client"
	if server {
		usage, cn = x509.ExtKeyUsageServerAuth, "sandbox-api"
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// MinRSABits is the smallest RSA key the API takes.
const MinRSABits = 2048

// CheckKey reports whether pub is a key the API takes from a user: Ed25519,
// RSA of MinRSABits or more, ECDSA on P-256 or P-384 (#106). The sandbox's
// own identity, its host key, is always Ed25519 (ParsePin).
func CheckKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return nil
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return fmt.Errorf("an RSA key of %d bits: the API takes RSA keys of %d bits or more", k.N.BitLen(), MinRSABits)
		}
		return nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
		return fmt.Errorf("an ECDSA key on %s: the API takes ECDSA keys on P-256 or P-384", k.Curve.Params().Name)
	}
	return fmt.Errorf("a %T key: the API takes Ed25519, RSA (%d bits or more) and ECDSA (P-256, P-384) keys", pub, MinRSABits)
}

// CertKey returns the SSH public key a certificate carries: the identity
// both ends check. Only the keys CheckKey takes are accepted.
func CertKey(der []byte) (ssh.PublicKey, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := CheckKey(c.PublicKey); err != nil {
		return nil, fmt.Errorf("the certificate's key: %w", err)
	}
	// A self-signed certificate whose signature does not hold is not one.
	if err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
		return nil, fmt.Errorf("the certificate is not signed by its own key: %w", err)
	}
	return ssh.NewPublicKey(c.PublicKey)
}

// KeyLine is a public key as authorized_keys and known_hosts write it,
// "ssh-ed25519 AAAA...", without a comment.
func KeyLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// ParsePin reads a pinned key: "ssh-ed25519 AAAA..." with or without a
// comment, or a known_hosts line ("host ssh-ed25519 AAAA...").
func ParsePin(s string) (ssh.PublicKey, error) {
	s = strings.TrimSpace(s)
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s)); err == nil {
		return checkEd25519(k)
	}
	if _, _, k, _, _, err := ssh.ParseKnownHosts([]byte(s)); err == nil {
		return checkEd25519(k)
	}
	return nil, fmt.Errorf("%q is not an SSH public key", s)
}

func checkEd25519(k ssh.PublicKey) (ssh.PublicKey, error) {
	if k.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("a %s key: only Ed25519 keys are supported", k.Type())
	}
	return k, nil
}

// DefaultKeyFiles are the files of ~/.ssh that LoadKey tries when it is
// given none and no SSH agent holds an Ed25519 key, in ssh's order.
var DefaultKeyFiles = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// LoadKey reads the user's SSH key: from keyFile, or with "" from the SSH
// agent at $SSH_AUTH_SOCK (its one Ed25519 key), or else the first of
// DefaultKeyFiles in ~/.ssh that exists. A key file may be Ed25519, RSA
// (2048 bits or more) or ECDSA (P-256, P-384); an agent's key only Ed25519:
// TLS 1.3 has an RSA key sign with RSA-PSS and an ECDSA key sign a digest,
// neither of which an SSH agent does.
func LoadKey(keyFile string) (crypto.Signer, error) {
	if keyFile == "" && os.Getenv("SSH_AUTH_SOCK") != "" {
		k, n, err := agentKey()
		if err != nil || n != 0 {
			return k, err
		}
		// The agent holds no Ed25519 key: a key file, as without one.
	}
	if keyFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		for _, name := range DefaultKeyFiles {
			p := filepath.Join(home, ".ssh", name)
			if _, err := os.Stat(p); err == nil {
				keyFile = p
				break
			}
		}
		if keyFile == "" {
			return nil, fmt.Errorf("no SSH key: give one with -i (none of %s in %s, and no Ed25519 key in an SSH agent)", strings.Join(DefaultKeyFiles, ", "), filepath.Join(home, ".ssh"))
		}
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	raw, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (a key with a passphrase: load it into your SSH agent and leave -i out; an agent's key must be Ed25519)", keyFile, err)
	}
	var k crypto.Signer
	switch r := raw.(type) {
	case *ed25519.PrivateKey:
		k = *r
	case ed25519.PrivateKey:
		k = r
	case *rsa.PrivateKey:
		k = r
	case *ecdsa.PrivateKey:
		k = r
	default:
		return nil, fmt.Errorf("%s: a %T key: the API takes Ed25519, RSA and ECDSA keys", keyFile, raw)
	}
	if err := CheckKey(k.Public()); err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	return k, nil
}

// agentSigner signs with a key held by an SSH agent. Ed25519 signs the
// message itself, so what TLS and X.509 hand to Sign is what the agent signs.
type agentSigner struct {
	ag  agent.ExtendedAgent
	key ssh.PublicKey
	pub ed25519.PublicKey
}

func (s agentSigner) Public() crypto.PublicKey { return s.pub }
func (s agentSigner) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("Ed25519 signs messages, not digests")
	}
	sig, err := s.ag.Sign(s.key, msg)
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

// agentKey is the SSH agent's one Ed25519 key. n is how many it holds: 0
// is not an error here (LoadKey goes on to the key files), more than one
// is.
func agentKey() (k crypto.Signer, n int, err error) {
	c, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, 0, fmt.Errorf("your SSH agent: %w", err)
	}
	ag := agent.NewClient(c)
	keys, err := ag.List()
	if err != nil {
		return nil, 0, fmt.Errorf("your SSH agent: %w", err)
	}
	var found []*agent.Key
	for _, k := range keys {
		if k.Type() == ssh.KeyAlgoED25519 {
			found = append(found, k)
		}
	}
	if len(found) == 0 {
		return nil, 0, nil
	}
	if len(found) != 1 {
		return nil, len(found), fmt.Errorf("your SSH agent holds %d Ed25519 keys: give the one to use with -i", len(found))
	}
	pk, err := ssh.ParsePublicKey(found[0].Blob)
	if err != nil {
		return nil, 1, err
	}
	pub := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	return agentSigner{ag: ag, key: pk, pub: pub}, 1, nil
}

// ErrPin is returned when the server's key is not the pinned one.
var ErrPin = errors.New("the server's key is not the pinned host key of this sandbox")

// Client talks to one sandbox's API.
type Client struct {
	// Addr is where to connect, host:port: the web router (DOMAIN:443) or,
	// on the host side, the guest's port directly.
	Addr string
	// ServerName is the TLS server name the router routes by,
	// NAME-ACCOUNT.DOMAIN.
	ServerName string
	// Pin is the sandbox's SSH host key, as sbxverify recorded it.
	Pin ssh.PublicKey
	// Key is the user's SSH key (LoadKey).
	Key crypto.Signer

	hc *http.Client
}

// TLSConfig is the client's TLS configuration: the user's certificate, the
// API's ALPN name, and the server accepted only with the pinned key.
func (c *Client) TLSConfig() (*tls.Config, error) {
	if c.Pin == nil {
		return nil, errors.New("no pinned host key: run sbxverify for this sandbox first, or give its host key")
	}
	if _, err := checkEd25519(c.Pin); err != nil {
		return nil, err
	}
	cert, err := SelfSigned(c.Key, false)
	if err != nil {
		return nil, err
	}
	want := c.Pin.Marshal()
	return &tls.Config{
		ServerName: c.ServerName, NextProtos: []string{ALPN}, MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// No certificate authority and no name check: the identity is the
		// key, compared with the pin. The handshake itself proves the
		// server holds that key's private half.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrPin
			}
			k, err := CertKey(raw[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrPin, err)
			}
			if !bytes.Equal(k.Marshal(), want) {
				return fmt.Errorf("%w: it presented %s, the pin is %s", ErrPin, KeyLine(k), KeyLine(c.Pin))
			}
			return nil
		},
	}, nil
}

func (c *Client) http() (*http.Client, error) {
	if c.hc != nil {
		return c.hc, nil
	}
	cfg, err := c.TLSConfig()
	if err != nil {
		return nil, err
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 20 * time.Second}, Config: cfg}
	c.hc = &http.Client{Transport: &http.Transport{
		DialTLSContext:        func(ctx context.Context, _, _ string) (net.Conn, error) { return d.DialContext(ctx, "tcp", c.Addr) },
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          2,
	}}
	return c.hc, nil
}

func (c *Client) url(path string, q url.Values) string {
	u := url.URL{Scheme: "https", Host: c.ServerName, Path: path}
	if c.ServerName == "" {
		u.Host = "sandbox"
	}
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Exec is a command to run in the sandbox (POST /v1/exec).
type Exec struct {
	Argv     []string          `json:"argv"`
	Cwd      string            `json:"cwd,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	TimeoutS int               `json:"timeout_s,omitempty"`
	StdinB64 string            `json:"stdin_b64,omitempty"`
}

// Line is one line of the exec reply: exactly one field is set.
type Line struct {
	Stdout   []byte `json:"stdout,omitempty"`
	Stderr   []byte `json:"stderr,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
}

// ErrNoExit is returned when the reply ended without an exit code.
var ErrNoExit = errors.New("the reply ended without an exit code")

// Run runs e and copies its output to stdout and stderr as it arrives. It
// returns the command's exit code; a command killed at its time limit
// returns 137 together with the server's error line as err.
func (c *Client) Run(ctx context.Context, e Exec, stdout, stderr io.Writer) (int, error) {
	hc, err := c.http()
	if err != nil {
		return -1, err
	}
	body, _ := json.Marshal(e)
	req, err := http.NewRequestWithContext(ctx, "POST", c.url("/v1/exec", nil), bytes.NewReader(body))
	if err != nil {
		return -1, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1, replyError(resp)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var srvErr error
	for sc.Scan() {
		var l Line
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return -1, fmt.Errorf("a reply line that is not JSON: %q", sc.Text())
		}
		switch {
		case l.Stdout != nil:
			stdout.Write(l.Stdout)
		case l.Stderr != nil:
			stderr.Write(l.Stderr)
		case l.Error != "":
			srvErr = errors.New(l.Error)
		case l.ExitCode != nil:
			return *l.ExitCode, srvErr
		}
	}
	if err := sc.Err(); err != nil {
		return -1, err
	}
	return -1, ErrNoExit
}

// Get streams the file at path in the sandbox to w (GET /v1/files).
func (c *Client) Get(ctx context.Context, path string, w io.Writer) (int64, error) {
	hc, err := c.http()
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.url("/v1/files", url.Values{"path": {path}}), nil)
	if err != nil {
		return 0, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, replyError(resp)
	}
	n, err := io.Copy(w, resp.Body)
	if err == nil && resp.ContentLength >= 0 && n != resp.ContentLength {
		err = fmt.Errorf("got %d bytes of %d", n, resp.ContentLength)
	}
	return n, err
}

// PutResult is the server's account of a written file.
type PutResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Put streams r to the file at path in the sandbox, with mode (PUT
// /v1/files). The file is replaced whole, or not at all. size is the
// length of r, or -1 if unknown.
func (c *Client) Put(ctx context.Context, path string, mode os.FileMode, r io.Reader, size int64) (*PutResult, error) {
	hc, err := c.http()
	if err != nil {
		return nil, err
	}
	q := url.Values{"path": {path}, "mode": {"0" + strconv.FormatUint(uint64(mode.Perm()), 8)}}
	req, err := http.NewRequestWithContext(ctx, "PUT", c.url("/v1/files", q), r)
	if err != nil {
		return nil, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, replyError(resp)
	}
	var res PutResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

func replyError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return fmt.Errorf("%s: %s", resp.Status, e.Error)
	}
	return fmt.Errorf("%s", resp.Status)
}

// B64 encodes stdin for Exec.StdinB64.
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Package userverify is what a sandbox's owner runs, on a machine of their
// own, to check a running sandbox without taking the service's word for
// anything:
//
//   - it logs in to the sandbox over SSH and notes the host key that session
//     was authenticated with;
//   - it has the sandbox produce a TDX quote over a nonce it has just made up
//     and over the sandbox's SSH host key;
//   - it verifies the quote: Intel's signature chain, a platform Intel rates
//     current, the measurements of the image the owner expects, the
//     sandbox's identity, the nonce, and that the host key in the quote is
//     the one the SSH session used;
//   - the sandbox says which image its root is made of (#112): the owner's
//     image's digest, or "base". RTMR3 must be the value that image and the
//     unlock leave (proto.RTMR3Running), which makes the answer authentic;
//     with the owner's key, it is then compared with the owner's record.
//
// If that holds, the owner is talking, right now, to a genuine TD that booted
// the expected image, and nothing sits in between. What it does not show is
// who else could obtain the sandbox's disk key: that is a property of where
// the key broker runs, not of the sandbox.
package userverify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// Verifier is the part of attest.TDX this needs. The production one is
// &attest.TDX{Policy: ...}: Intel's root, Intel's live collateral, no
// exception of any kind.
type Verifier interface {
	VerifyRunning(ctx context.Context, quote []byte, reportData [64]byte, sandboxID, image string) (*attest.Result, error)
	VerifyRunningAs(ctx context.Context, quote []byte, reportData [64]byte, sandboxID string, rtmr3 [48]byte) (*attest.Result, error)
}

// Target says how to reach the sandbox.
type Target struct {
	// Either through the service's entry point, by the sandbox's name ...
	Entry    string // host:port
	EntryKey string // the entry point's host key, "type base64"; pinned
	Name     string
	// ... or directly, at the sandbox's own SSH port, with its ID.
	Addr string // host:port
	ID   string
	// Auth is how the owner authenticates (their key).
	Auth []ssh.AuthMethod
	// OwnerRTMR3, for a sandbox whose disk key the owner holds, gives the
	// RTMR3 the sandbox must show once the owner's key unlocked it and its
	// root is image (ownerkey.ExpectedRTMR3). A TD unlocked by anyone else,
	// such as a host that booted one with this ID and answered it with a
	// secret of its own, shows another value and is not verified.
	OwnerRTMR3 func(sandboxID, image string) ([48]byte, error)
	// OwnerImage, once the quote has verified (and with it the image the
	// sandbox named), compares that image with the owner's record
	// (ownerkey.State.CheckImage). An error refuses the sandbox; the string
	// is a line for the report.
	OwnerImage func(sandboxID, image string) (string, error)
}

// Evidence is what sandbox-attest prints.
type Evidence struct {
	Version int    `json:"version"`
	Nonce   string `json:"nonce"`
	HostKey string `json:"ssh_host_key"`
	Quote   string `json:"quote"`
	// Image is the image the sandbox's root is made of (#112), as the
	// initrd recorded it in /run/tdx-sandbox/image: a digest, or "base".
	// A sandbox-attest from before #112 leaves it out; it is then read
	// from that file in the same session.
	Image string `json:"image,omitempty"`
}

// Report is the outcome of a check that passed.
type Report struct {
	SandboxID string
	// HostKey is the SSH host key the session was authenticated with, which
	// the quote was found to carry.
	HostKey string
	// ToldHostKey is the host key the service said the sandbox has, if the
	// service was asked. It is reported, not relied on.
	ToldHostKey string
	// ToldURL is the sandbox's HTTPS address at the web router, as the service
	// gave it (https://NAME-ACCOUNT.DOMAIN): where its API is reached (#106).
	// An address, not a trust anchor: the API is pinned by HostKey.
	ToldURL string
	Nonce   string
	Quote   *attest.Result
	// Checks is the verifier's account of the quote, check by check, when it
	// can give one. It explains the verdict and never replaces it.
	Checks []attest.Check
	// UnlockedByOwner: OwnerRTMR3 was given and the quote showed it.
	UnlockedByOwner bool
	// Image is the image the sandbox named for its root (#112): a digest,
	// or "base". Once the quote verified, RTMR3 vouches for it.
	Image string
	// ImageNote is OwnerImage's line about it.
	ImageNote string
	// Rehearsal: REHEARSAL BUILDS ONLY. The sandbox is not a TD and gave
	// no quote; nothing in this report is attested (rehearsal.go).
	Rehearsal bool
}

func keyLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func run(c *ssh.Client, cmd string) ([]byte, string, error) {
	s, err := c.NewSession()
	if err != nil {
		return nil, "", err
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
	err = s.Run(cmd)
	return out.Bytes(), strings.TrimSpace(errb.String()), err
}

// DialEntry logs in to the service's SSH entry point at entry (host:port),
// whose host key entryKey ("type base64", as the service publishes it) is
// pinned: an entry point answering with another key is not used. It is
// the one place a connection to the entry point is made, and it says it
// is trajrl (ClientVersion), which the entry point requires.
func DialEntry(entry, entryKey string, auth []ssh.AuthMethod) (*ssh.Client, error) {
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entryKey))
	if err != nil {
		return nil, errors.New("the entry point's host key is needed, as the service publishes it (type and base64)")
	}
	c, err := ssh.Dial("tcp", entry, &ssh.ClientConfig{User: "owner", Auth: auth, ClientVersion: sshClientVersion(),
		HostKeyCallback: ssh.FixedHostKey(pinned), Timeout: 20 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("the entry point: %w", err)
	}
	return c, nil
}

// Identity is how the owner authenticates over SSH: a private key file, or
// the keys of their SSH agent. It remembers which key last signed, which is
// the key the server accepted.
type Identity struct {
	Auth []ssh.AuthMethod
	mu   sync.Mutex
	used ssh.PublicKey
	// agentKeys is how many keys the SSH agent held when it was opened (0
	// for a key file).
	agentKeys int
}

// AgentKeys is how many keys the SSH agent held (0 for a key file). With
// more than one, the server, not the owner, chooses which one logs in.
func (id *Identity) AgentKeys() int { return id.agentKeys }

// LoadIdentity reads keyFile, or with "" uses the SSH agent at
// $SSH_AUTH_SOCK.
func LoadIdentity(keyFile string) (*Identity, error) {
	id := &Identity{}
	switch {
	case keyFile != "":
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w (a key with a passphrase: load it into your SSH agent and leave -i out)", keyFile, err)
		}
		id.Auth = []ssh.AuthMethod{ssh.PublicKeys(id.wrap(signer))}
	case os.Getenv("SSH_AUTH_SOCK") != "":
		c, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			return nil, fmt.Errorf("your SSH agent: %w", err)
		}
		ag := agent.NewClient(c)
		if keys, err := ag.List(); err == nil {
			id.agentKeys = len(keys)
		}
		id.Auth = []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			signers, err := ag.Signers()
			for i := range signers {
				signers[i] = id.wrap(signers[i])
			}
			return signers, err
		})}
	default:
		return nil, errors.New("no key: give -i KEYFILE or run an SSH agent")
	}
	return id, nil
}

// DefaultKeyFiles are the private key files of the SSH directory that ssh
// tries when it is given none, in its order.
var DefaultKeyFiles = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// DefaultKeyFile is the key file to log in with where none was given and
// no SSH agent holds a key, as ssh would find one: the first of
// DefaultKeyFiles in sshDir that exists and has no passphrase. locked
// names the ones passed over for a passphrase (ssh would ask for it; this
// package reads no SSH passphrase). "" if there is none.
func DefaultKeyFile(sshDir string) (file string, locked []string) {
	for _, name := range DefaultKeyFiles {
		p := filepath.Join(sshDir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if _, err := ssh.ParsePrivateKey(b); err != nil {
			var pm *ssh.PassphraseMissingError
			if errors.As(err, &pm) {
				locked = append(locked, p)
			}
			continue
		}
		return p, locked
	}
	return "", locked
}

// AgentHasKeys: $SSH_AUTH_SOCK names an SSH agent that holds a key.
func AgentHasKeys() bool {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return false
	}
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return false
	}
	defer c.Close()
	keys, err := agent.NewClient(c).List()
	return err == nil && len(keys) > 0
}

// NewIdentity is an Identity of one signer.
func NewIdentity(s ssh.Signer) *Identity {
	id := &Identity{}
	id.Auth = []ssh.AuthMethod{ssh.PublicKeys(id.wrap(s))}
	return id
}

// Used is the public key that last signed an authentication: after a
// successful login, the key the server accepted. Nil before any.
func (id *Identity) Used() ssh.PublicKey {
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.used
}

func (id *Identity) mark(k ssh.PublicKey) {
	id.mu.Lock()
	id.used = k
	id.mu.Unlock()
}

// The SSH client asks the server whether it would take a key before signing
// with it, so the signer that signs is the one that is accepted. The
// wrappers keep the signature algorithms of the key they wrap (an RSA key
// must not fall back to SHA-1).
type markSigner struct {
	ssh.Signer
	id *Identity
}

func (s markSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	s.id.mark(s.PublicKey())
	return s.Signer.Sign(r, data)
}

type markAlgSigner struct {
	markSigner
	alg ssh.AlgorithmSigner
}

func (s markAlgSigner) SignWithAlgorithm(r io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	s.id.mark(s.PublicKey())
	return s.alg.SignWithAlgorithm(r, data, algorithm)
}

type markMultiSigner struct {
	markAlgSigner
	algs []string
}

func (s markMultiSigner) Algorithms() []string { return s.algs }

func (id *Identity) wrap(s ssh.Signer) ssh.Signer {
	m := markSigner{s, id}
	alg, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return m
	}
	a := markAlgSigner{m, alg}
	if multi, ok := s.(ssh.MultiAlgorithmSigner); ok {
		return markMultiSigner{a, multi.Algorithms()}
	}
	return a
}

// Check does the whole thing. An error means the sandbox was not verified;
// it says which step failed.
func Check(ctx context.Context, t Target, v Verifier) (*Report, error) {
	rep := &Report{SandboxID: t.ID}
	var conn net.Conn
	var addr string
	switch {
	case t.Entry != "":
		entry, err := DialEntry(t.Entry, t.EntryKey, t.Auth)
		if err != nil {
			return nil, err
		}
		defer entry.Close()
		// What the service says about the sandbox. Only its ID is used
		// from here on, and the quote has to agree with it.
		out, errs, err := run(entry, "show "+t.Name+" --json")
		if err != nil {
			return nil, fmt.Errorf("show %s: %v %s", t.Name, err, errs)
		}
		var told struct {
			ID      string `json:"id"`
			State   string `json:"state"`
			HostKey string `json:"host_key"`
			URL     string `json:"https_url"`
		}
		if json.Unmarshal(out, &told) != nil || !proto.ValidSandboxID(told.ID) {
			return nil, errors.New("the entry point's answer about the sandbox could not be read")
		}
		if told.State != "running" {
			return nil, fmt.Errorf("%s is %s; only a running sandbox can be asked", t.Name, told.State)
		}
		rep.SandboxID, rep.ToldHostKey, rep.ToldURL = told.ID, told.HostKey, told.URL
		// By name through the entry point: it carries bytes; the SSH
		// session below is with the sandbox.
		if conn, err = entry.Dial("tcp", t.Name+":22"); err != nil {
			return nil, fmt.Errorf("reaching %s through the entry point: %w", t.Name, err)
		}
		addr = t.Name + ":22"
	case t.Addr != "" && proto.ValidSandboxID(t.ID):
		var err error
		if conn, err = (&net.Dialer{Timeout: 20 * time.Second}).DialContext(ctx, "tcp", t.Addr); err != nil {
			return nil, err
		}
		addr = t.Addr
	default:
		return nil, errors.New("say how to reach the sandbox: an entry point and a name, or an address and the sandbox's ID")
	}
	defer conn.Close()

	// Any host key is accepted here, and remembered: whether it is the right
	// one is decided by the quote, not by a list of known hosts.
	var presented ssh.PublicKey
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{User: "root", Auth: t.Auth, Timeout: 30 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error { presented = key; return nil }})
	if err != nil {
		return nil, fmt.Errorf("logging in to the sandbox: %w", err)
	}
	sandbox := ssh.NewClient(cc, chans, reqs)
	defer sandbox.Close()
	rep.HostKey = keyLine(presented)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	rep.Nonce = hex.EncodeToString(nonce)
	// The tool is on the sandbox's own disk, and also in the read-only base
	// image every boot mounts, for sandboxes created before it existed.
	out, errs, err := run(sandbox, "sandbox-attest "+rep.Nonce+" 2>/dev/null || /run/tdx-sandbox/base/usr/bin/sandbox-attest "+rep.Nonce)
	if err != nil {
		// Only a binary built with the tag "rehearsal" goes on without a
		// quote (rehearsal.go); a normal build has no such path.
		if notTD(err) && noQuoteAllowed() {
			return noQuoteCheck(sandbox, t, rep)
		}
		return nil, fmt.Errorf("the sandbox gave no quote: %s (%v)", errs, err)
	}
	var ev Evidence
	if err := json.Unmarshal(out, &ev); err != nil {
		return nil, errors.New("what the sandbox printed is not evidence")
	}
	if rep.Image = ev.Image; rep.Image == "" {
		if rep.Image, err = sandboxImage(sandbox); err != nil {
			return nil, err
		}
	}
	if !proto.ValidImageMeasure(rep.Image) {
		return nil, fmt.Errorf("the sandbox names its image %.80q, which is neither %q nor a sha256 digest", rep.Image, proto.ImageBase)
	}
	quote, err := base64.StdEncoding.DecodeString(ev.Quote)
	if err != nil || len(quote) == 0 {
		return nil, errors.New("what the sandbox printed holds no quote")
	}
	// The report data is computed here, from this side's nonce and from the
	// host key this side's SSH saw. What the sandbox says they were is not
	// used: a quote over anything else simply does not verify.
	rd := proto.UserReportData(nonce, rep.HostKey)
	var res *attest.Result
	if t.OwnerRTMR3 != nil {
		want, werr := t.OwnerRTMR3(rep.SandboxID, rep.Image)
		if werr != nil {
			return nil, werr
		}
		res, err = v.VerifyRunningAs(ctx, quote, rd, rep.SandboxID, want)
		if err != nil && res != nil && len(res.RTMRs) == 4 && !strings.EqualFold(res.RTMRs[3], hex.EncodeToString(want[:])) {
			err = fmt.Errorf("this sandbox was not unlocked with your key, or its root is not the image it names (%s): its RTMR3 is not the value your key and that image give it. Do not use it\n  (%w)", rep.Image, err)
		}
		rep.UnlockedByOwner = err == nil
	} else {
		res, err = v.VerifyRunning(ctx, quote, rd, rep.SandboxID, rep.Image)
		if e, ok := v.(interface {
			ExplainRunning(context.Context, []byte, [64]byte, string, string) []attest.Check
		}); ok {
			rep.Checks = e.ExplainRunning(ctx, quote, rd, rep.SandboxID, rep.Image)
		}
	}
	rep.Quote = res
	if err != nil {
		if ev.HostKey != "" && ev.HostKey != rep.HostKey {
			return rep, fmt.Errorf("%w\n  the quote was made for SSH host key %s,\n  but this SSH session was answered with %s:\n  something between you and the sandbox is answering in its place", err, ev.HostKey, rep.HostKey)
		}
		return rep, err
	}
	// The quote verified, and with RTMR3 the image the sandbox named: now
	// it is held against what the owner asked for.
	if t.OwnerImage != nil {
		if rep.ImageNote, err = t.OwnerImage(rep.SandboxID, rep.Image); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// sandboxImage reads the image the sandbox's root is made of, as the initrd
// recorded it, in the session already open: /run/tdx-sandbox/image, which a
// sandbox on the base image does not have. It is believed only as far as
// RTMR3 bears it out.
func sandboxImage(c *ssh.Client) (string, error) {
	out, errs, err := run(c, "cat /run/tdx-sandbox/image 2>/dev/null || echo "+proto.ImageBase)
	if err != nil {
		return "", fmt.Errorf("the sandbox did not say which image it runs: %s (%v)", errs, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// notTD: sandbox-attest's exit status 3, "this machine is not a TDX guest".
func notTD(err error) bool {
	var x *ssh.ExitError
	return errors.As(err, &x) && x.ExitStatus() == 3
}

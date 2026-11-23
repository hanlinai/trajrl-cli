package keycmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/keystmt"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// keysEntry is a stand-in entry point for one account, "alice": it stores
// and relays her statement as the control plane does (checked against the
// stored one, or her keys before the first), and nothing else.
type keysEntry struct {
	mu     sync.Mutex
	keys   []string
	signed string
	puts   int
	// offer, when set, is what "ssh-key statement --json" answers with in
	// place of the stored statement (a platform offering an older one).
	offer *string
}

func (e *keysEntry) handle(ch ssh.Channel, cmd string) uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch cmd {
	case "ssh-key statement --json":
		signed := e.signed
		if e.offer != nil {
			signed = *e.offer
		}
		json.NewEncoder(ch).Encode(map[string]any{"account": "alice", "keys": e.keys, "signed": signed})
		return 0
	case "ssh-key statement put":
		b, _ := io.ReadAll(ch)
		trust := keystmt.Trust{Account: "alice", Signers: e.keys}
		if e.signed != "" {
			text, _, _ := keystmt.Split([]byte(e.signed))
			prev, _ := keystmt.Parse(text)
			trust = keystmt.TrustOf(prev)
		}
		st, _, err := keystmt.Verify(b, trust)
		if err != nil {
			fmt.Fprintf(ch.Stderr(), "ssh-key statement put: refused: %v\n", err)
			return 1
		}
		e.signed, e.keys, e.puts = string(b), st.Keys, e.puts+1
		fmt.Fprintf(ch, "stored statement %d\n", st.Seq)
		return 0
	}
	fmt.Fprintf(ch.Stderr(), "unknown command: %s\n", cmd)
	return 2
}

func (e *keysEntry) dial(t *testing.T, as ssh.Signer) *ssh.Client {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(host)
	l, err := net.Listen("tcp", "127.0.0.1:0")
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
			go func() {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, r, _ := nc.Accept()
					go func() {
						for req := range r {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							var p struct{ Cmd string }
							ssh.Unmarshal(req.Payload, &p)
							req.Reply(true, nil)
							go func() {
								code := e.handle(ch, p.Cmd)
								b := make([]byte, 4)
								binary.BigEndian.PutUint32(b, code)
								ch.SendRequest("exit-status", false, b)
								ch.Close()
							}()
						}
					}()
				}
			}()
		}
	}()
	client, err := userverify.DialEntry(l.Addr().String(), string(ssh.MarshalAuthorizedKey(host.PublicKey())), []ssh.AuthMethod{ssh.PublicKeys(as)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func keysSigner(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

func keysTestEnv(t *testing.T, e *keysEntry, dir string, as ssh.Signer) (*keysEnv, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &keysEnv{dir: dir, entry: e.dial(t, as), signer: as, out: out, errw: out}, out
}

func storedStatement(t *testing.T, e *keysEntry) *keystmt.Statement {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	text, _, err := keystmt.Split([]byte(e.signed))
	if err != nil {
		t.Fatal(err)
	}
	st, err := keystmt.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// keys add signs with the owner's key and puts: the first statement holds
// the signing key and the new one, and not the platform's other keys
// unseen; -sandbox adds a key of that sandbox only, by its ID from the
// record; remove takes one out; a key not in the statement cannot sign.
func TestKeysAddRemoveSignAndPut(t *testing.T) {
	a, aLine := keysSigner(t)
	_, bLine := keysSigner(t)
	_, colleague := keysSigner(t)
	_, planted := keysSigner(t)
	stranger, _ := keysSigner(t)
	e := &keysEntry{keys: []string{aLine, planted}}
	dir := t.TempDir()
	st, err := ownerkey.OpenState(filepath.Join(dir, "sandboxes.json"), filepath.Join(dir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	st.Put(ownerkey.Record{ID: "sbx-00000000000000a1", Name: "web", Provisioned: true, Epoch: 1}, false)
	k, out := keysTestEnv(t, e, dir, a)

	if err := keysAdd(k, bLine+" laptop-b", ""); err != nil {
		t.Fatalf("keys add: %v\n%s", err, out)
	}
	s1 := storedStatement(t, e)
	if s1.Seq != 1 || len(s1.Keys) != 2 || fpOf(s1.Keys[0]) != fpOf(aLine) || s1.Keys[1] != bLine+" laptop-b" {
		t.Fatalf("the first statement: %+v", s1)
	}
	if !strings.Contains(out.String(), fpOf(planted)+" is a key of your account at the platform and is not in your first statement") {
		t.Fatalf("no note about the platform's other key:\n%s", out)
	}
	if b, _ := os.ReadFile(statementCache(dir)); string(b) != e.signed {
		t.Fatal("the statement is not kept in DIR/key-statement")
	}

	// A key file, for one sandbox, by name.
	f := filepath.Join(dir, "colleague.pub")
	os.WriteFile(f, []byte(colleague+" bob@work\n"), 0o644)
	if err := keysAdd(k, f, "web"); err != nil {
		t.Fatalf("keys add -sandbox web: %v", err)
	}
	if s2 := storedStatement(t, e); s2.Seq != 2 || len(s2.Sandboxes) != 1 || s2.Sandboxes[0].Sandbox != "sbx-00000000000000a1" || len(s2.Keys) != 2 {
		t.Fatalf("after adding a colleague's key: %+v", s2)
	}
	if err := keysAdd(k, bLine, ""); err == nil {
		t.Fatal("a key added twice")
	}
	if err := keysAdd(k, colleague, "nosuch"); err == nil || !strings.Contains(err.Error(), "no sandbox called nosuch") {
		t.Fatalf("an unknown sandbox: %v", err)
	}

	if err := keysRemove(k, fpOf(aLine), ""); err != nil {
		t.Fatalf("keys remove: %v", err)
	}
	if s3 := storedStatement(t, e); s3.Seq != 3 || len(s3.Keys) != 1 || s3.Keys[0] != bLine+" laptop-b" || len(s3.Sandboxes) != 1 {
		t.Fatalf("after removing a: %+v", s3)
	}
	// a is no longer in the statement: it cannot sign the next.
	if err := keysAdd(k, colleague, ""); err == nil || !strings.Contains(err.Error(), "not a login key") {
		t.Fatalf("a removed key signing: %v", err)
	}
	k.signer = stranger
	if err := keysRemove(k, f, "web"); err == nil {
		t.Fatal("a stranger's key signed")
	}
	if e.puts != 3 {
		t.Fatalf("%d statements stored", e.puts)
	}
}

// recovery-key init: a new statement with the recovery key's public half,
// and the private half printed once, after the platform stored it. With it,
// after every login key is lost, keys add -sign-with gives a new key.
func TestRecoveryKeyInitAndUse(t *testing.T) {
	a, aLine := keysSigner(t)
	c, cLine := keysSigner(t)
	e := &keysEntry{keys: []string{aLine}}
	dir := t.TempDir()
	k, out := keysTestEnv(t, e, dir, a)
	if err := recoveryKeyInit(k, false); err != nil {
		t.Fatalf("recovery-key init: %v\n%s", err, out)
	}
	printed := out.String()
	if strings.Count(printed, "-----BEGIN OPENSSH PRIVATE KEY-----") != 1 || !strings.Contains(printed, "It is shown once. Keep it OFFLINE") {
		t.Fatalf("the private half was not printed once:\n%s", printed)
	}
	st := storedStatement(t, e)
	if st.Recovery == "" || st.Seq != 1 || len(st.Keys) != 1 {
		t.Fatalf("the statement after recovery-key init: %+v", st)
	}
	i := strings.Index(printed, "-----BEGIN OPENSSH PRIVATE KEY-----")
	j := strings.Index(printed, "-----END OPENSSH PRIVATE KEY-----")
	recFile := filepath.Join(dir, "recovery.key")
	os.WriteFile(recFile, []byte(printed[i:j+len("-----END OPENSSH PRIVATE KEY-----")]+"\n"), 0o600)
	rs, err := loadSigner(recFile, nil)
	if err != nil || fpOf(st.Recovery) != ssh.FingerprintSHA256(rs.PublicKey()) {
		t.Fatalf("the printed private half is not the statement's recovery key: %v", err)
	}
	// Not twice without -replace, and the private half is not printed again.
	out.Reset()
	if err := recoveryKeyInit(k, false); err == nil || strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatalf("a second recovery-key init: %v %s", err, out)
	}

	// The laptop is lost. On a new machine, logged in with c (added on the
	// website), the recovery key signs a statement adding c.
	e.mu.Lock()
	e.keys = append(e.keys, cLine)
	e.mu.Unlock()
	k2, out2 := keysTestEnv(t, e, t.TempDir(), c)
	k2.signer = nil
	k2.signWith = recFile
	if err := keysAdd(k2, cLine+" new-laptop", ""); err != nil {
		t.Fatalf("keys add -sign-with recovery.key: %v\n%s", err, out2)
	}
	if st := storedStatement(t, e); st.Seq != 2 || len(st.Keys) != 2 || st.Recovery == "" {
		t.Fatalf("after recovery: %+v", st)
	}
}

// fetchStatement: the platform's statement, or sbxkey's own newer one when
// the platform offers an older one; an unlock sends it.
func TestKeyStatementFetchNewest(t *testing.T) {
	a, aLine := keysSigner(t)
	_, bLine := keysSigner(t)
	e := &keysEntry{keys: []string{aLine}}
	dir := t.TempDir()
	k, out := keysTestEnv(t, e, dir, a)
	if got := unlockStatement(k.entry, dir, "web", out); got != "" {
		t.Fatalf("no statement yet, sent: %q", got)
	}
	keysAdd(k, bLine, "")
	first := e.signed
	keysRemove(k, bLine, "")
	if got := unlockStatement(k.entry, dir, "web", out); got != e.signed || !strings.Contains(out.String(), "statement 2 of your keys sent to web's TD") {
		t.Fatalf("an unlock sends: %.60q\n%s", got, out)
	}
	e.offer = &first
	out.Reset()
	if got := unlockStatement(k.entry, dir, "web", out); got != e.signed || !strings.Contains(out.String(), "the platform offers statement 1") {
		t.Fatalf("with the platform offering an older statement, sent: %.60q\n%s", got, out)
	}
	garbage := "sbx-keys v1\naccount alice\nseq 9\n-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
	e.offer = &garbage
	out.Reset()
	if got := unlockStatement(k.entry, dir, "web", out); got != "" || !strings.Contains(out.String(), "its keys stay as they are") {
		t.Fatalf("a broken statement from the platform, sent: %.60q\n%s", got, out)
	}
}

// keys sync feeds the statement to the command given, "sandbox-keys apply"
// after it, on its standard input.
func TestKeysSyncFeedsTheStatement(t *testing.T) {
	a, aLine := keysSigner(t)
	_, bLine := keysSigner(t)
	e := &keysEntry{keys: []string{aLine}}
	dir := t.TempDir()
	k, _ := keysTestEnv(t, e, dir, a)
	if err := keysSync(k, "web", "sh -c true", ""); err == nil {
		t.Fatal("sync with no statement")
	}
	keysAdd(k, bLine, "")
	got := filepath.Join(dir, "fed")
	script := filepath.Join(dir, "fake-ssh")
	os.WriteFile(script, []byte("#!/bin/sh\necho \"$@\" > "+got+".args\ncat > "+got+"\n"), 0o755)
	if err := keysSync(k, "web", script+" root@web.sbx.test", ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(got)
	args, _ := os.ReadFile(got + ".args")
	if string(b) != e.signed || strings.TrimSpace(string(args)) != "root@web.sbx.test sandbox-keys apply" {
		t.Fatalf("fed %q with %q", b, args)
	}
	if err := keysSync(k, "web", "", ""); err == nil || !strings.Contains(err.Error(), "-domain") {
		t.Fatalf("no way to reach it: %v", err)
	}
}

// #118 D1: a login key removed on the website (the platform no longer
// lists it) does not come back at the owner's next signed change: it is
// left out of the new statement, with a note saying which and why, unless
// -keep-removed; removing it then is no error; a change that would leave
// no login key is refused.
func TestKeysRemovedOnWebsiteStayRemoved(t *testing.T) {
	a, aLine := keysSigner(t)
	_, bLine := keysSigner(t)
	_, cLine := keysSigner(t)
	_, dLine := keysSigner(t)
	e := &keysEntry{keys: []string{aLine}}
	dir := t.TempDir()
	k, out := keysTestEnv(t, e, dir, a)
	if err := keysAdd(k, bLine+" old-laptop", ""); err != nil {
		t.Fatalf("keys add: %v\n%s", err, out)
	}
	// The website removes b: the entry point no longer lists it.
	websiteRemoves := func(line string) {
		e.mu.Lock()
		defer e.mu.Unlock()
		var keep []string
		for _, l := range e.keys {
			if fpOf(l) != fpOf(line) {
				keep = append(keep, l)
			}
		}
		e.keys = keep
	}
	websiteRemoves(bLine)
	out.Reset()
	if err := keysAdd(k, cLine, ""); err != nil {
		t.Fatalf("keys add after the website removed b: %v\n%s", err, out)
	}
	st := storedStatement(t, e)
	if st.Seq != 2 || len(st.Keys) != 2 || fpOf(st.Keys[0]) != fpOf(aLine) || fpOf(st.Keys[1]) != fpOf(cLine) {
		t.Fatalf("b came back: %+v", st)
	}
	if !strings.Contains(out.String(), fpOf(bLine)+" old-laptop is left out of the new statement") || !strings.Contains(out.String(), "-keep-removed") {
		t.Fatalf("no note about b:\n%s", out)
	}

	// -keep-removed: the owner re-adds c on purpose.
	websiteRemoves(cLine)
	k.keepRemoved = true
	out.Reset()
	if err := keysAdd(k, dLine, ""); err != nil {
		t.Fatalf("keys add -keep-removed: %v\n%s", err, out)
	}
	if st := storedStatement(t, e); len(st.Keys) != 3 || fpOf(st.Keys[1]) != fpOf(cLine) {
		t.Fatalf("-keep-removed did not keep c: %+v", st)
	}
	if !strings.Contains(out.String(), "-keep-removed: it stays a login key") {
		t.Fatalf("no note about keeping c:\n%s", out)
	}

	// Removing a key the website removed already is no error.
	k.keepRemoved = false
	websiteRemoves(dLine)
	if err := keysRemove(k, dLine, ""); err != nil {
		t.Fatalf("keys remove of a key the website removed: %v", err)
	}
	if st := storedStatement(t, e); len(st.Keys) != 2 || fpOf(st.Keys[0]) != fpOf(aLine) || fpOf(st.Keys[1]) != fpOf(cLine) {
		t.Fatalf("after removing d: %+v", st)
	}
	// Nothing would be left: refused, nothing stored.
	websiteRemoves(aLine)
	websiteRemoves(cLine)
	puts := e.puts
	if err := recoveryKeyInit(k, false); err == nil || !strings.Contains(err.Error(), "no login key") {
		t.Fatalf("a statement with no login key: %v", err)
	}
	if e.puts != puts {
		t.Fatal("a statement with no login key was stored")
	}
}

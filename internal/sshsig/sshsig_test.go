package sshsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const ns = "sbx-keys@trajrl"

func signers(t *testing.T) map[string]ssh.Signer {
	t.Helper()
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	out := map[string]ssh.Signer{}
	for name, k := range map[string]any{"ed25519": ed, "ecdsa-p256": ec, "rsa": rs} {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = s
	}
	return out
}

// Signed here, verified here; a changed message, another namespace or a
// damaged signature does not verify.
func TestSignVerify(t *testing.T) {
	msg := []byte("sbx-keys v1\naccount alice\nseq 1\n")
	for name, s := range signers(t) {
		sig, err := Sign(s, ns, msg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.HasPrefix(string(sig), beginLine+"\n") {
			t.Fatalf("%s: not armored: %s", name, sig)
		}
		pub, err := Verify(sig, msg, ns)
		if err != nil || !Equal(pub, s.PublicKey()) {
			t.Fatalf("%s: verify: %v", name, err)
		}
		if _, err := Verify(sig, append(msg, 'x'), ns); err == nil {
			t.Fatalf("%s: a changed message verified", name)
		}
		if _, err := Verify(sig, msg, "file"); err == nil || !strings.Contains(err.Error(), "namespace") {
			t.Fatalf("%s: another namespace: %v", name, err)
		}
		bad := []byte(strings.Replace(string(sig), "A", "B", 1))
		if _, err := Verify(bad, msg, ns); err == nil {
			t.Fatalf("%s: a damaged signature verified", name)
		}
	}
	if _, err := Verify([]byte("not a signature"), msg, ns); err == nil {
		t.Fatal("garbage verified")
	}
}

func keygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed: the interop with OpenSSH is not tested here")
	}
	return p
}

// Interop with OpenSSH both ways, for each key type: ssh-keygen -Y sign is
// verified here, and what this package signs passes ssh-keygen -Y verify
// against an allowed-signers file; ssh-keygen refuses it under another
// namespace and for another message.
func TestInteropWithSSHKeygen(t *testing.T) {
	kg := keygen(t)
	dir := t.TempDir()
	msgPath := filepath.Join(dir, "statement")
	msg := []byte("sbx-keys v1\naccount alice\nseq 7\nkey ssh-ed25519 AAAA... laptop\n")
	os.WriteFile(msgPath, msg, 0o644)
	for _, kt := range []struct{ name, flag string }{{"ed25519", "-t ed25519"}, {"ecdsa-p256", "-t ecdsa -b 256"}, {"rsa", "-t rsa -b 2048"}} {
		key := filepath.Join(dir, kt.name)
		if out, err := exec.Command(kg, append(strings.Fields(kt.flag), "-N", "", "-q", "-C", kt.name, "-f", key)...).CombinedOutput(); err != nil {
			t.Fatalf("%s: ssh-keygen: %v %s", kt.name, err, out)
		}
		pubLine, _ := os.ReadFile(key + ".pub")
		pub, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
		if err != nil {
			t.Fatal(err)
		}

		// OpenSSH signs, this package verifies.
		os.Remove(msgPath + ".sig")
		if out, err := exec.Command(kg, "-Y", "sign", "-q", "-f", key, "-n", ns, msgPath).CombinedOutput(); err != nil {
			t.Fatalf("%s: ssh-keygen -Y sign: %v %s", kt.name, err, out)
		}
		sig, _ := os.ReadFile(msgPath + ".sig")
		got, err := Verify(sig, msg, ns)
		if err != nil || !Equal(got, pub) {
			t.Fatalf("%s: ssh-keygen's signature: %v", kt.name, err)
		}
		if _, err := Verify(sig, msg, "git"); err == nil {
			t.Fatalf("%s: ssh-keygen's signature verified under another namespace", kt.name)
		}

		// This package signs, OpenSSH verifies.
		b, _ := os.ReadFile(key)
		s, err := ssh.ParsePrivateKey(b)
		if err != nil {
			t.Fatal(err)
		}
		mine, err := Sign(s, ns, msg)
		if err != nil {
			t.Fatalf("%s: %v", kt.name, err)
		}
		sigPath := filepath.Join(dir, kt.name+".mine.sig")
		os.WriteFile(sigPath, mine, 0o644)
		allowed := filepath.Join(dir, "allowed_signers")
		os.WriteFile(allowed, []byte("owner@example "+strings.TrimSpace(string(pubLine))+"\n"), 0o644)
		verify := func(namespace string, message []byte) error {
			c := exec.Command(kg, "-Y", "verify", "-f", allowed, "-I", "owner@example", "-n", namespace, "-s", sigPath)
			c.Stdin = strings.NewReader(string(message))
			out, err := c.CombinedOutput()
			if err != nil {
				return &exec.ExitError{Stderr: out}
			}
			return nil
		}
		if err := verify(ns, msg); err != nil {
			t.Fatalf("%s: ssh-keygen -Y verify refused this package's signature: %s", kt.name, err.(*exec.ExitError).Stderr)
		}
		if verify("file", msg) == nil {
			t.Fatalf("%s: ssh-keygen verified it under another namespace", kt.name)
		}
		if verify(ns, append(msg, '\n')) == nil {
			t.Fatalf("%s: ssh-keygen verified it for another message", kt.name)
		}
	}
}

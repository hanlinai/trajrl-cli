package keystmt

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func key(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// The text round-trips, and Parse takes nothing but the format.
func TestKeyStatementParse(t *testing.T) {
	_, a := key(t)
	_, r := key(t)
	st := &Statement{Account: "alice", Seq: 3, Keys: []string{`from="10.0.0.0/8" ` + a + " laptop"},
		Sandboxes: []SandboxKey{{Sandbox: "sbx-0123456789abcdef", Key: a + " bob"}}, Recovery: r}
	got, err := Parse(st.Text())
	if err != nil || string(got.Text()) != string(st.Text()) {
		t.Fatalf("round trip: %v\n%s", err, st.Text())
	}
	head := "sbx-keys v1\naccount alice\nseq 1\n"
	for what, text := range map[string]string{
		"no header":         "account alice\nseq 1\n",
		"another version":   "sbx-keys v2\naccount alice\nseq 1\n",
		"no final new line": strings.TrimSuffix(head, "\n"),
		"a bad seq":         "sbx-keys v1\naccount alice\nseq 01\n",
		"a bad account":     "sbx-keys v1\naccount Alice Smith\nseq 1\n",
		"an unknown line":   head + "admin " + a + "\n",
		"a blank line":      head + "\n",
		"a key twice":       head + "key " + a + "\nkey " + a + " again\n",
		"two recovery keys": head + "recovery " + r + "\nrecovery " + a + "\n",
		"recovery options":  head + "recovery no-pty " + r + "\n",
		"a sandbox by name": head + "sandbox web key " + a + "\n",
		"not a key":         head + "key ssh-ed25519 AAAA\n",
	} {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: parsed", what)
		}
	}
	var many strings.Builder
	many.WriteString(head)
	for range MaxKeys + 1 {
		_, k := key(t)
		many.WriteString("key " + k + "\n")
	}
	if _, err := Parse([]byte(many.String())); err == nil {
		t.Errorf("%d keys parsed", MaxKeys+1)
	}
}

// Verify: the trust's signers, account and seq; a statement with its text
// changed after signing does not verify.
func TestKeyStatementVerify(t *testing.T) {
	s, a := key(t)
	_, b := key(t)
	signed, err := Sign(&Statement{Account: "alice", Seq: 2, Keys: []string{a}}, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, by, err := Verify(signed, Trust{Account: "alice", Seq: 1, Signers: []string{b, a + " c"}}); err != nil || ssh.FingerprintSHA256(by) != ssh.FingerprintSHA256(s.PublicKey()) {
		t.Fatalf("verify: %v", err)
	}
	if _, _, err := Verify(signed, Trust{Seq: 1, Signers: []string{b}}); err == nil {
		t.Fatal("verified against other signers")
	}
	changed := strings.Replace(string(signed), "seq 2", "seq 9", 1)
	if _, _, err := Verify([]byte(changed), Trust{Seq: 1, Signers: []string{a}}); err == nil {
		t.Fatal("a changed text verified")
	}
}

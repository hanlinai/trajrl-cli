package userverify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The key file ssh would use without -i: the first of id_ed25519,
// id_ecdsa, id_rsa that exists and has no passphrase; one with a
// passphrase is passed over and named.
func TestDefaultKeyFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, key any, pass string) {
		var block *pem.Block
		var err error
		if pass == "" {
			block, err = ssh.MarshalPrivateKey(key, "")
		} else {
			block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(pass))
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if f, locked := DefaultKeyFile(dir); f != "" || locked != nil {
		t.Fatalf("an empty directory: %q %q", f, locked)
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	write("id_ed25519", ed, "secret")
	if f, locked := DefaultKeyFile(dir); f != "" || !reflect.DeepEqual(locked, []string{filepath.Join(dir, "id_ed25519")}) {
		t.Fatalf("only a key with a passphrase: %q %q", f, locked)
	}
	write("id_rsa", ed, "") // any key under that name
	write("id_ecdsa", ec, "")
	f, locked := DefaultKeyFile(dir)
	if f != filepath.Join(dir, "id_ecdsa") || len(locked) != 1 {
		t.Fatalf("got %q %q, want id_ecdsa with id_ed25519 passed over", f, locked)
	}
	if _, err := LoadIdentity(f); err != nil {
		t.Fatal(err)
	}
	write("id_ed25519", ed, "")
	if f, locked := DefaultKeyFile(dir); f != filepath.Join(dir, "id_ed25519") || locked != nil {
		t.Fatalf("got %q %q, want id_ed25519", f, locked)
	}
	t.Setenv("SSH_AUTH_SOCK", "")
	if AgentHasKeys() {
		t.Fatal("no agent, and AgentHasKeys")
	}
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "no-such-socket"))
	if AgentHasKeys() {
		t.Fatal("an agent socket that is not there, and AgentHasKeys")
	}
}

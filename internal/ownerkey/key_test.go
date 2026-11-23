package ownerkey

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// (g) The recovery phrase gives the master secret back, and a phrase with one
// character wrong, missing or extra is refused, never read as another secret.
func TestRecoveryPhraseRoundTripAndOneCharacterErrors(t *testing.T) {
	for range 20 {
		m, err := NewMaster()
		if err != nil {
			t.Fatal(err)
		}
		phrase := m.Phrase()
		if g := strings.Split(phrase, "-"); len(g) != PhraseGroups {
			t.Fatalf("%d groups", len(g))
		}
		back, err := ParsePhrase(phrase)
		if err != nil || !back.Equal(m) {
			t.Fatalf("round trip: %v", err)
		}
		// As a person might type it: lower case, spaces, O for 0, l for 1.
		typed := strings.NewReplacer("-", " ", "0", "o", "1", "l").Replace(strings.ToLower(phrase))
		if back, err := ParsePhrase(typed); err != nil || !back.Equal(m) {
			t.Fatalf("typed form: %v", err)
		}
		// Every single-character substitution, at every position.
		flat := strings.ReplaceAll(phrase, "-", "")
		for i := range len(flat) {
			for _, c := range crockford {
				if byte(c) == flat[i] {
					continue
				}
				bad := flat[:i] + string(c) + flat[i+1:]
				if got, err := ParsePhrase(bad); err == nil {
					t.Fatalf("a phrase with character %d changed was accepted (same secret: %v)", i, got.Equal(m))
				}
			}
		}
		// Two neighbours swapped.
		for i := range len(flat) - 1 {
			if flat[i] == flat[i+1] {
				continue
			}
			swapped := flat[:i] + string(flat[i+1]) + string(flat[i]) + flat[i+2:]
			if _, err := ParsePhrase(swapped); err == nil {
				t.Fatalf("a phrase with characters %d and %d swapped was accepted", i, i+1)
			}
		}
		if _, err := ParsePhrase(flat[1:]); err == nil {
			t.Fatal("a phrase with a character missing was accepted")
		}
		if _, err := ParsePhrase(flat + "0"); err == nil {
			t.Fatal("a phrase with a character too many was accepted")
		}
		if _, err := ParsePhrase(flat[:10] + "U" + flat[11:]); err == nil {
			t.Fatal("a character outside the alphabet was accepted")
		}
	}
	// The secret is not in anything printed of a Master.
	m, _ := NewMaster()
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		if s := fmt.Sprintf(verb, m); strings.Contains(s, fmt.Sprintf("%x", m.b[:4])) || strings.Contains(s, m.Phrase()[:9]) {
			t.Fatalf("%s prints the secret: %s", verb, s)
		}
	}
}

// (h) The key file opens with its passphrase and with nothing else, is mode
// 0600 and is never written over.
func TestKeyFilePassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.key")
	pass := []byte("correct horse battery staple, long")
	m, _ := NewMaster()
	if err := m.WriteKeyFile(path, []byte("short")); err == nil {
		t.Fatal("a key file was sealed under a short passphrase")
	}
	if err := m.WriteKeyFile(path, pass); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, m.b[:]) || bytes.Contains(raw, []byte(m.Phrase()[:9])) {
		t.Fatal("the key file holds the secret in the clear")
	}
	back, err := LoadKeyFile(path, pass)
	if err != nil || !back.Equal(m) {
		t.Fatalf("the right passphrase: %v", err)
	}
	if _, err := LoadKeyFile(path, []byte("correct horse battery staple, LONG")); !errors.Is(err, ErrKeyFileAuth) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	other, _ := NewMaster()
	if err := other.WriteKeyFile(path, pass); err == nil || !strings.Contains(err.Error(), "never written over") {
		t.Fatalf("written over: %v", err)
	}
	if back, _ := LoadKeyFile(path, pass); !back.Equal(m) {
		t.Fatal("the key file changed")
	}
	// One bit changed anywhere in the sealed part: it does not open.
	raw[len(raw)-5] ^= 1
	cut := filepath.Join(dir, "changed.key")
	os.WriteFile(cut, raw, 0o600)
	if _, err := LoadKeyFile(cut, pass); !errors.Is(err, ErrKeyFileAuth) {
		t.Fatalf("a changed file: %v", err)
	}
}

// One master secret, one disk secret per sandbox, none equal to another.
func TestDiskSecretPerSandbox(t *testing.T) {
	m, _ := NewMaster()
	a, err := m.DiskSecret("sbx-00000000000000a1")
	if err != nil || len(a) != 32 {
		t.Fatal(err)
	}
	b, _ := m.DiskSecret("sbx-00000000000000a2")
	a2, _ := m.DiskSecret("sbx-00000000000000a1")
	other, _ := NewMaster()
	c, _ := other.DiskSecret("sbx-00000000000000a1")
	if bytes.Equal(a, b) || !bytes.Equal(a, a2) || bytes.Equal(a, c) || bytes.Equal(a, m.b[:]) {
		t.Fatal("disk secrets are not one per sandbox and owner")
	}
	if _, err := m.DiskSecret("web"); err == nil {
		t.Fatal("a disk secret for something that is not a sandbox ID")
	}
}

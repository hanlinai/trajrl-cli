// Package ownerkey is the sandbox owner's side of a sandbox's boot: the
// owner, not the platform, holds every disk key.
//
// The owner has one 32-byte master secret, kept in a key file sealed under a
// passphrase and, on paper, as a recovery phrase. A sandbox's disk secret is
// derived from it and the sandbox's ID; nothing per sandbox is secret. At
// every boot the sandbox's TD waits; the owner's tool (cmd/sbxkey) is handed
// the TD's connection by the platform, verifies the TD's quote against
// Intel's PKI and the owner's own launch policies, and only then sends the
// disk secret (Unlock). The platform relays bytes and never has a disk key.
//
// What follows from that, and is accepted: no unattended restart (a stopped
// sandbox waits for its owner), and a lost master secret is lost data.
package ownerkey

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/proto"
	"github.com/hanlinai/trajrl-cli/internal/sealedfile"
)

// MasterLen is the length of the owner's master secret.
const MasterLen = 32

// Master is the owner's master secret. Its printing verbs show nothing of it.
type Master struct {
	b [MasterLen]byte
}

// NewMaster makes a master secret.
func NewMaster() (*Master, error) {
	m := &Master{}
	if _, err := rand.Read(m.b[:]); err != nil {
		return nil, err
	}
	return m, nil
}

// Wipe overwrites the secret in memory.
func (m *Master) Wipe() { sealedfile.Wipe(m.b[:]) }

func (m Master) String() string             { return "owner master secret (not shown)" }
func (m Master) Format(f fmt.State, _ rune) { io.WriteString(f, m.String()) }
func (m Master) GoString() string           { return m.String() }

// Equal reports whether o is the same secret.
func (m *Master) Equal(o *Master) bool { return o != nil && m.b == o.b }

func masterFrom(b []byte) (*Master, error) {
	if len(b) != MasterLen {
		return nil, errors.New("a master secret is 32 bytes")
	}
	m := &Master{}
	copy(m.b[:], b)
	return m, nil
}

// DiskSecretInfo is the HKDF info prefix of a disk secret; the sandbox's ID
// follows it.
const DiskSecretInfo = "tdx-sandbox/disk-secret/v1"

// DiskSecret is the disk secret of one sandbox:
// HKDF-SHA256(master, info = DiskSecretInfo ‖ sandbox ID). The guest derives
// its disk keys from it and from the salt of its disk's format.
func (m *Master) DiskSecret(sandboxID string) ([]byte, error) {
	if !proto.ValidSandboxID(sandboxID) {
		return nil, fmt.Errorf("invalid sandbox id %q", sandboxID)
	}
	return hkdf.Key(sha256.New, m.b[:], nil, DiskSecretInfo+sandboxID, proto.SecretLen)
}

// The key file: sealedfile with this magic; the JSON inside is keyDoc.
const (
	keyMagic = "TDX-SANDBOX-OWNER-KEY-1\n"
	keyKind  = "tdx-sandbox/owner-key/v1"
	// KeyFileKind names the file in messages.
	KeyFileKind = "a sandbox owner's key file"
)

// MinPassphrase is the shortest passphrase the key file is sealed with.
const MinPassphrase = sealedfile.MinPassphrase

type keyDoc struct {
	Kind    string    `json:"kind"`
	Master  []byte    `json:"master"`
	Created time.Time `json:"created"`
}

// WriteKeyFile seals the master secret under passphrase into a new file
// (mode 0600, never over an existing file).
func (m *Master) WriteKeyFile(path string, passphrase []byte) error {
	doc := keyDoc{Kind: keyKind, Master: append([]byte(nil), m.b[:]...), Created: time.Now().UTC().Truncate(time.Second)}
	defer sealedfile.Wipe(doc.Master)
	plain, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	defer sealedfile.Wipe(plain)
	return sealedfile.Describe(path, KeyFileKind, sealedfile.Write(path, keyMagic, plain, passphrase))
}

// ErrKeyFileAuth is returned when the key file does not open.
var ErrKeyFileAuth = sealedfile.ErrAuth

// KeyFileShape says whether path is a key file by its first line, without
// opening it (no passphrase): trajrl doctor.
func KeyFileShape(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b := make([]byte, len(keyMagic))
	if _, err := io.ReadFull(f, b); err != nil || string(b) != keyMagic {
		return fmt.Errorf("%s is not %s", path, KeyFileKind)
	}
	return nil
}

// LoadKeyFile opens the key file.
func LoadKeyFile(path string, passphrase []byte) (*Master, error) {
	plain, err := sealedfile.Read(path, keyMagic, passphrase)
	if err != nil {
		return nil, sealedfile.Describe(path, KeyFileKind, err)
	}
	defer sealedfile.Wipe(plain)
	var doc keyDoc
	// Errors of the JSON decoder can quote the input; they are not passed on.
	if json.Unmarshal(plain, &doc) != nil || doc.Kind != keyKind {
		return nil, fmt.Errorf("%s: unreadable contents", path)
	}
	defer sealedfile.Wipe(doc.Master)
	return masterFrom(doc.Master)
}

// The recovery phrase is the master secret written for a person: Crockford
// base32 (digits and capitals without I, L, O and U; on reading, case is
// ignored and I, L read as 1 and O as 0), 52 characters for the 256 bits
// (the last one's 4 spare bits zero), then a check group of 4 characters, in
// groups of 4 joined by "-": 14 groups in all. The check group's first
// character is sum(d_i * a^i) over GF(32) of the 52 data characters, which
// changes with any one wrong character and with any two adjacent ones
// swapped; the other three are 15 bits of a SHA-256 of the secret, against
// anything else. A missing or extra character is caught by the length.
const (
	crockford      = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	phraseData     = 52 // 260 bits, the last 4 zero
	phraseCheck    = 4
	PhraseGroups   = (phraseData + phraseCheck) / 4
	phraseCheckTag = "tdx-sandbox/recovery-phrase/v1"
)

// gfMul multiplies in GF(32) = GF(2)[x]/(x^5 + x^2 + 1).
func gfMul(a, b byte) byte {
	var p byte
	for b != 0 {
		if b&1 != 0 {
			p ^= a
		}
		b >>= 1
		a <<= 1
		if a&0x20 != 0 {
			a ^= 0x25
		}
	}
	return p
}

// phraseCheckOf is the check group of the data characters sym (Crockford
// digits) and the secret b they encode.
func phraseCheckOf(sym string, b []byte) string {
	var lin, w byte = 0, 1
	for i := range len(sym) {
		lin ^= gfMul(byte(strings.IndexByte(crockford, sym[i])), w)
		w = gfMul(w, 2) // a = x, a primitive element
	}
	h := sha256.New()
	h.Write([]byte(phraseCheckTag))
	h.Write(b)
	sum := h.Sum(nil)
	v := uint32(sum[0])<<7 | uint32(sum[1])>>1
	out := []byte{crockford[lin], 0, 0, 0}
	for i := phraseCheck - 1; i >= 1; i-- {
		out[i] = crockford[v&31]
		v >>= 5
	}
	return string(out)
}

// Phrase is the recovery phrase of the master secret, in groups.
func (m *Master) Phrase() string {
	var sym []byte
	var acc uint32
	bits := 0
	for _, x := range m.b {
		acc = acc<<8 | uint32(x)
		bits += 8
		for bits >= 5 {
			sym = append(sym, crockford[(acc>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		sym = append(sym, crockford[(acc<<(5-bits))&31])
	}
	all := string(sym) + phraseCheckOf(string(sym), m.b[:])
	groups := make([]string, 0, PhraseGroups)
	for i := 0; i < len(all); i += 4 {
		groups = append(groups, all[i:i+4])
	}
	return strings.Join(groups, "-")
}

// PhraseGroupsOf splits a phrase into its groups, normalised; nil if it does
// not have the shape of one.
func PhraseGroupsOf(s string) []string {
	n, err := normalisePhrase(s)
	if err != nil {
		return nil
	}
	out := make([]string, 0, PhraseGroups)
	for i := 0; i < len(n); i += 4 {
		out = append(out, n[i:i+4])
	}
	return out
}

// NormaliseGroup reads part of a phrase as ParsePhrase does (case, I, L, O,
// separators), for comparing what an owner types back with a group.
func NormaliseGroup(s string) string {
	var b strings.Builder
	normalise(&b, s)
	return b.String()
}

func normalise(b *strings.Builder, s string) error {
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
			continue
		case r == 'O':
			r = '0'
		case r == 'I' || r == 'L':
			r = '1'
		}
		if r > 127 || strings.IndexByte(crockford, byte(r)) < 0 {
			return fmt.Errorf("%q is not a character of a recovery phrase", r)
		}
		b.WriteRune(r)
	}
	return nil
}

func normalisePhrase(s string) (string, error) {
	var b strings.Builder
	if err := normalise(&b, s); err != nil {
		return "", err
	}
	if b.Len() != phraseData+phraseCheck {
		return "", fmt.Errorf("the phrase has %d characters; a recovery phrase has %d (%d groups of 4)", b.Len(), phraseData+phraseCheck, PhraseGroups)
	}
	return b.String(), nil
}

// ParsePhrase is the reverse of Phrase. It refuses a phrase with a wrong,
// missing or extra character.
func ParsePhrase(s string) (*Master, error) {
	n, err := normalisePhrase(s)
	if err != nil {
		return nil, err
	}
	m := &Master{}
	var acc uint32
	bits, j := 0, 0
	for i := 0; i < phraseData; i++ {
		acc = acc<<5 | uint32(strings.IndexByte(crockford, n[i]))
		bits += 5
		if bits >= 8 {
			m.b[j] = byte(acc >> (bits - 8))
			j++
			bits -= 8
		}
	}
	if acc&((1<<bits)-1) != 0 || j != MasterLen {
		m.Wipe()
		return nil, errors.New("the phrase does not check: a character is wrong")
	}
	if phraseCheckOf(n[:phraseData], m.b[:]) != n[phraseData:] {
		m.Wipe()
		return nil, errors.New("the phrase does not check: a character is wrong")
	}
	return m, nil
}

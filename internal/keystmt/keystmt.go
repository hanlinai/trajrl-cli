// Package keystmt is the owner-signed statement of an account's SSH keys
// (#65): which keys log in to the owner's sandboxes, which further keys log
// in to one sandbox only (a colleague's), and the recovery key, which never
// logs in and may only sign the next statement. A sandbox accepts a new
// statement only if a key of the last one it applied signed it, so neither
// the platform, which stores and relays statements, nor anyone who takes
// over the owner's website session, can put a key into a sandbox.
//
// The statement is UTF-8 text, one item a line, in this order:
//
//	sbx-keys v1
//	account ACCOUNT
//	seq N
//	key <authorized_keys line>          0..16: the account's login keys
//	sandbox SANDBOX-ID key <line>       0..16 per sandbox: that sandbox only
//	recovery <public key>               0..1: signs statements, never logs in
//
// followed by its SSHSIG signature (internal/sshsig, namespace
// sbx-keys@trajrl), armored, as "ssh-keygen -Y sign" writes it. A sandbox
// is named by its ID (sbx-<16 hex>), which its TD knows from its attested
// boot and which a rename leaves as it is; the owner's sbxkey takes NAME
// and writes the ID its record holds.
package keystmt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/proto"
	"github.com/hanlinai/trajrl-cli/internal/sshsig"
)

const (
	// Namespace is the SSHSIG namespace of statements: a signature made
	// for anything else (git, files) is not one.
	Namespace = "sbx-keys@trajrl"
	header    = "sbx-keys v1"
	// MaxSize bounds a signed statement, text and signature: it travels in
	// the owner's release (proto.MaxKeyStatement).
	MaxSize = proto.MaxKeyStatement
	// MaxKeys is the most login keys, and the most keys of one sandbox.
	MaxKeys = 16
	// MaxSandboxLines is the most "sandbox" lines in all.
	MaxSandboxLines = 128
	beginSig        = "-----BEGIN SSH SIGNATURE-----"
)

// SandboxKey is one key of one sandbox only.
type SandboxKey struct {
	Sandbox string `json:"sandbox"` // its ID
	Key     string `json:"key"`     // an authorized_keys line
}

// Statement is the text of a statement.
type Statement struct {
	Account   string       `json:"account"`
	Seq       uint64       `json:"seq"`
	Keys      []string     `json:"keys"`
	Sandboxes []SandboxKey `json:"sandboxes,omitempty"`
	Recovery  string       `json:"recovery,omitempty"`
}

// Text is the statement as it is signed.
func (s *Statement) Text() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\naccount %s\nseq %d\n", header, s.Account, s.Seq)
	for _, k := range s.Keys {
		b.WriteString("key " + k + "\n")
	}
	for _, k := range s.Sandboxes {
		b.WriteString("sandbox " + k.Sandbox + " key " + k.Key + "\n")
	}
	if s.Recovery != "" {
		b.WriteString("recovery " + s.Recovery + "\n")
	}
	return b.Bytes()
}

// KeysOf returns the lines that log in to the sandbox with this ID: the
// login keys, then its own.
func (s *Statement) KeysOf(sandboxID string) []string {
	out := append([]string(nil), s.Keys...)
	for _, k := range s.Sandboxes {
		if k.Sandbox == sandboxID {
			out = append(out, k.Key)
		}
	}
	return out
}

// Signers are the keys that may sign the statement after this one: its
// login keys and its recovery key. A sandbox's own keys may not.
func (s *Statement) Signers() []string {
	out := append([]string(nil), s.Keys...)
	if s.Recovery != "" {
		out = append(out, s.Recovery)
	}
	return out
}

// ParseKeyLine parses one authorized_keys line (options and a comment
// allowed) and returns it trimmed, and its key.
func ParseKeyLine(line string) (string, ssh.PublicKey, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") || !utf8.ValidString(line) {
		return "", nil, errors.New("not one authorized_keys line")
	}
	k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", nil, fmt.Errorf("not an authorized_keys line: %.40q", line)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return "", nil, errors.New("more than one key on a line")
	}
	if _, ok := k.(*ssh.Certificate); ok {
		return "", nil, errors.New("a certificate is not a key here")
	}
	return line, k, nil
}

// ParseRecovery parses a recovery key: a public key, "type base64
// [comment]", without options, of a type that can sign statements.
func ParseRecovery(line string) (string, ssh.PublicKey, error) {
	line, k, err := ParseKeyLine(line)
	if err != nil {
		return "", nil, err
	}
	_, _, opts, _, _ := ssh.ParseAuthorizedKey([]byte(line))
	if len(opts) != 0 {
		return "", nil, errors.New("a recovery key has no options")
	}
	if !sshsig.KeyAllowed(k) {
		return "", nil, fmt.Errorf("a %s key cannot be a recovery key", k.Type())
	}
	return line, k, nil
}

// ValidAccount reports whether s can be an account name in a statement.
func ValidAccount(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// Check checks a statement as Parse would.
func (s *Statement) Check() error {
	_, err := Parse(s.Text())
	return err
}

// Parse parses a statement's text, strictly: the header, account and seq
// lines first, then key, sandbox and recovery lines, and nothing else.
func Parse(text []byte) (*Statement, error) {
	if len(text) > MaxSize || !utf8.Valid(text) {
		return nil, errors.New("the statement is too long, or not UTF-8")
	}
	if len(text) == 0 || text[len(text)-1] != '\n' {
		return nil, errors.New("the statement does not end with a new line")
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) < 3 || lines[0] != header {
		return nil, fmt.Errorf("not a statement: the first line is not %q", header)
	}
	st := &Statement{}
	acc, ok := strings.CutPrefix(lines[1], "account ")
	if !ok || !ValidAccount(acc) {
		return nil, fmt.Errorf("line 2 is not \"account NAME\": %.60q", lines[1])
	}
	st.Account = acc
	seq, ok := strings.CutPrefix(lines[2], "seq ")
	n, err := strconv.ParseUint(seq, 10, 63)
	if !ok || err != nil || strconv.FormatUint(n, 10) != seq {
		return nil, fmt.Errorf("line 3 is not \"seq N\": %.60q", lines[2])
	}
	st.Seq = n
	seen := map[string]bool{}
	perSandbox := map[string]int{}
	for i, l := range lines[3:] {
		no := i + 4
		switch {
		case strings.HasPrefix(l, "key "):
			line, k, err := ParseKeyLine(l[len("key "):])
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", no, err)
			}
			if seen["key "+string(k.Marshal())] {
				return nil, fmt.Errorf("line %d: a key given twice", no)
			}
			seen["key "+string(k.Marshal())] = true
			st.Keys = append(st.Keys, line)
			if len(st.Keys) > MaxKeys {
				return nil, fmt.Errorf("more than %d keys", MaxKeys)
			}
		case strings.HasPrefix(l, "sandbox "):
			id, rest, _ := strings.Cut(l[len("sandbox "):], " ")
			kl, ok := strings.CutPrefix(rest, "key ")
			if !proto.ValidSandboxID(id) || !ok {
				return nil, fmt.Errorf("line %d is not \"sandbox SANDBOX-ID key LINE\" (the sandbox by its ID, sbx-...)", no)
			}
			line, k, err := ParseKeyLine(kl)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", no, err)
			}
			if seen[id+" "+string(k.Marshal())] {
				return nil, fmt.Errorf("line %d: a key given twice for %s", no, id)
			}
			seen[id+" "+string(k.Marshal())] = true
			st.Sandboxes = append(st.Sandboxes, SandboxKey{id, line})
			if perSandbox[id]++; perSandbox[id] > MaxKeys {
				return nil, fmt.Errorf("more than %d keys for %s", MaxKeys, id)
			}
			if len(st.Sandboxes) > MaxSandboxLines {
				return nil, fmt.Errorf("more than %d sandbox lines", MaxSandboxLines)
			}
		case strings.HasPrefix(l, "recovery "):
			if st.Recovery != "" {
				return nil, fmt.Errorf("line %d: a second recovery key", no)
			}
			line, _, err := ParseRecovery(l[len("recovery "):])
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", no, err)
			}
			st.Recovery = line
		default:
			return nil, fmt.Errorf("line %d is not a key, sandbox or recovery line: %.60q", no, l)
		}
	}
	return st, nil
}

// Split separates a signed statement into its text and its armored
// signature.
func Split(signed []byte) (text, sig []byte, err error) {
	if len(signed) > MaxSize {
		return nil, nil, fmt.Errorf("a signed statement has at most %d bytes", MaxSize)
	}
	signed = bytes.ReplaceAll(signed, []byte("\r\n"), []byte("\n"))
	i := bytes.Index(signed, []byte("\n"+beginSig))
	if i < 0 {
		return nil, nil, errors.New("the statement is not signed (no SSH signature after it)")
	}
	return signed[:i+1], signed[i+1:], nil
}

// Sign signs a statement and returns it signed: its text, then the
// signature.
func Sign(st *Statement, signer ssh.Signer) ([]byte, error) {
	if err := st.Check(); err != nil {
		return nil, err
	}
	text := st.Text()
	sig, err := sshsig.Sign(signer, Namespace, text)
	if err != nil {
		return nil, err
	}
	out := append(text, sig...)
	if len(out) > MaxSize {
		return nil, fmt.Errorf("the signed statement has %d bytes; at most %d", len(out), MaxSize)
	}
	return out, nil
}

// Trust is what a new statement is checked against: the last one applied.
type Trust struct {
	// Account: the statement's account must be this one. Empty: not yet
	// known (no statement applied yet), any.
	Account string
	// Seq: the statement's seq must be greater.
	Seq uint64
	// Signers: authorized_keys lines; one of their keys must have signed.
	Signers []string
}

// TrustOf is the trust a statement, once applied, gives the next one.
func TrustOf(s *Statement) Trust {
	return Trust{Account: s.Account, Seq: s.Seq, Signers: s.Signers()}
}

// Verify checks a signed statement against the trust of the last one
// applied. It returns the statement and the key that signed it.
func Verify(signed []byte, t Trust) (*Statement, ssh.PublicKey, error) {
	text, sig, err := Split(signed)
	if err != nil {
		return nil, nil, err
	}
	st, err := Parse(text)
	if err != nil {
		return nil, nil, err
	}
	if t.Account != "" && st.Account != t.Account {
		return nil, nil, fmt.Errorf("the statement is for account %q, not %q", st.Account, t.Account)
	}
	if st.Seq <= t.Seq {
		return nil, nil, fmt.Errorf("the statement's seq %d is not greater than the last applied, %d", st.Seq, t.Seq)
	}
	by, err := sshsig.Verify(sig, text, Namespace)
	if err != nil {
		return nil, nil, err
	}
	for _, l := range t.Signers {
		if _, k, err := ParseKeyLine(l); err == nil && sshsig.Equal(k, by) {
			return st, by, nil
		}
	}
	return nil, nil, fmt.Errorf("the statement is signed by %s, which is not a key of the last applied statement", ssh.FingerprintSHA256(by))
}

// Info is a signed statement as "ssh-key statement --json" prints it.
type Info struct {
	Statement
	// SignedBy is the fingerprint of the key that signed it.
	SignedBy string `json:"signed_by"`
	// Signed is the signed statement itself.
	Signed string `json:"signed"`
}

// MarshalSigned is the JSON of a signed statement, which must parse.
func MarshalSigned(signed []byte) ([]byte, error) {
	text, sig, err := Split(signed)
	if err != nil {
		return nil, err
	}
	st, err := Parse(text)
	if err != nil {
		return nil, err
	}
	by, err := sshsig.Verify(sig, text, Namespace)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Info{Statement: *st, SignedBy: ssh.FingerprintSHA256(by), Signed: string(signed)})
}

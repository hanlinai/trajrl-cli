// Package sshsig signs and verifies messages in OpenSSH's signature format,
// SSHSIG: what "ssh-keygen -Y sign" writes and "ssh-keygen -Y verify" reads
// (OpenSSH's PROTOCOL.sshsig). A signature names its public key, a
// namespace that keeps signatures made for one purpose from being taken for
// another, and the hash of the message; it is armored as
//
//	-----BEGIN SSH SIGNATURE-----
//	base64, 70 columns
//	-----END SSH SIGNATURE-----
//
// Keys: Ed25519 and ECDSA (P-256, P-384, P-521), and RSA with SHA-2
// signatures (rsa-sha2-512 when signing; a SHA-1 "ssh-rsa" signature is
// refused). Security-key (sk-) keys and certificates are not accepted.
package sshsig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	magic   = "SSHSIG"
	version = 1
	// HashSHA512 is the hash this package signs with, as ssh-keygen does.
	HashSHA512 = "sha512"
	hashSHA256 = "sha256"

	beginLine = "-----BEGIN SSH SIGNATURE-----"
	endLine   = "-----END SSH SIGNATURE-----"
	// MaxArmored bounds an armored signature this package reads: an RSA
	// key of 16384 bits and its signature fit.
	MaxArmored = 8 << 10
)

// allowed are the key types accepted, with the signature algorithms each
// may sign with.
var allowed = map[string][]string{
	ssh.KeyAlgoED25519:  {ssh.KeyAlgoED25519},
	ssh.KeyAlgoECDSA256: {ssh.KeyAlgoECDSA256},
	ssh.KeyAlgoECDSA384: {ssh.KeyAlgoECDSA384},
	ssh.KeyAlgoECDSA521: {ssh.KeyAlgoECDSA521},
	ssh.KeyAlgoRSA:      {ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
}

// KeyAllowed reports whether a key of this type can sign and be verified
// here.
func KeyAllowed(k ssh.PublicKey) bool {
	_, ok := allowed[k.Type()]
	return ok
}

// signedData is what the key actually signs: the preamble, the namespace,
// the reserved field, the hash's name and the message's hash.
func signedData(namespace, hash string, message []byte) ([]byte, error) {
	var h []byte
	switch hash {
	case HashSHA512:
		s := sha512.Sum512(message)
		h = s[:]
	case hashSHA256:
		s := sha256.Sum256(message)
		h = s[:]
	default:
		return nil, fmt.Errorf("hash %q is not supported", hash)
	}
	return append([]byte(magic), ssh.Marshal(struct {
		Namespace, Reserved, Hash string
		H                         []byte
	}{namespace, "", hash, h})...), nil
}

// blob is the signature's binary form after the preamble.
type blob struct {
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	Hash      string
	Signature []byte
}

// Sign signs message for namespace with signer and returns the armored
// signature. An RSA key signs with rsa-sha2-512.
func Sign(signer ssh.Signer, namespace string, message []byte) ([]byte, error) {
	if namespace == "" {
		return nil, errors.New("sshsig: a namespace is required")
	}
	pub := signer.PublicKey()
	if !KeyAllowed(pub) {
		return nil, fmt.Errorf("sshsig: a %s key cannot sign here (Ed25519, ECDSA or RSA)", pub.Type())
	}
	data, err := signedData(namespace, HashSHA512, message)
	if err != nil {
		return nil, err
	}
	var sig *ssh.Signature
	if pub.Type() == ssh.KeyAlgoRSA {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("sshsig: this RSA key cannot make SHA-2 signatures")
		}
		sig, err = as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
	} else {
		sig, err = signer.Sign(rand.Reader, data)
	}
	if err != nil {
		return nil, fmt.Errorf("sshsig: signing: %w", err)
	}
	b := append([]byte(magic), ssh.Marshal(blob{Version: version, PublicKey: pub.Marshal(), Namespace: namespace,
		Hash: HashSHA512, Signature: ssh.Marshal(sig)})...)
	return armor(b), nil
}

func armor(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out bytes.Buffer
	out.WriteString(beginLine + "\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n" + endLine + "\n")
	return out.Bytes()
}

func unarmor(armored []byte) ([]byte, error) {
	if len(armored) > MaxArmored {
		return nil, errors.New("sshsig: the signature is too long")
	}
	s := strings.TrimSpace(strings.ReplaceAll(string(armored), "\r\n", "\n"))
	if !strings.HasPrefix(s, beginLine+"\n") || !strings.HasSuffix(s, "\n"+endLine) {
		return nil, errors.New("sshsig: not an armored SSH signature")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(s, beginLine+"\n"), "\n"+endLine)
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	if err != nil {
		return nil, fmt.Errorf("sshsig: the signature's base64: %w", err)
	}
	return b, nil
}

// Verify checks an armored signature of message under namespace and returns
// the public key it names, which made it. Which keys to trust is the
// caller's decision: compare the key returned (Equal) with those.
func Verify(armored, message []byte, namespace string) (ssh.PublicKey, error) {
	b, err := unarmor(armored)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(b, []byte(magic)) {
		return nil, errors.New("sshsig: no SSHSIG preamble")
	}
	var bl blob
	if err := ssh.Unmarshal(b[len(magic):], &bl); err != nil {
		return nil, fmt.Errorf("sshsig: malformed signature: %w", err)
	}
	if bl.Version != version {
		return nil, fmt.Errorf("sshsig: signature version %d is not supported", bl.Version)
	}
	if bl.Namespace != namespace {
		return nil, fmt.Errorf("sshsig: the signature is for namespace %q, not %q", bl.Namespace, namespace)
	}
	pub, err := ssh.ParsePublicKey(bl.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sshsig: the signature's public key: %w", err)
	}
	algs, ok := allowed[pub.Type()]
	if !ok {
		return nil, fmt.Errorf("sshsig: a signature by a %s key is not accepted", pub.Type())
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(bl.Signature, &sig); err != nil {
		return nil, fmt.Errorf("sshsig: malformed signature: %w", err)
	}
	okAlg := false
	for _, a := range algs {
		okAlg = okAlg || sig.Format == a
	}
	if !okAlg {
		return nil, fmt.Errorf("sshsig: a %s signature by a %s key is not accepted", sig.Format, pub.Type())
	}
	data, err := signedData(namespace, bl.Hash, message)
	if err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	if err := pub.Verify(data, &sig); err != nil {
		return nil, errors.New("sshsig: the signature does not verify")
	}
	return pub, nil
}

// Equal reports whether two public keys are the same key.
func Equal(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(a.Marshal(), b.Marshal())
}

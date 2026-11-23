// Package sealedfile keeps a small secret document in a file sealed under a
// passphrase, behind a magic line that says what the file is:
//
//	file   = magic | sealed
//	sealed = header | AES-256-GCM(key, nonce, document, additional data = header)
//	header = "TDX-SANDBOX-KBS-BACKUP-1\n" | log2 N (1) | r (1) | p (1) | salt (16) | nonce (12)
//	key    = scrypt(passphrase, salt, N = 2^15, r = 8, p = 1)
//
// sealed is byte for byte the format of a broker backup (kbs.Seal), which
// custodians' files have always used; it is implemented here on its own so
// that the owner's tool needs nothing of the broker.
//
// A file is written with mode 0600, created with O_EXCL (never over another
// file) and made durable before it counts as written. Nothing of it is
// readable without the passphrase, and every byte of the document is
// authenticated. A custodian's key and share files (internal/custodian) and
// a sandbox owner's key file (internal/ownerkey) are such files.
package sealedfile

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

// MinPassphrase is the shortest passphrase a file is sealed with (the same
// as kbs.MinPassphrase).
const MinPassphrase = 20

const (
	sealMagic  = "TDX-SANDBOX-KBS-BACKUP-1\n"
	sealLogN   = 15
	sealR      = 8
	sealP      = 1
	sealHeader = len(sealMagic) + 3 + 16 + 12
)

func sealKey(passphrase, header []byte) (cipher.AEAD, error) {
	logN, r, p := int(header[len(sealMagic)]), int(header[len(sealMagic)+1]), int(header[len(sealMagic)+2])
	// Fixed here: a file asking for other parameters is not one of ours, and
	// does not get to choose how much memory opening it takes.
	if logN != sealLogN || r != sealR || p != sealP {
		return nil, ErrNotSealed
	}
	salt := header[len(sealMagic)+3 : len(sealMagic)+3+16]
	key, err := scrypt.Key(passphrase, salt, 1<<logN, r, p, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal encrypts and authenticates doc under passphrase.
func Seal(doc, passphrase []byte) ([]byte, error) {
	if len(passphrase) < MinPassphrase {
		return nil, fmt.Errorf("passphrase too short: at least %d characters are required", MinPassphrase)
	}
	header := make([]byte, sealHeader)
	n := copy(header, sealMagic)
	header[n], header[n+1], header[n+2] = sealLogN, sealR, sealP
	if _, err := rand.Read(header[n+3:]); err != nil {
		return nil, err
	}
	aead, err := sealKey(passphrase, header)
	if err != nil {
		return nil, err
	}
	return aead.Seal(header, header[sealHeader-12:], doc, header), nil
}

// Unseal is the reverse of Seal: ErrAuth if the passphrase is wrong or one
// bit has changed, ErrNotSealed if it is not of this format.
func Unseal(blob, passphrase []byte) ([]byte, error) {
	if len(blob) < sealHeader+16 || string(blob[:len(sealMagic)]) != sealMagic {
		return nil, ErrNotSealed
	}
	header := blob[:sealHeader]
	aead, err := sealKey(passphrase, header)
	if err != nil {
		return nil, err
	}
	doc, err := aead.Open(nil, header[sealHeader-12:], blob[sealHeader:], header)
	if err != nil {
		return nil, ErrAuth
	}
	return doc, nil
}

// MaxFile bounds what Read takes in.
const MaxFile = 1 << 20

var (
	// ErrExist is returned by Write when the file already exists.
	ErrExist = os.ErrExist
	// ErrAuth is returned by Read when the file does not open: a wrong
	// passphrase, or a file that was changed or cut short.
	ErrAuth = errors.New("the file does not open: wrong passphrase, or the file was changed or cut short")
	// ErrNotSealed is returned by Read for a file that is not one of these
	// with the given magic.
	ErrNotSealed = errors.New("not a file of this kind")
)

// Write seals doc under passphrase into a new file at path, which must not
// exist (ErrExist).
func Write(path, magic string, doc, passphrase []byte) error {
	sealed, err := Seal(doc, passphrase)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append([]byte(magic), sealed...))
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path) // this call made it, and it is not whole
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Read opens a file Write made with the same magic. The document is the
// caller's to wipe.
func Read(path, magic string, passphrase []byte) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	blob, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(blob) > MaxFile || !bytes.HasPrefix(blob, []byte(magic)) {
		return nil, ErrNotSealed
	}
	doc, err := Unseal(blob[len(magic):], passphrase)
	if err != nil && !errors.Is(err, ErrAuth) {
		return nil, ErrNotSealed
	}
	return doc, err
}

// Wipe overwrites b with zeros.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Describe is a short account of a Write or Read error for a person, naming
// the file and what kind it should be.
func Describe(path, kind string, err error) error {
	switch {
	case errors.Is(err, ErrExist):
		return fmt.Errorf("%s exists; %s is never written over", path, kind)
	case errors.Is(err, ErrAuth):
		return fmt.Errorf("%s: %w", path, err)
	case errors.Is(err, ErrNotSealed):
		return fmt.Errorf("%s is not %s", path, kind)
	}
	return err
}

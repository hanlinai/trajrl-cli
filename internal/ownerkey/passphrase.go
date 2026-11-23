package ownerkey

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// ExpectedRTMR3 is the RTMR3 a running sandbox shows when the owner whose
// master secret this is unlocked it (proto.RTMR3OwnerUnlock) and its root is
// image (a digest, or proto.ImageBase): proto.RTMR3Running.
func ExpectedRTMR3(m *Master, sandboxID, image string) ([48]byte, error) {
	secret, err := m.DiskSecret(sandboxID)
	if err != nil {
		return [48]byte{}, err
	}
	defer clear(secret)
	v, err := proto.RTMR3OwnerUnlock(secret)
	if err != nil {
		return [48]byte{}, err
	}
	return proto.RTMR3Running(v, image), nil
}

// KeyFileIn is the key file in an owner's directory.
func KeyFileIn(dir string) string { return dir + string(os.PathSeparator) + "owner.key" }

// ReadPassphraseFile reads a passphrase from a file only its owner can read.
// A passphrase is never taken from the command line.
//
// On Windows the check is skipped: Go reports every file there as 0666 or
// 0444 (Unix modes do not describe its access lists), so the mode says
// nothing about who can read the file.
func ReadPassphraseFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %04o); a passphrase file must be 0600 or stricter", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(b), "\r\n")), nil
}

// AskSecret asks on the terminal without echo.
func AskSecret(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("there is no terminal to ask on: give -passphrase-file")
	}
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return p, err
}

// PassphraseFileEnv names the environment variable that names a
// passphrase file, for a program that runs trajrl without a terminal.
const PassphraseFileEnv = "TRAJRL_PASSPHRASE_FILE"

// ErrNeedsPassphrase: the owner key's passphrase was given neither way and
// there is no terminal to ask on (trajrl's exit status 3).
var ErrNeedsPassphrase = errors.New("the owner key needs its passphrase: give -passphrase-file or " + PassphraseFileEnv)

// Passphrase is the owner key's passphrase, from the first of: passFile
// (-passphrase-file), the file $TRAJRL_PASSPHRASE_FILE names, the terminal
// (asked with prompt, without echo). There is no passphrase agent. Without
// any of them it is ErrNeedsPassphrase: a standard input that is not a
// terminal is never read, so nothing waits on it.
func Passphrase(passFile, prompt string) ([]byte, error) {
	if passFile == "" {
		passFile = os.Getenv(PassphraseFileEnv)
	}
	if passFile != "" {
		return ReadPassphraseFile(passFile)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, ErrNeedsPassphrase
	}
	return AskSecret(prompt)
}

// OpenKeyFile opens the key file in dir with the passphrase from passFile,
// or from where Passphrase finds it.
func OpenKeyFile(dir, passFile string) (*Master, error) {
	path := KeyFileIn(dir)
	pass, err := Passphrase(passFile, "Passphrase of "+path+": ")
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	return LoadKeyFile(path, pass)
}

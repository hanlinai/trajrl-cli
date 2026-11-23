//go:build !rehearsal

package userverify

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// A normal build verifies a quote or nothing: a sandbox that gives none is
// not verified. Only a binary built with the tag "rehearsal" has another
// answer (rehearsal.go).
func noQuoteAllowed() bool { return false }

func noQuoteCheck(*ssh.Client, Target, *Report) (*Report, error) {
	return nil, errors.New("the sandbox gave no quote: it is not a TDX guest")
}

// Package clierr is how trajrl's own commands end (docs/cli.md, "For
// programs"): one exit status per kind of failure, and with --json the
// error as one JSON object on stderr, {"error": "...", "code": N}, for the
// Python SDK and other programs that drive trajrl.
package clierr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// The exit statuses of trajrl's own commands. A command forwarded to the
// platform keeps the platform's.
const (
	OK = 0
	// Failed: the command failed.
	Failed = 1
	// Usage: the command line is wrong.
	Usage = 2
	// NeedsOwner: the owner is needed: the owner key's passphrase was not
	// given and there is no terminal to ask on, or a sandbox waits for an
	// unlock (or a decision) that was not asked for.
	NeedsOwner = 3
	// Transport: the entry point (or the sandbox's API) was not reached, or
	// the connection was cut, as ssh's own 255.
	Transport = 255
)

type coded struct {
	code int
	err  error
}

func (c *coded) Error() string { return c.err.Error() }
func (c *coded) Unwrap() error { return c.err }

// With is err with the exit status code; nil stays nil.
func With(code int, err error) error {
	if err == nil {
		return nil
	}
	return &coded{code, err}
}

// Code is err's exit status: the one With gave it, NeedsOwner for
// ownerkey.ErrNeedsPassphrase, otherwise def.
func Code(err error, def int) int {
	var c *coded
	if errors.As(err, &c) {
		return c.code
	}
	if errors.Is(err, ownerkey.ErrNeedsPassphrase) {
		return NeedsOwner
	}
	return def
}

// Write says msg, an error, on w: "PROG: msg", or with asJSON the line
// {"error": msg, "code": code}.
func Write(w io.Writer, prog string, asJSON bool, code int, msg string) {
	if !asJSON {
		fmt.Fprintf(w, "%s: %s\n", prog, msg)
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}{strings.TrimSpace(msg), code})
}

// WantsJSON tells whether args, before a "--", hold --json (or -json,
// --json=true).
func WantsJSON(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if IsJSONFlag(a) {
			return true
		}
	}
	return false
}

// IsJSONFlag tells whether a is --json in one of the forms WantsJSON takes.
func IsJSONFlag(a string) bool {
	switch a {
	case "--json", "-json", "--json=true", "-json=true":
		return true
	}
	return false
}

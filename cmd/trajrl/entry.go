package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// dialEntry logs in to the configured entry point, its key pinned, with
// the configured SSH key or the SSH agent.
func dialEntry(c *config) (*ssh.Client, error) {
	if c.Entry == "" || c.EntryKey == "" {
		_, err := loadConfig()
		if err == nil {
			err = fmt.Errorf("%s names no entry point: run %s setup again", configPath(), prog)
		}
		return nil, err
	}
	if cred, _ := activeCredentials(); cred != nil {
		return userverify.DialEntry(c.Entry, c.EntryKey, nil)
	}
	file, locked := c.identityFile()
	if file == "" && !userverify.AgentHasKeys() {
		return nil, noKey(locked)
	}
	id, err := userverify.LoadIdentity(file)
	if err != nil {
		return nil, err
	}
	return userverify.DialEntry(c.Entry, c.EntryKey, id.Auth)
}

// forward runs one command at the entry point as the owner's ssh would
// without a terminal: the words joined by one space, stdin given to it,
// its stdout and stderr as they come. It returns the command's exit
// status, or 255 if it has none (the entry point not reached, the session
// cut).
func forward(c *config, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	client, err := dialEntry(c)
	if err != nil {
		clierr.Write(stderr, prog, jsonMode, clierr.Transport, err.Error())
		return clierr.Transport
	}
	defer client.Close()
	s, err := client.NewSession()
	if err != nil {
		clierr.Write(stderr, prog, jsonMode, clierr.Transport, err.Error())
		return clierr.Transport
	}
	defer s.Close()
	s.Stdin, s.Stdout, s.Stderr = stdin, stdout, stderr
	err = s.Run(strings.Join(args, " "))
	var exit *ssh.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitStatus()
	}
	clierr.Write(stderr, prog, jsonMode, clierr.Transport, "the entry point: "+err.Error())
	return clierr.Transport
}

// separators are the words a shell would have taken as the end of one
// command, typed on one line to trajrl as plain words.
var separators = map[string]bool{"/": true, ";": true, "&&": true, "|": true}

// freeText are the platform's commands that take free text, where a
// separator may be a word of it: "comment NAME TEXT...", "tag NAME TAG..."
// (a tag may be any word, "trajrl" or "new" too), "ssh-key add KEY ...
// COMMENT", "token new --label L".
var freeText = map[string]bool{"comment": true, "tag": true, "ssh-key": true, "token": true}

// severalCommands tells whether args, a command line for the entry point,
// is several commands typed on one line ("ls / trajrl whoami / trajrl
// doctor"), which the entry point would take as one. For a command that
// takes free text, only a separator followed by the word trajrl is; for
// any other, a lone separator is, and so is the word trajrl after the
// first followed by a command's name ("ls trajrl whoami": "show trajrl" or
// "rm trajrl --yes" name a sandbox called trajrl).
func severalCommands(args []string) bool {
	if len(args) == 0 {
		return false
	}
	free := freeText[args[0]]
	for i, a := range args {
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		switch {
		case separators[a] && (!free || next == prog):
			return true
		case !free && i > 0 && a == prog && isCommandWord(next):
			return true
		}
	}
	return false
}

// isCommandWord tells whether w is the first word of one of trajrl's own
// commands or of the platform's.
func isCommandWord(w string) bool {
	if w == "" {
		return false
	}
	if _, ok := handlers[w]; ok {
		return true
	}
	for _, g := range Platform {
		for _, c := range g.Commands {
			if first, _, _ := strings.Cut(c.Words, " "); first == w {
				return true
			}
		}
	}
	return false
}

// forwardCmd is a command of the entry point's, forwarded.
func forwardCmd(args []string) int {
	if len(args) == 0 {
		return fail(2, "usage: %s entry COMMAND [ARGS...]", prog)
	}
	c, err := loadConfig()
	if err != nil {
		return fail(255, "%v", err)
	}
	return forward(c, args, os.Stdin, os.Stdout, os.Stderr)
}

// entryOutput runs one command at the entry point with no input and
// returns what it printed; a status other than 0 is an error with what it
// said on stderr.
func entryOutput(c *config, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	code := forward(c, args, bytes.NewReader(nil), &out, &errb)
	if code != 0 {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = fmt.Sprintf("exit status %d", code)
		}
		return out.Bytes(), fmt.Errorf("%s: %s", args[0], msg)
	}
	return out.Bytes(), nil
}

// errNoAnswer: the entry point did not answer in time.
var errNoAnswer = errors.New("no answer in time")

// entryOutputWithin is entryOutput that gives up after limit with
// errNoAnswer. said is what the entry point printed on stderr, either way.
// A command given up on is left to the end of the process.
func entryOutputWithin(c *config, limit time.Duration, args ...string) (out []byte, said string, err error) {
	var errb lockedBuffer
	type result struct {
		out  []byte
		code int
	}
	done := make(chan result, 1)
	go func() {
		var o bytes.Buffer
		code := forward(c, args, bytes.NewReader(nil), &o, &errb)
		done <- result{o.Bytes(), code}
	}()
	select {
	case r := <-done:
		said = strings.TrimSpace(strings.ReplaceAll(errb.String(), "\r", ""))
		if r.code != 0 {
			msg := said
			if msg == "" {
				msg = fmt.Sprintf("exit status %d", r.code)
			}
			return r.out, said, fmt.Errorf("%s: %s", args[0], msg)
		}
		return r.out, said, nil
	case <-time.After(limit):
		return nil, strings.TrimSpace(strings.ReplaceAll(errb.String(), "\r", "")), errNoAnswer
	}
}

// lockedBuffer is a bytes.Buffer written and read from two goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

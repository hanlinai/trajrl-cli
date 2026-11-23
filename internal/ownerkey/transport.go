package ownerkey

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// The interface with the platform. The entry command `unlock NAME`, run by
// NAME's owner on the platform's SSH entry point, starts the sandbox if it is
// stopped, waits up to 10 minutes for its TD to connect, then writes exactly
// one line to the session's stdout:
//
//	tdx-sandbox-unlock/v1 <sandbox-id>\n
//
// and from then on splices the session's stdin and stdout to the TD's
// connection, byte for byte, in both directions. The TD is the TLS client;
// this side is the TLS server. On a failure before the splice the entry
// command writes a message to stderr and exits non-zero.
const (
	PreambleTag = "tdx-sandbox-unlock/v1"
	// PreambleWait is how long the tool waits for the preamble: the
	// platform's 10 minutes and a margin.
	PreambleWait = 11 * time.Minute
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ValidName reports whether name can be passed to the entry point as one
// word.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// ReadPreamble reads the platform's one line and returns the sandbox ID it
// names. Anything else first is an error.
func ReadPreamble(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if len(line) == 0 {
				return "", fmt.Errorf("the platform closed the session before handing over the TD's connection: %w", err)
			}
			return "", fmt.Errorf("the platform's first line was cut short: %w", err)
		}
		if b == '\n' {
			break
		}
		if len(line) >= 128 {
			return "", errors.New("the platform's first line is not the unlock preamble")
		}
		line = append(line, b)
	}
	f := strings.Split(string(line), " ")
	if len(f) != 2 || f[0] != PreambleTag || !proto.ValidSandboxID(f[1]) {
		return "", fmt.Errorf("the platform's first line is not the unlock preamble: %.80q", line)
	}
	return f[1], nil
}

// streamConn is a net.Conn over a reader and a writer (an SSH session's
// stdout and stdin). A deadline that passes closes the stream.
type streamConn struct {
	r       io.Reader
	w       io.Writer
	close   func() error
	once    sync.Once
	mu      sync.Mutex
	timer   *time.Timer
	expired atomic.Bool
}

type pipeAddr string

func (a pipeAddr) Network() string { return "relay" }
func (a pipeAddr) String() string  { return string(a) }

// NewStreamConn makes a net.Conn of r and w; close is called once, by Close
// or when a deadline passes.
func NewStreamConn(r io.Reader, w io.Writer, close func() error) net.Conn {
	return &streamConn{r: r, w: w, close: close}
}

func (c *streamConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil && c.expired.Load() {
		err = os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *streamConn) Write(p []byte) (int, error) {
	if c.expired.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	return c.w.Write(p)
}

func (c *streamConn) Close() error {
	var err error
	c.once.Do(func() {
		c.mu.Lock()
		if c.timer != nil {
			c.timer.Stop()
		}
		c.mu.Unlock()
		err = c.close()
	})
	return err
}

func (c *streamConn) LocalAddr() net.Addr  { return pipeAddr("owner") }
func (c *streamConn) RemoteAddr() net.Addr { return pipeAddr("td-via-platform") }

func (c *streamConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if t.IsZero() {
		return nil
	}
	c.timer = time.AfterFunc(time.Until(t), func() { c.expired.Store(true); c.Close() })
	return nil
}
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

// limitedBuffer keeps the first n bytes written to it.
type limitedBuffer struct {
	mu  sync.Mutex
	b   bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := l.max - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.TrimSpace(Printable(l.b.String()))
}

// Printable is s with every control character but newline and tab taken
// out (escape sequences included, C1 controls too): what the platform says
// is shown, never interpreted by the owner's terminal.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= ' ' && r != 0x7f && (r < 0x80 || r > 0x9f) && r != 0xfffd) {
			return r
		}
		return -1
	}, strings.ToValidUTF8(s, ""))
}

// OpenUnlock runs `unlock NAME` on the entry point and waits for the
// platform to hand over the TD's connection. It returns that connection and
// the sandbox ID the platform named.
func OpenUnlock(entry *ssh.Client, name string, wait time.Duration) (net.Conn, string, error) {
	if !ValidName(name) {
		return nil, "", fmt.Errorf("%q is not a sandbox name", name)
	}
	sess, err := entry.NewSession()
	if err != nil {
		return nil, "", err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, "", err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, "", err
	}
	stderr := &limitedBuffer{max: 4 << 10}
	sess.Stderr = stderr
	if err := sess.Start("unlock " + name); err != nil {
		sess.Close()
		return nil, "", fmt.Errorf("unlock %s: %w", name, err)
	}
	failed := func(err error) (net.Conn, string, error) {
		sess.Close()
		werr := sess.Wait()
		msg := stderr.String()
		if msg == "" && werr != nil {
			msg = werr.Error()
		}
		if msg != "" {
			return nil, "", fmt.Errorf("unlock %s: %v\n  the platform said: %s", name, err, msg)
		}
		return nil, "", fmt.Errorf("unlock %s: %w", name, err)
	}
	r := bufio.NewReader(stdout)
	timer := time.AfterFunc(wait, func() { sess.Close() })
	id, err := ReadPreamble(r)
	if !timer.Stop() {
		return failed(fmt.Errorf("no TD connection was handed over within %v", wait))
	}
	if err != nil {
		return failed(err)
	}
	return NewStreamConn(r, stdin, func() error {
		stdin.Close()
		return sess.Close()
	}), id, nil
}

// RunEntry runs one entry command and returns its output; a non-zero exit is
// an error carrying what it wrote to stderr.
func RunEntry(entry *ssh.Client, args []string) (string, error) {
	return RunEntryInput(entry, args, nil)
}

// RunEntryInput is RunEntry with input on the command's standard input
// (nil: none).
func RunEntryInput(entry *ssh.Client, args []string, input []byte) (string, error) {
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\r\n'\"\\`$;&|<>") {
			return "", fmt.Errorf("%q cannot be passed to the entry point as one word", a)
		}
	}
	sess, err := entry.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	errb := &limitedBuffer{max: 4 << 10}
	outb := &limitedBuffer{max: 64 << 10}
	sess.Stdout, sess.Stderr = outb, errb
	if input != nil {
		sess.Stdin = bytes.NewReader(input)
	}
	if err := sess.Run(strings.Join(args, " ")); err != nil {
		if msg := errb.String(); msg != "" {
			return outb.String(), fmt.Errorf("%s: %s", args[0], msg)
		}
		return outb.String(), fmt.Errorf("%s: %w", args[0], err)
	}
	return outb.String(), nil
}

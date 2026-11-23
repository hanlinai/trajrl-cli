// Package apicmd is sbxapi (cmd/sbxapi runs it as it is) and trajrl's exec
// and cp (MainWith, #123).
//
// sbxapi is the client of the HTTPS API inside a sandbox (cmd/sandbox-api,
// issue #106): run a command in it, or copy a file in or out, over mutual
// TLS that ends in the TD. See docs/api-in-sandbox.md.
//
//	sbxapi exec [flags] NAME -- COMMAND [ARG...]
//	sbxapi cp [flags] LOCAL NAME:/PATH
//	sbxapi cp [flags] NAME:/PATH LOCAL
//
// NAME is the sandbox's name as sbxverify recorded it, or its host name at
// the web router (NAME-ACCOUNT.DOMAIN). The server is accepted only with the
// SSH host key sbxverify recorded for it (~/.config/sbx/verified.json);
// without a record it refuses, unless the key is given with --pin. The
// client authenticates with your own SSH key (Ed25519, RSA of 2048 bits or
// more, ECDSA P-256 or P-384), which must be in
// root's authorized_keys in the sandbox.
package apicmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
)

// die ends sbxapi with exit status 255, as it always has; trajrl with 1
// (a local file, stdin), see fail.
func die(format string, a ...any) {
	fail(clierr.Failed, fmt.Errorf(format, a...))
}

// fail ends the command on err: sbxapi exits 255 on every error, as it
// always has; trajrl exits with err's status (clierr), def if it has none,
// and with --json says it as {"error": ..., "code": N}.
func fail(def int, err error) {
	code := clierr.Transport
	if trajrl() {
		code = clierr.Code(err, def)
	}
	clierr.Write(os.Stderr, prog, asJSON, code, err.Error())
	os.Exit(code)
}

// failed is fail for an error of the sandbox's API: 255 if the API was not
// reached (or the connection cut), 1 if it answered with a refusal; a
// sandbox that waits for its owner's key is 3 (Options.Explain).
func failed(name string, err error) {
	if isTransport(err) {
		if explain != nil {
			if e := explain(name); e != nil {
				fail(clierr.Failed, fmt.Errorf("%v (%w)", err, e))
			}
		}
		fail(clierr.Transport, err)
	}
	fail(clierr.Failed, err)
}

// isTransport tells an error of the connection from an answer.
func isTransport(err error) bool {
	var ue *url.Error
	return errors.As(err, &ue)
}

// trajrl tells whether this is trajrl's exec or cp, not sbxapi.
func trajrl() bool { return prog != "sbxapi" }

// asJSON: trajrl's --json was given.
var asJSON bool

// explain is this run's Options.Explain.
var explain func(name string) error

// prog is the program's name in its messages: sbxapi, or trajrl.
var prog = "sbxapi"

// Options is what trajrl gives sbxapi (#123). The zero value is sbxapi as
// it is.
type Options struct {
	// Prog is the program's name in its messages ("": sbxapi).
	Prog string
	// Fallback, if set, is asked for the pinned host key and the TLS
	// server name of a sandbox that sbxverify's record does not have (and
	// no -pin was given). An error is the refusal.
	Fallback func(name string) (pin, host string, err error)
	// Explain, if set, is asked why the sandbox name's API could not be
	// reached; an error with clierr.NeedsOwner (it waits for its owner's
	// key) makes the exit status 3. nil: no more is known.
	Explain func(name string) error
}

// fallback is this run's Options.Fallback.
var fallback func(name string) (pin, host string, err error)

const usage = `usage:
  sbxapi exec [flags] NAME -- COMMAND [ARG...]
  sbxapi cp [flags] LOCAL NAME:/PATH
  sbxapi cp [flags] NAME:/PATH LOCAL
flags:`

type env map[string]string

func (e env) String() string { return "" }
func (e env) Set(v string) error {
	k, val, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return errors.New("give NAME=VALUE")
	}
	e[k] = val
	return nil
}

// common is what every subcommand takes.
type common struct {
	key, pin, pins, connect, host string
}

func (c *common) flags(fs *flag.FlagSet) {
	keyHelp := "your SSH private key, Ed25519 (default: your SSH agent's Ed25519 key, else ~/.ssh/id_ed25519)"
	if prog != "sbxapi" {
		// sbxapi's own help stays as it was recorded (testdata/legacy);
		// the key types it takes are the same.
		keyHelp = "your SSH private key: Ed25519, RSA (2048 bits or more) or ECDSA (P-256, P-384) (default: your SSH agent's Ed25519 key, else ~/.ssh/id_ed25519, id_ecdsa, id_rsa)"
	}
	fs.StringVar(&c.key, "i", "", keyHelp)
	fs.StringVar(&c.pin, "pin", "", "the sandbox's SSH host key, 'ssh-ed25519 AAAA...' (default: the one sbxverify recorded)")
	fs.StringVar(&c.pins, "pins", sbxapi.DefaultPinFile(), "sbxverify's record of the sandboxes it verified")
	fs.StringVar(&c.connect, "connect", "", "where to connect, host:port (default: the sandbox's host name, port 443: the web router)")
	fs.StringVar(&c.host, "host", "", "the TLS server name, NAME-ACCOUNT.DOMAIN (default: from sbxverify's record, or NAME if it has a dot)")
}

// client resolves NAME to a server name, an address and a pinned key.
func (c *common) client(name string) (*sbxapi.Client, error) {
	cl := &sbxapi.Client{ServerName: c.host}
	var rec *sbxapi.Pin
	if ps, err := sbxapi.LoadPins(c.pins); err == nil {
		if p, err := ps.Lookup(name); err == nil {
			rec = &p
		} else if c.pin == "" && fallback != nil {
			pin, host, err := fallback(name)
			if err != nil {
				return nil, err
			}
			rec = &sbxapi.Pin{HostKey: pin}
			if cl.ServerName == "" {
				cl.ServerName = host
			}
		} else if c.pin == "" {
			return nil, err
		}
	} else if c.pin == "" {
		return nil, err
	}
	pinLine := c.pin
	if pinLine == "" {
		pinLine = rec.HostKey
	}
	k, err := sbxapi.ParsePin(pinLine)
	if err != nil {
		return nil, err
	}
	cl.Pin = k
	if cl.ServerName == "" && rec != nil {
		cl.ServerName = rec.Host()
	}
	if cl.ServerName == "" && strings.Contains(name, ".") {
		cl.ServerName = name
	}
	if cl.ServerName == "" {
		return nil, fmt.Errorf("no host name for %s: give NAME-ACCOUNT.DOMAIN or -host", name)
	}
	cl.Addr = c.connect
	if cl.Addr == "" {
		cl.Addr = cl.ServerName + ":443"
	}
	if cl.Key, err = sbxapi.LoadKey(c.key); err != nil {
		return nil, err
	}
	return cl, nil
}

// parse reads flags wherever they are before "--", and returns the other
// arguments and those after "--". A flag set that exits on an error never
// returns one; with --json (ContinueOnError) it is said as JSON, status 2.
func parse(fs *flag.FlagSet, args []string) (pos, tail []string) {
	for {
		// The flag package would take "--" as its own end of flags.
		if len(args) > 0 && args[0] == "--" {
			return pos, args[1:]
		}
		if err := fs.Parse(args); err != nil {
			fail(clierr.Usage, err)
		}
		if n := len(args) - len(fs.Args()); n > 0 && args[n-1] == "--" {
			return pos, fs.Args()
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// newFlags is a subcommand's flag set: one that exits on an error, as
// sbxapi's, but with trajrl's --json one that returns it (parse).
func newFlags(name string) *flag.FlagSet {
	if asJSON {
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		return fs
	}
	return flag.NewFlagSet(name, flag.ExitOnError)
}

// jsonFlag adds trajrl's -json to fs (sbxapi has none).
func jsonFlag(fs *flag.FlagSet, help string) {
	if trajrl() {
		fs.BoolVar(&asJSON, "json", asJSON, help)
	}
}

// usageError ends the command on a wrong command line, status 2.
func usageError(text string) {
	if asJSON {
		clierr.Write(os.Stderr, prog, true, clierr.Usage, text)
	} else {
		fmt.Fprintln(os.Stderr, text)
	}
	os.Exit(clierr.Usage)
}

// Main is sbxapi, its command line os.Args.
func Main() { MainWith(os.Args[1:], Options{}) }

// MainWith runs sbxapi's command args (without the program's name) with
// opt. Like sbxapi it exits with the command's status.
func MainWith(args []string, opt Options) {
	if opt.Prog != "" {
		prog = opt.Prog
	}
	fallback = opt.Fallback
	explain = opt.Explain
	asJSON = trajrl() && clierr.WantsJSON(args)
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch args[0] {
	case "exec":
		os.Exit(execCmd(ctx, args[1:]))
	case "cp":
		cpCmd(ctx, args[1:])
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

func execCmd(ctx context.Context, args []string) int {
	fs := newFlags("exec")
	var c common
	c.flags(fs)
	e := env{}
	fs.Var(e, "e", "an environment variable NAME=VALUE (repeat)")
	if trajrl() {
		fs.Var(e, "env", "an environment variable NAME=VALUE (repeat); the same as -e")
	}
	cwd := fs.String("cwd", "", "working directory (default /root)")
	timeout := fs.Int("timeout", 60, fmt.Sprintf("seconds the command may run, at most %d", sbxapi.MaxTimeout))
	stdin := fs.Bool("stdin", false, "send this program's standard input to the command (read whole, before it starts)")
	jsonFlag(fs, "print the command's output as NDJSON on stdout, the in-sandbox API's own lines: {\"stdout\": BASE64}, {\"stderr\": BASE64}, last {\"exit_code\": N}")
	pos, cmd := parse(fs, args)
	if len(pos) != 1 || len(cmd) == 0 {
		usageError("usage: " + prog + " exec [flags] NAME -- COMMAND [ARG...]")
	}
	cl, err := c.client(pos[0])
	if err != nil {
		fail(clierr.Failed, err)
	}
	req := sbxapi.Exec{Argv: cmd, Cwd: *cwd, Env: e, TimeoutS: *timeout}
	if *stdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			die("stdin: %v", err)
		}
		req.StdinB64 = sbxapi.B64(b)
	}
	if asJSON {
		return execJSON(ctx, cl, pos[0], req)
	}
	code, err := cl.Run(ctx, req, os.Stdout, os.Stderr)
	if err != nil {
		if code < 0 && trajrl() {
			failed(pos[0], err)
		}
		fmt.Fprintln(os.Stderr, prog+":", err)
		if code < 0 {
			return 255
		}
	}
	return code
}

// execJSON is trajrl exec --json: the in-sandbox API's NDJSON lines on
// stdout as it sends them (sbxapi.Line: stdout and stderr base64, as Go
// encodes bytes in JSON), its error line if it sent one, and last
// {"exit_code": N}. The exit status is the command's.
func execJSON(ctx context.Context, cl *sbxapi.Client, name string, req sbxapi.Exec) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	code, err := cl.Run(ctx, req, lineWriter{enc, false}, lineWriter{enc, true})
	if code < 0 {
		if err == nil {
			err = sbxapi.ErrNoExit
		}
		failed(name, err)
	}
	if err != nil {
		// The server's error line (a command killed at its time limit).
		enc.Encode(sbxapi.Line{Error: err.Error()})
	}
	enc.Encode(sbxapi.Line{ExitCode: &code})
	return code
}

// lineWriter writes each write as one line {"stdout": BASE64} (or
// "stderr"): the line the in-sandbox API sent, as it sent it.
type lineWriter struct {
	enc    *json.Encoder
	stderr bool
}

func (w lineWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	l := sbxapi.Line{Stdout: p}
	if w.stderr {
		l = sbxapi.Line{Stderr: p}
	}
	return len(p), w.enc.Encode(l)
}

// cpResult is what trajrl cp --json prints.
type cpResult struct {
	// Direction is "in" (into the sandbox) or "out".
	Direction string `json:"direction"`
	// Path is the path in the sandbox.
	Path string `json:"path"`
	// Bytes is how many bytes were copied.
	Bytes int64 `json:"bytes"`
}

func printCp(r cpResult) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.Encode(r)
	}
}

func cpCmd(ctx context.Context, args []string) {
	fs := newFlags("cp")
	var c common
	c.flags(fs)
	mode := fs.String("mode", "", "the file's mode in the sandbox, octal (default: the local file's)")
	jsonFlag(fs, "print {\"direction\": \"in\"|\"out\", \"path\": PATH, \"bytes\": N} on stdout")
	pos, _ := parse(fs, args)
	if len(pos) != 2 {
		usageError("usage: " + prog + " cp [flags] LOCAL NAME:/PATH | NAME:/PATH LOCAL")
	}
	if asJSON && pos[1] == "-" {
		usageError("usage: " + prog + " cp --json NAME:/PATH LOCAL: with --json, stdout is the result, not the file")
	}
	remote := func(s string) (string, string, bool) {
		n, p, ok := strings.Cut(s, ":")
		return n, p, ok && strings.HasPrefix(p, "/")
	}
	if name, path, ok := remote(pos[1]); ok {
		f, err := os.Open(pos[0])
		if err != nil {
			die("%v", err)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			die("%v", err)
		}
		m := st.Mode().Perm()
		if *mode != "" {
			v, err := strconv.ParseUint(*mode, 8, 32)
			if err != nil {
				die("-mode %q is not octal", *mode)
			}
			m = os.FileMode(v)
		}
		cl, err := c.client(name)
		if err != nil {
			fail(clierr.Failed, err)
		}
		t0 := time.Now()
		res, err := cl.Put(ctx, path, m, f, st.Size())
		if err != nil {
			failed(name, err)
		}
		fmt.Fprintf(os.Stderr, "%s -> %s:%s, %d bytes in %s, sha256 %s\n", pos[0], name, res.Path, res.Size, time.Since(t0).Round(time.Millisecond), res.SHA256)
		printCp(cpResult{Direction: "in", Path: res.Path, Bytes: res.Size})
		return
	}
	name, path, ok := remote(pos[0])
	if !ok {
		if trajrl() {
			usageError(prog + ": one of the two must be NAME:/PATH")
		}
		die("one of the two must be NAME:/PATH")
	}
	cl, err := c.client(name)
	if err != nil {
		fail(clierr.Failed, err)
	}
	out := os.Stdout
	if pos[1] != "-" {
		tmp, err := os.CreateTemp(dirOf(pos[1]), ".sbxapi-*")
		if err != nil {
			die("%v", err)
		}
		defer os.Remove(tmp.Name())
		out = tmp
	}
	n, err := cl.Get(ctx, path, out)
	if err != nil {
		failed(name, err)
	}
	if out != os.Stdout {
		if err := out.Close(); err != nil {
			die("%v", err)
		}
		if err := os.Rename(out.Name(), pos[1]); err != nil {
			die("%v", err)
		}
		fmt.Fprintf(os.Stderr, "%s:%s -> %s, %d bytes\n", name, path, pos[1], n)
	}
	printCp(cpResult{Direction: "out", Path: path, Bytes: n})
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		if i == 0 {
			return "/"
		}
		return p[:i]
	}
	return "."
}

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
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, prog+": "+format+"\n", a...)
	os.Exit(255)
}

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
// arguments and those after "--".
func parse(fs *flag.FlagSet, args []string) (pos, tail []string) {
	for {
		// The flag package would take "--" as its own end of flags.
		if len(args) > 0 && args[0] == "--" {
			return pos, args[1:]
		}
		fs.Parse(args)
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

// Main is sbxapi, its command line os.Args.
func Main() { MainWith(os.Args[1:], Options{}) }

// MainWith runs sbxapi's command args (without the program's name) with
// opt. Like sbxapi it exits with the command's status.
func MainWith(args []string, opt Options) {
	if opt.Prog != "" {
		prog = opt.Prog
	}
	fallback = opt.Fallback
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
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	var c common
	c.flags(fs)
	e := env{}
	fs.Var(e, "e", "an environment variable NAME=VALUE (repeat)")
	cwd := fs.String("cwd", "", "working directory (default /root)")
	timeout := fs.Int("timeout", 60, fmt.Sprintf("seconds the command may run, at most %d", sbxapi.MaxTimeout))
	stdin := fs.Bool("stdin", false, "send this program's standard input to the command (read whole, before it starts)")
	pos, cmd := parse(fs, args)
	if len(pos) != 1 || len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "usage: "+prog+" exec [flags] NAME -- COMMAND [ARG...]")
		os.Exit(2)
	}
	cl, err := c.client(pos[0])
	if err != nil {
		die("%v", err)
	}
	req := sbxapi.Exec{Argv: cmd, Cwd: *cwd, Env: e, TimeoutS: *timeout}
	if *stdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			die("stdin: %v", err)
		}
		req.StdinB64 = sbxapi.B64(b)
	}
	code, err := cl.Run(ctx, req, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, prog+":", err)
		if code < 0 {
			return 255
		}
	}
	return code
}

func cpCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("cp", flag.ExitOnError)
	var c common
	c.flags(fs)
	mode := fs.String("mode", "", "the file's mode in the sandbox, octal (default: the local file's)")
	pos, _ := parse(fs, args)
	if len(pos) != 2 {
		fmt.Fprintln(os.Stderr, "usage: "+prog+" cp [flags] LOCAL NAME:/PATH | NAME:/PATH LOCAL")
		os.Exit(2)
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
			die("%v", err)
		}
		t0 := time.Now()
		res, err := cl.Put(ctx, path, m, f, st.Size())
		if err != nil {
			die("%v", err)
		}
		fmt.Fprintf(os.Stderr, "%s -> %s:%s, %d bytes in %s, sha256 %s\n", pos[0], name, res.Path, res.Size, time.Since(t0).Round(time.Millisecond), res.SHA256)
		return
	}
	name, path, ok := remote(pos[0])
	if !ok {
		die("one of the two must be NAME:/PATH")
	}
	cl, err := c.client(name)
	if err != nil {
		die("%v", err)
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
		die("%v", err)
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

// Package verifycmd is sbxverify (cmd/sbxverify runs it as it is) and
// trajrl's verify (MainWith, #123).
//
// sbxverify is for a sandbox's owner: it checks, from the owner's own
// machine and without relying on anything the service says, that a running
// sandbox is a genuine Intel TDX guest on a platform Intel rates current,
// that it booted the image the owner expects, and that the SSH session ends
// inside it. See internal/userverify.
//
//	sbxverify -entry HOST:2222 -entry-key 'ssh-ed25519 AAAA...' -name web -policy image.json
//	sbxverify -addr HOST:22001 -id sbx-0123456789abcdef -policy image.json
//	sbxverify ... -owner-key ~/.config/sbxkey    (a sandbox whose disk key you hold)
//	sbxverify ... -json                           (one JSON object on stdout: verdict, reason,
//	                                              sandbox_id, checked_at, quote)
//
// With -owner-key (the directory of sbxkey's key file) the sandbox must also
// have been unlocked with your key: its RTMR3 must be the value only a TD
// given your disk secret for it shows. A TD the host booted with this
// sandbox's ID and unlocked itself is refused.
//
// The image (#112): the sandbox names the image its root is made of (the
// digest of its owner's image, or "base"), and RTMR3 must also show that
// image, which makes the answer authentic. With -owner-key it is then
// compared with your record (sandboxes.json in the same directory): the
// digest you created the sandbox with, or base. A record without one (from
// before #112) records the digest at this first check, printed, and later
// checks must match it. A mismatch is a refusal that names both.
//
// There is no flag that relaxes or skips a check. A binary built with the Go
// build tag "rehearsal" (rehearsal.go) has -dev-insecure-rehearsal, for the
// emulated rehearsal only, where the guests are not TDs: it compares the
// image with the record without any quote, and never says VERIFIED. A
// normal build has neither the flag nor the code behind it.
//
// The policy file holds the measurements the owner expects (the format the
// broker uses). Its worth is its origin: computed from a build of the
// published source (tests/mrtd-from-firmware.py, tests/rtmr-from-artifacts.py)
// it makes the check independent of the service; copied from the service it
// only shows that the sandbox is what the service says it is.
package verifycmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/proto"
	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

type paths []string

func (p *paths) String() string     { return strings.Join(*p, ",") }
func (p *paths) Set(v string) error { *p = append(*p, v); return nil }

// die ends the check on err: exit status 1, as sbxverify's; under trajrl
// the owner key's passphrase not given without a terminal is 3, and with
// --json the error is said as {"error": ..., "code": N}.
func die(err error) {
	code := clierr.Failed
	if prog != "sbxverify" {
		code = clierr.Code(err, clierr.Failed)
	}
	clierr.Write(os.Stderr, prog, jsonErrors, code, err.Error())
	os.Exit(code)
}

// jsonErrors: trajrl verify --json, whose errors are JSON too.
var jsonErrors bool

// prog is the program's name in its messages: sbxverify, or trajrl.
var prog = "sbxverify"

// Options is what trajrl gives sbxverify (#123). The zero value is
// sbxverify as it is.
type Options struct {
	// Prog is the program's name in its messages ("": sbxverify).
	Prog string
	// Entry, EntryKey, Identity and Policies are the values of -entry,
	// -entry-key, -i and -policy (each one) where they were not given. They
	// are set on the parsed flags, never added to the command line.
	Entry, EntryKey, Identity string
	Policies                  []string
	// NoPolicy, if set, is the error without any policy.
	NoPolicy string
	// ArgsAfterName takes "NAME [flags]": the one word that is not a flag
	// is -name, and flags may come after it.
	ArgsAfterName bool
	// OwnerDir, if set, adds -owner: -owner-key OwnerDir.
	OwnerDir string
}

// checks prints the verifier's account of the quote, one check a line.
func checks(w io.Writer, list []attest.Check, after string) {
	if len(list) == 0 {
		return
	}
	// The list is made by a second look at the same quote. If it does not
	// tell the verdict's story (a refusal with every check holding, or the
	// reverse: collateral fetched at two moments, or a fault in how the
	// policies were given), it explains nothing and is not shown.
	failed := 0
	for _, c := range list {
		if !c.OK {
			failed++
		}
	}
	if refused := after != ""; refused != (failed > 0) {
		fmt.Fprintln(w, "\n(No check-by-check account: a second look at the quote did not agree with the verdict. The verdict stands.)")
		return
	}
	fmt.Fprintln(w, "\nCheck by check:")
	for _, c := range list {
		mark, sep := "ok  ", "   "
		if !c.OK {
			mark, sep = "FAIL", " : "
		}
		fmt.Fprintf(w, "  [%s] %s", mark, c.What)
		if c.Detail != "" {
			fmt.Fprintf(w, "%s%s", sep, c.Detail)
		}
		fmt.Fprintln(w)
	}
	if after != "" {
		fmt.Fprintln(w, after)
	}
}

// Verdict is what -json prints: one object, on success and on refusal
// alike. Quote is the verifier's result as it is (null if the check did not
// get as far as a quote). host/probe.sh hands it to sbxctl host-admit (#58).
type Verdict struct {
	Verdict   string         `json:"verdict"` // VERIFIED or NOT VERIFIED
	Reason    string         `json:"reason,omitempty"`
	SandboxID string         `json:"sandbox_id"`
	CheckedAt time.Time      `json:"checked_at"`
	Quote     *attest.Result `json:"quote"`
	// UnlockedByOwner: with -owner-key, RTMR3 showed the owner's key.
	UnlockedByOwner bool `json:"unlocked_by_owner,omitempty"`
	// Image is the image the sandbox named for its root, a digest or
	// "base" (#112); with VERIFIED, RTMR3 vouches for it.
	Image string `json:"image,omitempty"`
}

// rehearsalFlags is set only in a binary built with the tag "rehearsal"
// (rehearsal.go): it adds its flag to fs and returns what to do once parsed.
var rehearsalFlags func(fs *flag.FlagSet) (parsed func())

// rehearsalRecord is set only in a binary built with the tag "rehearsal"
// (rehearsal.go): it records the host key a check without a quote saw,
// apart from record's verified keys.
var rehearsalRecord func(out io.Writer, record, name, sandboxID, hostKey string)

// imageNote is the report's line about the image check against the
// owner's record (ownerkey.State.CheckImage).
func imageNote(name string, c ownerkey.ImageCheck, image string) string {
	what := "the base image"
	if image != proto.ImageBase {
		what = image
	}
	switch {
	case c.NoRecord:
		return fmt.Sprintf("runs %s; your record has no sandbox %s, so it was compared with nothing", what, name)
	case c.FirstUse:
		return fmt.Sprintf("runs %s; your record had no digest for it (%s), so this one is now recorded (trust on first use): later checks must find the same", what, orBase(c.Image))
	case c.Image != "":
		return fmt.Sprintf("runs %s, the image you created it with (%s)", what, c.Image)
	}
	return fmt.Sprintf("runs %s, as your record says", what)
}

func orBase(ref string) string {
	if ref == "" {
		return "created on the base image"
	}
	return ref
}

// verdictOf is the -json object for a check's outcome. id is the sandbox
// asked for, used when the report does not name one.
func verdictOf(rep *userverify.Report, err error, id string, at time.Time) Verdict {
	v := Verdict{Verdict: "VERIFIED", SandboxID: id, CheckedAt: at.UTC()}
	if err != nil {
		v.Verdict, v.Reason = "NOT VERIFIED", err.Error()
	}
	if rep != nil {
		if rep.SandboxID != "" {
			v.SandboxID = rep.SandboxID
		}
		v.Quote = rep.Quote
		v.UnlockedByOwner = err == nil && rep.UnlockedByOwner
		v.Image = rep.Image
		if rep.Rehearsal && err == nil {
			v.Verdict, v.Reason = "NOT VERIFIED", "rehearsal: the sandbox is not a TD and gave no quote; only the image it names was compared with your record"
		}
	}
	return v
}

// Main is sbxverify, its command line os.Args.
func Main() { MainWith(os.Args[1:], Options{}) }

// MainWith runs sbxverify with the arguments args (without the program's
// name) and opt. Like sbxverify it exits on an error.
func MainWith(args []string, opt Options) {
	if opt.Prog != "" {
		prog = opt.Prog
	}
	jsonErrors = prog != "sbxverify" && clierr.WantsJSON(args)
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var t userverify.Target
	var policies paths
	fs.StringVar(&t.Entry, "entry", "", "the service's SSH entry point, host:port")
	fs.StringVar(&t.EntryKey, "entry-key", "", "the entry point's SSH host key as the service publishes it, e.g. 'ssh-ed25519 AAAA...'")
	fs.StringVar(&t.Name, "name", "", "the sandbox's name (with -entry)")
	fs.StringVar(&t.Addr, "addr", "", "the sandbox's own SSH address, host:port (instead of -entry and -name)")
	fs.StringVar(&t.ID, "id", "", "the sandbox's ID (with -addr)")
	keyFile := fs.String("i", "", "your SSH private key file (default: your SSH agent)")
	fs.Var(&policies, "policy", "the measurements you expect (JSON); several may be given, one must match in full")
	timeout := fs.Duration("timeout", 2*time.Minute, "give up after this long")
	ownerDir := fs.String("owner-key", "", "the directory of your sbxkey key file: the sandbox must have been unlocked with your key")
	var owner *bool
	if opt.OwnerDir != "" {
		owner = fs.Bool("owner", false, "the sandbox must have been unlocked with your key (the key file in "+opt.OwnerDir+"): -owner-key "+opt.OwnerDir)
	}
	passFile := fs.String("passphrase-file", "", "with -owner-key: a file only you can read holding the key file's passphrase (default: asked on the terminal)")
	record := fs.String("record", sbxapi.DefaultPinFile(), "after VERIFIED, record the host key the TD vouched for here, for sbxapi to pin (\"\" records nothing)")
	asJSON := fs.Bool("json", false, "print the verdict and the verified quote's facts as one JSON object on stdout (the account for people goes to stderr); the exit status is the same")
	var parsed func()
	if rehearsalFlags != nil {
		parsed = rehearsalFlags(fs)
	}
	if opt.ArgsAfterName {
		var pos []string
		for rest := args; ; {
			fs.Parse(rest)
			if rest = fs.Args(); len(rest) == 0 {
				break
			}
			pos, rest = append(pos, rest[0]), rest[1:]
		}
		switch {
		case len(pos) > 1:
			fmt.Fprintf(os.Stderr, "%s: one sandbox at a time: %s\n", prog, strings.Join(pos, " "))
			os.Exit(2)
		case len(pos) == 1 && t.Name != "":
			fmt.Fprintf(os.Stderr, "%s: NAME and -name both given\n", prog)
			os.Exit(2)
		case len(pos) == 1:
			t.Name = pos[0]
		}
	} else {
		fs.Parse(args)
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	// The defaults of opt, for an entry point and a sandbox's name; with
	// -addr there is no entry point to default to.
	if !given["addr"] && !given["id"] {
		for name, v := range map[string]string{"entry": opt.Entry, "entry-key": opt.EntryKey} {
			if !given[name] && v != "" {
				fs.Set(name, v)
			}
		}
	}
	if !given["i"] && opt.Identity != "" {
		fs.Set("i", opt.Identity)
	}
	if !given["policy"] {
		for _, p := range opt.Policies {
			fs.Set("policy", p)
		}
	}
	if owner != nil && *owner && *ownerDir == "" {
		*ownerDir = opt.OwnerDir
	}
	if parsed != nil {
		parsed()
	}
	if len(policies) == 0 {
		if opt.NoPolicy != "" {
			die(errors.New(opt.NoPolicy))
		}
		die(errors.New("-policy is required: without the measurements you expect there is nothing to compare the sandbox with"))
	}
	// The production verifier and nothing else: Intel's root of trust,
	// Intel's collateral fetched now, every TCB level required UpToDate.
	// There is no flag for an exception.
	v := &attest.TDX{}
	for i, f := range policies {
		p, err := attest.LoadPolicy(f)
		if err != nil {
			die(err)
		}
		if i == 0 {
			v.Policy = p
		} else {
			v.Also = append(v.Also, p)
		}
	}
	id, err := userverify.LoadIdentity(*keyFile)
	if err != nil {
		die(err)
	}
	t.Auth = id.Auth
	if *ownerDir != "" {
		m, err := ownerkey.OpenKeyFile(*ownerDir, *passFile)
		if err != nil {
			die(err)
		}
		defer m.Wipe()
		t.OwnerRTMR3 = func(sandboxID, image string) ([48]byte, error) { return ownerkey.ExpectedRTMR3(m, sandboxID, image) }
		st, err := ownerkey.OpenState(filepath.Join(*ownerDir, "sandboxes.json"), filepath.Join(*ownerDir, "known_hosts"))
		if err != nil {
			die(err)
		}
		t.OwnerImage = func(sandboxID, image string) (string, error) {
			name := t.Name
			if r := st.Get(sandboxID); r != nil {
				name = r.Name
			}
			c, err := st.CheckImage(sandboxID, image)
			if err != nil {
				return "", err
			}
			return imageNote(name, c, image), nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rep, err := userverify.Check(ctx, t, v)
	// With -json the one object goes to stdout, and the account for people
	// to stderr.
	out := io.Writer(os.Stdout)
	if *asJSON {
		out = os.Stderr
		json.NewEncoder(os.Stdout).Encode(verdictOf(rep, err, t.ID, time.Now()))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "NOT VERIFIED:", err)
		if rep != nil && rep.Quote != nil && rep.Quote.PlatformTCB != "" {
			fmt.Fprintf(os.Stderr, "  Intel's rating: platform %s, TDX module %s, quoting enclave %s\n", rep.Quote.PlatformTCB, rep.Quote.ModuleTCBStatus, rep.Quote.QETCBStatus)
		}
		if rep != nil {
			checks(os.Stderr, rep.Checks, "The verdict above stands: one check that does not hold is enough, and there is no option to overlook one.")
		}
		if jsonErrors {
			clierr.Write(os.Stderr, prog, true, clierr.Failed, "NOT VERIFIED: "+err.Error())
		}
		os.Exit(1)
	}
	if rep.Rehearsal {
		// Only a binary built with the tag "rehearsal" gets here.
		fmt.Fprintf(out, "REHEARSAL, NOT VERIFIED: %s is not a TD and gave no quote; nothing about it is attested.\n", rep.SandboxID)
		if rep.ImageNote != "" {
			fmt.Fprintf(out, "  image (not attested) %s\n", rep.ImageNote)
		}
		if rehearsalRecord != nil && *record != "" && t.Name != "" && rep.HostKey != "" {
			rehearsalRecord(out, *record, t.Name, rep.SandboxID, rep.HostKey)
		}
		return
	}
	q := rep.Quote
	fmt.Fprintf(out, `VERIFIED: %s is a genuine Intel TDX guest running the image you expect.

  quote            signed by an Intel quoting enclave; certificate chain and revocation checked against Intel
  platform         %s (TDX module %s, quoting enclave %s), as Intel rates it now
  image            measurements match your policy %q
                   MRTD  %s
                   RTMR1 %s
  boot             completed the measured boot stage; not a debug TD
  identity         launched for sandbox %s
  fresh            the quote carries the nonce chosen here a moment ago (%s...)
  this session     the quote carries the SSH host key this session was authenticated with:
                   %s
`, rep.SandboxID, q.PlatformTCB, q.ModuleTCBStatus, q.QETCBStatus, q.Policy, q.MRTD, q.RTMRs[1], rep.SandboxID, rep.Nonce[:16], rep.HostKey)
	if rep.UnlockedByOwner {
		fmt.Fprintln(out, "  your key         RTMR3 commits to the disk secret your key gives this sandbox: you unlocked it, nobody else")
	}
	if rep.Image == proto.ImageBase {
		fmt.Fprintln(out, "  root             the platform's base image, no image of the owner's: RTMR3 shows it")
	} else {
		fmt.Fprintf(out, "  root             the owner's image %s over the base image: RTMR3 shows it\n", rep.Image)
	}
	if rep.ImageNote != "" {
		fmt.Fprintf(out, "  your image       %s\n", rep.ImageNote)
	}
	if rep.ToldHostKey != "" && strings.TrimSpace(rep.ToldHostKey) != rep.HostKey {
		fmt.Fprintf(out, "\n  note: the service lists another host key for this sandbox (%s). The one above is the one the TD vouches for.\n", strings.TrimSpace(rep.ToldHostKey))
	}
	checks(out, rep.Checks, "")
	// The API inside the sandbox (sbxapi, #106) is pinned by this key.
	if *record != "" {
		pin := sbxapi.Pin{Name: t.Name, ID: rep.SandboxID, HostKey: rep.HostKey, HTTPSURL: rep.ToldURL, Entry: t.Entry, Verified: time.Now().UTC()}
		if err := sbxapi.RecordPin(*record, pin); err != nil {
			fmt.Fprintf(os.Stderr, "\n%s: the host key could not be recorded in %s: %v\n", prog, *record, err)
		} else {
			fmt.Fprintf(out, "\n  recorded         this host key in %s: sbxapi accepts the sandbox's API only with it\n", *record)
		}
	}
	if rep.UnlockedByOwner {
		fmt.Fprint(out, `
What this does not tell you: whether the image is one you should trust (that
depends on where your policy file came from).
`)
		return
	}
	fmt.Fprint(out, `
What this does not tell you: who else could obtain this sandbox's disk key (that
depends on where the service keeps its key broker), and whether the image is one
you should trust (that depends on where your policy file came from).
`)
}

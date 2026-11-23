// Package keycmd is sbxkey, the sandbox owner's key tool (cmd/sbxkey runs
// it as it is), and the commands of trajrl that need the owner's key
// (MainWith, #123).
//
// sbxkey is the sandbox owner's key tool. The owner, not the platform, holds
// every disk key of their sandboxes: one master secret, in a key file sealed
// under a passphrase on the owner's machine and on paper as a recovery
// phrase. At every boot a sandbox's TD waits; sbxkey, run by the owner, is
// handed the TD's connection by the platform, checks the TD's quote (Intel's
// signature chain, every TCB level UpToDate, the owner's launch policy, this
// sandbox, this session) and only then sends the disk secret. See
// internal/ownerkey.
//
//	sbxkey init                      make the master secret; shows the recovery phrase once
//	sbxkey restore                   rebuild the key file from the recovery phrase
//	sbxkey backup-check              check your written recovery phrase against the key file
//	sbxkey start  [flags] NAME       unlock NAME's boot (the platform starts it if stopped)
//	sbxkey unlock [flags] NAME       the same
//	sbxkey new    [flags] NAME [entry flags...]
//	                                 create NAME at the platform, then unlock its first boot
//	                                 (-prompt TEXT: with a coding agent started on a task, prompt.go)
//	sbxkey rename OLD NEW            follow a rename at the platform (ssh ENTRY rename OLD NEW)
//	sbxkey known-hosts [NAME]        write your sandboxes' SSH host keys for your ssh (sshpin.go)
//	sbxkey keys add|remove|list|sync change the keys your sandboxes accept, signed by you (keys.go)
//	sbxkey recovery-key init         a key that may only sign those changes, kept offline
//
// There is no flag that relaxes or skips any check of the quote, and no
// unattested mode. The one exception is not in this program as built and
// shipped: a binary built with the Go build tag "rehearsal" (rehearsal.go)
// has -dev-insecure-rehearsal, for the emulated rehearsal only, where the
// guests are not TDs. A normal build has neither the flag nor the code
// behind it (TestBuildTagDefaultHasNoRehearsal).
package keycmd

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/proto"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

const usage = `usage:
  sbxkey init         [-dir DIR] [-passphrase-file FILE]
  sbxkey restore      [-dir DIR] [-passphrase-file FILE]
  sbxkey backup-check [-dir DIR] [-passphrase-file FILE]
  sbxkey start        [flags] NAME
  sbxkey unlock       [flags] NAME
  sbxkey new          [flags] NAME [flags for the entry point's new command...]
  sbxkey rename       [-dir DIR] OLD NEW   after "rename OLD NEW" at the platform: your record follows
  sbxkey known-hosts  [-dir DIR] [-domain D] [-ssh-known-hosts PATH] [-entry HOST:PORT -entry-key KEY [-i KEYFILE]] [NAME]
                                           write the SSH host keys on your record where your ssh reads them,
                                           without an unlock (for sandboxes made before sbxkey did this itself)
  sbxkey keys list|add|remove|sync ...     your signed statement of SSH keys, which your sandboxes follow
  sbxkey recovery-key init                 a recovery key, shown once, kept offline ("sbxkey keys" for more)

flags of start, unlock and new:
  -entry HOST:PORT -entry-key 'ssh-ed25519 AAAA...'   the platform's SSH entry point, its key pinned
  -policy FILE (repeatable)                            the launch policies you accept (required)
  -i KEYFILE                                           your SSH key (default: your SSH agent)
  -authorized-keys FILE                                keys for root in a new sandbox (default: the key used for the entry)
  -setup-script FILE                                   run once after the first boot
  -image REGISTRY/REPO@sha256:...                      the sandbox's own image, by digest (new: also --image after NAME);
                                                       its TD pulls and checks it at the first boot, over the base image
  -registry-auth FILE                                  USER:PASSWORD for the image's registry, sent to the TD only
  -env KEY=VALUE (repeatable)                          an environment variable for login shells and services,
                                                       set at the first boot (a prelude to the setup script)
  -accept-older N                                      accept an older disk at exactly boot N (a snapshot you restored)
  -accept-newer N                                      accept a newer disk at exactly boot N (started from another machine of yours)
  -first-boot                                          (start, unlock) accept a first boot: a blank disk is formatted
  -accept-recovered                                    (start, unlock) unlock a copy recovered after its host failed
                                                       without asking (the platform's notice is shown first)
  -prompt TEXT | -prompt-file FILE                     (new) start a coding agent on this task at the first boot; its
                                                       key is asked for (not shown), or read as one line from a pipe
  -agent claude|codex|pi -agent-provider P -no-agent-key
                                                       (new, with -prompt) the agent (default claude), pi's provider
                                                       (default anthropic), or no key (add one later)
  -known-host NAME (repeatable)                        host names to pin the SSH host key for (default: NAME
                                                       and NAME.DOMAIN)
  -domain D                                            (also rename) the platform's domain for sandbox names
                                                       (default: asked of the entry point, and remembered)
  -ssh-known-hosts PATH | none                         (also rename) the file your ssh reads your sandboxes' host
                                                       keys from, written after every unlock (default:
                                                       ~/.ssh/sbx_known_hosts, for sbxkey's own directory); none: no file
  -dir DIR -passphrase-file FILE
`

// rehearsalUsage and rehearsalFlags are set only in a binary built with the
// tag "rehearsal" (rehearsal.go). rehearsalFlags adds its flags to a boot
// command's flag set and returns what to do once they are parsed.
var (
	rehearsalUsage string
	rehearsalFlags func(fs *flag.FlagSet) (parsed func())
)

// die ends the command on err: exit status 1, or under trajrl the status
// clierr gives err (3: the owner is needed, 255: the entry point was not
// reached), with --json the error as one JSON object on stderr.
func die(err error) {
	code := clierr.Code(err, clierr.Failed)
	if ownerkey.Tool == "sbxkey" {
		code = clierr.Failed
	}
	clierr.Write(os.Stderr, ownerkey.Tool, asJSON, code, err.Error())
	os.Exit(code)
}

// usageExit ends the command on a wrong command line: text, the usage, on
// stderr, or with --json {"error": "usage: ...", "code": 2}.
func usageExit(text string) {
	if asJSON {
		clierr.Write(os.Stderr, ownerkey.Tool, true, clierr.Usage, text)
	} else {
		fmt.Fprint(os.Stderr, text)
	}
	os.Exit(clierr.Usage)
}

// asJSON: --json was given to new, start or unlock (trajrl only): the
// result is one JSON object on jsonOut (the real stdout), everything for
// people goes to stderr, and an error is {"error": ..., "code": N}.
var (
	asJSON  bool
	jsonOut = os.Stdout
)

// Options is what trajrl gives sbxkey's commands (#123). The zero value is
// sbxkey as it is; the commands it prints name ownerkey.Tool.
type Options struct {
	// Entry, EntryKey, Identity, Domain and Policies are the values of
	// -entry, -entry-key, -i, -domain and -policy (each one) for a command
	// that has the flag and was not given it. They are set on the parsed
	// flags, never added to the command line: a command without -entry is
	// never given one.
	Entry, EntryKey, Identity, Domain string
	Policies                          []string
	// NoPolicy, if set, is the error of start, unlock and new without any
	// policy (one that says how to add one).
	NoPolicy string
	// ArgsAfterName lets start and unlock take their flags after NAME too.
	ArgsAfterName bool
	// JSON: --json is among the arguments (trajrl's new, start, unlock).
	JSON bool
}

// options are this run's.
var options Options

// given is the flags the person gave (before the defaults of options).
var given = map[string]bool{}

// applyDefaults sets the flags of fs that the command has and the person
// did not give to the values of options; skip names flags that keep their
// own default. It records what was given.
func applyDefaults(fs *flag.FlagSet, skip ...string) {
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	set := func(name string, values ...string) {
		if given[name] || fs.Lookup(name) == nil || slices.Contains(skip, name) {
			return
		}
		for _, v := range values {
			if v != "" {
				if err := fs.Set(name, v); err != nil {
					die(fmt.Errorf("-%s %s: %w", name, v, err))
				}
			}
		}
	}
	set("entry", options.Entry)
	set("entry-key", options.EntryKey)
	set("i", options.Identity)
	set("domain", options.Domain)
	set("policy", options.Policies...)
}

// renderUsage is a usage text with its commands under ownerkey.Tool.
func renderUsage(s string) string {
	if ownerkey.Tool == "sbxkey" {
		return s
	}
	old := "sbxkey"
	var pairs []string
	for _, c := range []string{"init", "restore", "backup-check"} {
		pairs = append(pairs, old+" "+c, ownerkey.Command(c))
	}
	return strings.NewReplacer(append(pairs, old+" ", ownerkey.Tool+" ")...).Replace(s)
}

type paths []string

func (p *paths) String() string     { return strings.Join(*p, ",") }
func (p *paths) Set(v string) error { *p = append(*p, v); return nil }

type opts struct {
	dir, passFile                     string
	entry, entryKey, keyFile          string
	policies, knownHosts, env         paths
	authorizedKeys, setupScript       string
	image, registryAuth               string
	acceptOlder, acceptNewer          uint64
	firstBoot, acceptRecovered        bool
	prompt                            promptOpts
	wait                              time.Duration
	keyPath, statePath, knownHostPath string
	pin                               sshPin
	// json: -json was given (trajrl's new, start, unlock).
	json bool
}

// DefaultDir is sbxkey's own directory: $SBXKEY_DIR, or sbxkey in the
// user's configuration directory.
func DefaultDir() string { return defaultDir() }

func defaultDir() string {
	if d := os.Getenv("SBXKEY_DIR"); d != "" {
		return d
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "sbxkey")
	}
	return ".sbxkey"
}

// Main is sbxkey, its command line os.Args.
func Main() { MainWith(os.Args[1:], Options{}) }

// MainWith runs sbxkey's command args (without the program's name) with
// opt. Like sbxkey it exits on an error.
func MainWith(args []string, opt Options) {
	options = opt
	usage := renderUsage(usage + rehearsalUsage)
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := args[0]
	boot := cmd == "start" || cmd == "unlock" || cmd == "new"
	// --json is trajrl's, for new, start and unlock (sbxkey has none).
	jsonFlag := boot && ownerkey.Tool != "sbxkey"
	if jsonFlag && opt.JSON {
		asJSON = true
		// Whatever is printed for people goes to stderr; stdout carries
		// the one object.
		jsonOut, os.Stdout = os.Stdout, os.Stderr
		defer func() { os.Stdout = jsonOut }()
	}
	if cmd == "keys" || cmd == "recovery-key" { // keys.go (#65)
		if err := keysMain(args); err != nil {
			die(err)
		}
		return
	}
	var o opts
	fs := flag.NewFlagSet(ownerkey.Command(cmd), flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if asJSON {
		// A wrong flag is said as JSON too (parseFailed), and only that.
		fs.Init(ownerkey.Command(cmd), flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.Usage = func() {}
	}
	var parsed func()
	fs.StringVar(&o.dir, "dir", defaultDir(), "where the key file, the state and known_hosts are")
	fs.StringVar(&o.passFile, "passphrase-file", "", "a file only you can read holding the key file's passphrase (default: asked on the terminal)")
	if jsonFlag {
		fs.BoolVar(&o.json, "json", false, "print the result as one JSON object on stdout (the account for people goes to stderr)")
	}
	if boot {
		fs.StringVar(&o.entry, "entry", "", "the platform's SSH entry point, host:port")
		fs.StringVar(&o.entryKey, "entry-key", "", "the entry point's SSH host key as the platform publishes it")
		fs.StringVar(&o.keyFile, "i", "", "your SSH private key file (default: your SSH agent)")
		fs.Var(&o.policies, "policy", "a launch policy you accept (JSON); several may be given, one must match in full")
		fs.StringVar(&o.authorizedKeys, "authorized-keys", "", "authorized_keys for root at the first boot (default: the key used for the entry point)")
		fs.StringVar(&o.setupScript, "setup-script", "", "a script run once after the first boot")
		fs.StringVar(&o.image, "image", "", "the sandbox's own image, REGISTRY/REPO@sha256:... (by digest; pulled and checked by the TD at its first boot)")
		fs.StringVar(&o.registryAuth, "registry-auth", "", "a file holding USER:PASSWORD for the image's registry (sent to the TD with the first boot only)")
		fs.Var(&o.env, "env", "KEY=VALUE, set at the first boot for login shells (/etc/environment) and services (systemd DefaultEnvironment); repeatable")
		fs.Uint64Var(&o.acceptOlder, "accept-older", 0, "accept an older disk at exactly this boot epoch (a snapshot you restored on purpose; a refused start names the number)")
		fs.Uint64Var(&o.acceptNewer, "accept-newer", 0, "accept a newer disk at exactly this boot epoch (started from another machine of yours; a refused start names the number)")
		if cmd != "new" {
			fs.BoolVar(&o.firstBoot, "first-boot", false, "accept a first boot (a blank disk formatted) for a sandbox that has never booted")
			fs.BoolVar(&o.acceptRecovered, "accept-recovered", false, "unlock a copy recovered after its host failed without asking (its notice is shown)")
		}
		// Taken by start and unlock too, to be refused there by name.
		fs.StringVar(&o.prompt.text, "prompt", "", "(new) a task for a coding agent, started at the first boot")
		fs.StringVar(&o.prompt.file, "prompt-file", "", "(new) the task from a file")
		fs.StringVar(&o.prompt.agent, "agent", "", "(new, with -prompt) claude, codex or pi (default claude)")
		fs.StringVar(&o.prompt.provider, "agent-provider", "", "(new, with -prompt, -agent pi) the provider of pi's key (default anthropic)")
		fs.BoolVar(&o.prompt.noKey, "no-agent-key", false, "(new, with -prompt) put no key in the sandbox; add one later")
		fs.Var(&o.knownHosts, "known-host", "a host name to pin the SSH host key for (default: the sandbox's name)")
		fs.DurationVar(&o.wait, "wait", ownerkey.PreambleWait, "how long to wait for the platform to hand over the TD's connection")
		if rehearsalFlags != nil {
			parsed = rehearsalFlags(fs)
		}
	}
	sshPinFlags(fs, &o, cmd)
	var pos []string
	if opt.ArgsAfterName && (cmd == "start" || cmd == "unlock") {
		var err error
		pos, err = parseInterleaved(fs, args[1:]) // exits on an error, but with --json
		parseFailed(err)
	} else {
		parseFailed(fs.Parse(args[1:]))
		pos = fs.Args()
	}
	applyDefaults(fs)
	if parsed != nil {
		parsed()
	}
	if err := o.pin.resolve(o.dir); err != nil {
		die(err)
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "prompt":
			o.prompt.textSet = true
		case "agent", "agent-provider", "no-agent-key":
			o.prompt.agentSet = true
		}
	})
	o.keyPath = filepath.Join(o.dir, "owner.key")
	o.statePath = filepath.Join(o.dir, "sandboxes.json")
	o.knownHostPath = filepath.Join(o.dir, "known_hosts")
	var err error
	switch cmd {
	case "init":
		err = initKey(&o)
	case "restore":
		err = restore(&o)
	case "backup-check":
		err = backupCheck(&o)
	case "start", "unlock", "new":
		if len(pos) < 1 || (cmd != "new" && len(pos) != 1) {
			usageExit(usage)
		}
		err = unlock(&o, cmd == "new", pos[0], pos[1:])
	case "rename":
		if len(pos) != 2 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		err = rename(&o, pos[0], pos[1])
	case "known-hosts":
		err = knownHosts(&o, pos)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		die(err)
	}
}

// parseFailed ends the command on a flag the flag set refused: only with
// --json does the flag set return the error (ContinueOnError) rather than
// exit, and it is said as JSON, with exit status 2.
func parseFailed(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, flag.ErrHelp) {
		usageExit(renderUsage(usage + rehearsalUsage))
	}
	die(clierr.With(clierr.Usage, err))
}

// --- passphrases and the terminal -------------------------------------------

var stdin = bufio.NewReader(os.Stdin)

func isTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func readLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	s, err := stdin.ReadString('\n')
	if err != nil && (err != io.EOF || s == "") {
		return "", errors.New("no answer")
	}
	return strings.TrimSpace(s), nil
}

func askSecret(prompt string) ([]byte, error) { return ownerkey.AskSecret(prompt) }

func passphrase(o *opts, isNew bool) ([]byte, error) {
	var p []byte
	var err error
	switch {
	case o.passFile != "":
		p, err = ownerkey.ReadPassphraseFile(o.passFile)
	case !isNew:
		// -passphrase-file, $TRAJRL_PASSPHRASE_FILE, the terminal; never a
		// wait on a stdin that is not one (ErrNeedsPassphrase).
		p, err = ownerkey.Passphrase("", "Passphrase of "+o.keyPath+": ")
	default:
		if p, err = askSecret(fmt.Sprintf("New passphrase for the key file (at least %d characters): ", ownerkey.MinPassphrase)); err != nil {
			return nil, err
		}
		again, err := askSecret("The same passphrase again: ")
		if err != nil {
			return nil, err
		}
		if string(again) != string(p) {
			return nil, errors.New("the two passphrases differ")
		}
	}
	if err != nil {
		return nil, err
	}
	if isNew && len(p) < ownerkey.MinPassphrase {
		return nil, fmt.Errorf("the passphrase has %d characters; at least %d are required", len(p), ownerkey.MinPassphrase)
	}
	return p, nil
}

func loadMaster(o *opts) (*ownerkey.Master, error) {
	pass, err := passphrase(o, false)
	if err != nil {
		return nil, err
	}
	return ownerkey.LoadKeyFile(o.keyPath, pass)
}

func randIndex(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}

// --- init, restore, backup-check -------------------------------------------

func initKey(o *opts) error {
	if _, err := os.Stat(o.keyPath); err == nil {
		return fmt.Errorf("%s exists; a key file is never written over (to start from your recovery phrase: %s into another -dir)", o.keyPath, ownerkey.Command("restore"))
	}
	// The phrase is shown on a terminal only, never into a file or a pipe.
	if !term.IsTerminal(int(os.Stdout.Fd())) || !isTerminal() {
		return errors.New("init shows your recovery phrase once and asks you to type part of it back: run it on a terminal")
	}
	if err := os.MkdirAll(o.dir, 0o700); err != nil {
		return err
	}
	pass, err := passphrase(o, true)
	if err != nil {
		return err
	}
	m, err := ownerkey.NewMaster()
	if err != nil {
		return err
	}
	defer m.Wipe()
	groups := ownerkey.PhraseGroupsOf(m.Phrase())
	fmt.Printf(`
YOUR RECOVERY PHRASE. Write it down, on paper, now.

Every disk of every sandbox of yours is locked by the secret below. Nobody
else has it: not the platform, not its operator. If you lose both this phrase
and your key file (or its passphrase), every sandbox's data is gone for good.

    %s
    %s

It is shown once. (Letters I, L read as 1, O as 0; case does not matter.)
`, strings.Join(groups[:7], "-"), strings.Join(groups[7:], "-"))
	for attempt := 0; ; attempt++ {
		if attempt == 3 {
			return errors.New("the groups typed back do not match; nothing was written. Run " + ownerkey.Command("init") + " again (it makes a new secret)")
		}
		picks := map[int]bool{}
		for len(picks) < 3 {
			picks[randIndex(len(groups))] = true
		}
		ok := true
		for i := range len(groups) {
			if !picks[i] {
				continue
			}
			a, err := readLine(fmt.Sprintf("Type group %d of your phrase (4 characters): ", i+1))
			if err != nil {
				return err
			}
			if ownerkey.NormaliseGroup(a) != groups[i] {
				ok = false
			}
		}
		if ok {
			break
		}
		fmt.Fprintln(os.Stderr, "That does not match what was shown. Check what you wrote down.")
	}
	if err := m.WriteKeyFile(o.keyPath, pass); err != nil {
		return err
	}
	fmt.Printf("\nKey file written: %s (sealed under your passphrase, mode 0600).\n"+
		"Keep a copy of it too. Check your written phrase any time with: %s\n", o.keyPath, ownerkey.Command("backup-check"))
	return nil
}

func askPhrase() (*ownerkey.Master, error) {
	s, err := readLine("Your recovery phrase (14 groups of 4): ")
	if err != nil {
		return nil, err
	}
	return ownerkey.ParsePhrase(s)
}

func restore(o *opts) error {
	if _, err := os.Stat(o.keyPath); err == nil {
		return fmt.Errorf("%s exists; a key file is never written over", o.keyPath)
	}
	if err := os.MkdirAll(o.dir, 0o700); err != nil {
		return err
	}
	m, err := askPhrase()
	if err != nil {
		return err
	}
	defer m.Wipe()
	pass, err := passphrase(o, true)
	if err != nil {
		return err
	}
	if err := m.WriteKeyFile(o.keyPath, pass); err != nil {
		return err
	}
	fmt.Printf("Key file rebuilt: %s. The records of your sandboxes are not in the phrase: the next start of each\n"+
		"accepts its disk as it is (trust on first use) and knows no SSH host key for it.\n", o.keyPath)
	return nil
}

func backupCheck(o *opts) error {
	m, err := loadMaster(o)
	if err != nil {
		return err
	}
	defer m.Wipe()
	written, err := askPhrase()
	if err != nil {
		return fmt.Errorf("%w; check what you wrote down against your key file again", err)
	}
	defer written.Wipe()
	if !written.Equal(m) {
		return errors.New("that is a valid recovery phrase, but not the one of this key file")
	}
	if st, err := ownerkey.OpenState(o.statePath, o.knownHostPath); err == nil {
		st.MarkBackupChecked()
	}
	fmt.Println("Your written recovery phrase restores this key file.")
	return nil
}

// --- rename -------------------------------------------------------------------

// rename follows a rename at the platform (#72). The unlock refuses a
// sandbox whose name there is not its record's, so after "rename OLD NEW"
// the record is renamed here too. Only the name changes: the sandbox's ID,
// from which its disk secret is derived, its boot epoch and its pinned SSH
// host key stay. No key is needed: the record is not secret.
func rename(o *opts, old, name string) error {
	for _, n := range []string{old, name} {
		if !ownerkey.ValidName(n) {
			return fmt.Errorf("%q is not a sandbox name", n)
		}
	}
	st, err := ownerkey.OpenState(o.statePath, o.knownHostPath)
	if err != nil {
		return err
	}
	r, err := st.Rename(old, name)
	if err != nil {
		return err
	}
	fmt.Printf("%s (%s) is %s in your record now. Its boot epoch (%d), its key and its pinned SSH host key are unchanged.\n", old, r.ID, name, r.Epoch)
	if r.SSHHostKey == "" {
		return nil
	}
	domain := sandboxDomain(o, st, nil)
	line, err := st.PinSandbox(old, name, domain, r.SSHHostKey)
	if err != nil {
		return fmt.Errorf("the record is renamed; its SSH host key could not be pinned for %s: %w", name, err)
	}
	fmt.Printf("  SSH host key pinned for %s in %s (the line for %s is gone):\n    %s\n  Lines you pinned with -known-host for other names are as they were.\n", name, o.knownHostPath, old, line)
	writeSSHMirror(o, st, domain)
	return nil
}

// --- start, unlock, new -------------------------------------------------------

func unlock(o *opts, isNew bool, name string, entryArgs []string) error {
	if !ownerkey.ValidName(name) {
		return fmt.Errorf("%q is not a sandbox name", name)
	}
	if isNew && ownerkey.Tool != "sbxkey" {
		// --json after NAME is trajrl's, never the platform's new.
		entryArgs = slices.DeleteFunc(slices.Clone(entryArgs), clierr.IsJSONFlag)
	}
	if err := o.prompt.check(isNew, o.setupScript); err != nil {
		return err
	}
	// Checked before -prompt asks for a key.
	if len(o.policies) == 0 {
		if options.NoPolicy != "" {
			return errors.New(options.NoPolicy)
		}
		return errors.New("-policy is required: without the measurements you expect there is nothing to check the TD against")
	}
	if o.entry == "" {
		return errors.New("-entry and -entry-key are required")
	}
	var script string
	if o.prompt.given() {
		// Built in memory, the key read here: it is in no local file (prompt.go).
		s, err := buildPrompt(&o.prompt, stdin, isTerminal(), os.Stderr)
		if err != nil {
			return err
		}
		script = s
	} else if o.setupScript != "" {
		b, err := os.ReadFile(o.setupScript)
		if err != nil {
			return err
		}
		script = string(b)
	}
	// -env pairs become a prelude to the script (env.go); the limit counts both.
	setup, err := setupWithEnv(o.env, script, proto.MaxSetupScript)
	if err != nil {
		return err
	}
	// --image REF among the entry point's arguments is the sandbox's own
	// image (image.go), never sent to the platform.
	if isNew {
		ref, rest, err := imageFromEntryArgs(entryArgs)
		if err != nil {
			return err
		}
		if ref != "" && o.image != "" {
			return errors.New("-image and --image both given")
		}
		if ref != "" {
			o.image, entryArgs = ref, rest
		}
	}
	registryAuth, err := checkImage(o.image, o.registryAuth)
	if err != nil {
		return err
	}
	// The production verifier and nothing else: Intel's root of trust,
	// Intel's collateral fetched now, every TCB level required UpToDate.
	v := &attest.TDX{}
	for i, f := range o.policies {
		p, err := attest.LoadPolicy(f)
		if err != nil {
			return err
		}
		if i == 0 {
			v.Policy = p
		} else {
			v.Also = append(v.Also, p)
		}
	}
	var authorized string
	if o.authorizedKeys != "" {
		b, err := os.ReadFile(o.authorizedKeys)
		if err != nil {
			return err
		}
		for rest := b; len(strings.TrimSpace(string(rest))) > 0; {
			if _, _, _, rest, err = ssh.ParseAuthorizedKey(rest); err != nil {
				return fmt.Errorf("%s: %w", o.authorizedKeys, err)
			}
		}
		authorized = string(b)
	}
	id, err := userverify.LoadIdentity(o.keyFile)
	if err != nil {
		return err
	}
	// Which agent key logs in is the server's choice; it would become root's
	// key in the new sandbox. With more than one, the owner says which.
	if isNew && authorized == "" && id.AgentKeys() > 1 {
		return fmt.Errorf("your SSH agent holds %d keys, and the platform would choose which of them becomes root's key in %s: give -authorized-keys FILE, or -i KEYFILE", id.AgentKeys(), name)
	}
	st, err := ownerkey.OpenState(o.statePath, o.knownHostPath)
	if err != nil {
		return err
	}
	m, err := loadMaster(o)
	if err != nil {
		return err
	}
	defer m.Wipe()
	if st.BackupChecked().IsZero() {
		fmt.Fprintln(os.Stderr, "note: your recovery phrase has never been checked against this key file ("+ownerkey.Command("backup-check")+"). Without it, a lost key file is lost data.")
	}

	entry, err := userverify.DialEntry(o.entry, o.entryKey, id.Auth)
	if err != nil {
		return clierr.With(clierr.Transport, err)
	}
	defer entry.Close()
	domain := sandboxDomain(o, st, func() (string, error) { return ownerkey.RunEntry(entry, []string{"domain"}) })
	if authorized == "" {
		k := id.Used()
		if k == nil {
			return errors.New("could not tell which SSH key logged in to the entry point: give -authorized-keys")
		}
		authorized = string(ssh.MarshalAuthorizedKey(k))
	}
	if isNew || o.firstBoot {
		fmt.Fprintf(os.Stderr, "root's authorized_keys in %s at its first boot:\n%s", name, ownerkey.Printable(authorized))
		if o.image != "" {
			fmt.Fprintf(os.Stderr, "its image, pulled and checked by its TD at the first boot: %s\n", o.image)
		}
	}
	if isNew {
		out, err := ownerkey.RunEntry(entry, append([]string{"new", name}, entryArgs...))
		if out != "" {
			fmt.Fprintln(os.Stderr, out) // filtered: no escape sequences
		}
		if err != nil {
			return err
		}
	}
	// A recovered copy's notice is read and confirmed first (recovered.go).
	rc := recoveredCheck{accept: o.acceptRecovered, tty: isTerminal(), ask: readLine, errw: os.Stderr}
	conn, sbID, view, err := openUnlock(entry, name, isNew, rc, o.wait)
	if err != nil {
		return err
	}
	// Its web names (webnames.go), at every unlock.
	names, dropped := webNames(name, view)
	sayWebNames(os.Stderr, name, names, dropped)
	// The account's signed statement of keys (#65, keys.go), at every
	// unlock: the TD applies it if a key it trusts signed it.
	statement := unlockStatement(entry, o.dir, name, os.Stderr)
	u := &ownerkey.Unlock{Verifier: v, Master: m, State: st, Name: name, SandboxID: sbID, New: isNew, FirstBoot: o.firstBoot,
		AuthorizedKeys: authorized, SetupScript: setup, Image: o.image, RegistryAuth: registryAuth, AcceptOlder: o.acceptOlder, AcceptNewer: o.acceptNewer, KnownHosts: o.pinHosts(name, domain),
		WebNames: names, KeyStatement: statement}
	res, err := u.Serve(conn)
	if err == nil {
		syncSSHPins(o, st, name, domain)
	}
	report(name, res, err, o)
	if err == nil && res.Mode == proto.ModeTDX {
		// The quote at unlock is taken before the TD commits RTMR3 to the
		// secret and to its image (#112); the running sandbox's quote
		// shows both.
		fmt.Printf("  to check that the running sandbox is the TD you unlocked, running the image you asked for:\n    %s\n", verifyLine(o, name))
	}
	if err == nil && asJSON {
		var state *string
		if v, serr := showSandbox(entry, name); serr == nil && v.State != "" {
			state = &v.State
		}
		hostKey := res.HostKey
		if r := st.ByName(name); r != nil && r.SSHHostKey != "" {
			hostKey = r.SSHHostKey
		}
		writeBootJSON(jsonOut, bootResultOf(name, state, res, hostKey))
	}
	return err
}

// verifyLine is the command that checks the running sandbox name with the
// owner's key: sbxverify with every flag, or under trajrl "trajrl verify
// NAME -owner" with the flags this run was given (what came from trajrl's
// configuration, trajrl verify takes from there too).
func verifyLine(o *opts, name string) string {
	if ownerkey.Tool == "sbxkey" {
		return fmt.Sprintf("%s -entry %s -entry-key '%s' -name %s -owner-key %s %s",
			"sbx"+"verify", o.entry, o.entryKey, name, o.dir, "-policy "+strings.Join(o.policies, " -policy "))
	}
	line := ownerkey.Tool + " verify " + name
	if filepath.Clean(o.dir) == filepath.Clean(defaultDir()) {
		line += " -owner"
	} else {
		line += " -owner-key " + o.dir
	}
	if given["entry"] || given["entry-key"] {
		line += fmt.Sprintf(" -entry %s -entry-key '%s'", o.entry, o.entryKey)
	}
	if given["i"] && o.keyFile != "" {
		line += " -i " + o.keyFile
	}
	if given["policy"] {
		line += " -policy " + strings.Join(o.policies, " -policy ")
	}
	return line
}

func report(name string, res *ownerkey.Outcome, err error, o *opts) {
	if res == nil {
		return
	}
	if q := res.Quote; q != nil && q.PlatformTCB != "" {
		if err != nil && !res.Released {
			fmt.Fprintf(os.Stderr, "  Intel's rating: platform %s, TDX module %s, quoting enclave %s\n", q.PlatformTCB, q.ModuleTCBStatus, q.QETCBStatus)
		}
	}
	if res.Released && res.Mode != proto.ModeTDX {
		// Only a binary built with the tag "rehearsal" gets here.
		fmt.Printf("%s (%s): NO QUOTE, NOT VERIFIED: the disk secret was sent WITHOUT ATTESTATION (evidence mode %s).\n", name, res.SandboxID, res.Mode)
	} else if res.Released {
		q := res.Quote
		fmt.Printf("%s (%s): quote VERIFIED and the disk secret sent.\n", name, res.SandboxID)
		if q != nil {
			fmt.Printf("  platform %s (TDX module %s, quoting enclave %s); policy %q\n  MRTD  %s\n", q.PlatformTCB, q.ModuleTCBStatus, q.QETCBStatus, q.Policy, q.MRTD)
		}
	}
	for _, n := range res.Notes {
		fmt.Println("  note:", n)
	}
	if err != nil {
		return
	}
	if res.FirstBoot {
		fmt.Printf(`  first boot: the disk was formatted, boot epoch 1.
  SSH host key reported by the TD, pinned in %s:
    %s
%s`, o.knownHostPath, res.KnownHostsLine, sshHint(o, name))
		fmt.Println(imageRecorded(name, o.image))
		return
	}
	fmt.Printf("  unlocked: boot epoch %d confirmed.\n", res.Epoch)
}

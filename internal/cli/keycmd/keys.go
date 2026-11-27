package keycmd

// Owner-signed key changes (#65): sbxkey keys and sbxkey recovery-key.
//
//	sbxkey keys list                       the account's statement of keys
//	sbxkey keys add PUBKEY|FILE [-sandbox NAME]
//	sbxkey keys remove PUBKEY|FILE|SHA256:FP [-sandbox NAME]
//	                                       fetch the statement from the
//	                                       platform, change it, sign it with
//	                                       your key (-i, or your SSH agent's;
//	                                       -sign-with FILE: the recovery key)
//	                                       and store it there
//	sbxkey keys sync NAME                  feed the statement to NAME now, over
//	                                       your own SSH (sandbox-keys apply)
//	sbxkey recovery-key init               make a recovery key: its private half
//	                                       is shown once, its public half goes
//	                                       into a new statement
//
// A statement (internal/keystmt) lists the account's login keys, keys for
// one sandbox only (a colleague's), and the recovery key, which may only
// sign the next statement. The platform stores and relays it and cannot
// make one: each sandbox applies a statement only if a key of the last one
// it applied signed it. sbxkey sends the platform's copy with every unlock;
// "keys sync" feeds it to a running sandbox. sbxkey keeps the newest
// statement it has seen in DIR/key-statement and sends that instead of an
// older one the platform might offer.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/hanlinai/trajrl-cli/internal/keystmt"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/sshsig"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

const keysUsage = `usage:
  sbxkey keys list   [entry flags] [-json]
  sbxkey keys add    [entry flags] [-sign-with FILE] PUBKEY|FILE [-sandbox NAME]
  sbxkey keys remove [entry flags] [-sign-with FILE] PUBKEY|FILE|SHA256:FP [-sandbox NAME]
  sbxkey keys sync   [entry flags] [-ssh 'COMMAND'] [-domain D] NAME
  sbxkey recovery-key init [entry flags] [-sign-with FILE] [-replace]

entry flags: -entry HOST:PORT -entry-key 'ssh-ed25519 AAAA...' [-i KEYFILE] [-dir DIR]

  add, remove  change your signed statement of keys: your login keys (they open the
               entry point and every sandbox of yours), or with -sandbox NAME the keys
               of that sandbox only (a colleague's). Signed with your key (-i, or the
               one of your SSH agent that logged in), or with -sign-with FILE (your
               recovery key, when every login key is lost). Your sandboxes apply it at
               their next unlock, or now with: sbxkey keys sync NAME
  sync         feeds the statement to NAME over your own SSH (default: ssh root@NAME.DOMAIN;
               -ssh gives the command, which is run with "sandbox-keys apply" after it)
  recovery-key init
               makes a recovery key: shown ONCE, to be kept offline. It never logs in;
               it signs a statement that gives you a new key after a lost laptop
`

// statementCache is where the newest statement sbxkey has seen is kept.
func statementCache(dir string) string { return filepath.Join(dir, "key-statement") }

// keysEnv is what the keys commands work with.
type keysEnv struct {
	dir      string
	entry    *ssh.Client
	id       *userverify.Identity
	keyFile  string // -i
	signWith string // -sign-with
	out      io.Writer
	errw     io.Writer
	// signer, when set, signs (tests); otherwise signerFor finds one.
	signer ssh.Signer
	// readSecret asks for a key file's passphrase.
	readSecret func(prompt string) ([]byte, error)
	// keepRemoved (-keep-removed) keeps in the next statement the login
	// keys the platform no longer lists (removed on the website).
	keepRemoved bool
}

// current is the account's statement as the platform has it, or sbxkey's
// own newer one; signed is "" when the account has none yet, and then the
// statement holds the account's keys at the platform with seq 0: the keys
// the platform takes the first statement's signature from.
type current struct {
	account string
	st      *keystmt.Statement
	signed  string
	// platform are the account's login keys as the platform lists them
	// now: the stored statement's, less any removed on the website since.
	platform []string
}

// base is what the next statement starts from: a copy of the current one.
// Before the first, nothing: the platform's list of the account's keys is
// not carried into a statement unseen, since whatever key is in a signed
// statement opens every sandbox. put adds the key that signs.
//
// A login key of the current statement that the platform no longer lists
// was removed on the website (#118 D1): it is left out of the next one,
// or it would come back as a login at this change. dropped are those keys;
// keep (-keep-removed) carries them over all the same.
func (c *current) base(keep bool) (next keystmt.Statement, dropped []string) {
	if c.signed == "" {
		return keystmt.Statement{Account: c.account}, nil
	}
	n := *c.st
	n.Keys = nil
	listed := map[string]bool{}
	for _, l := range c.platform {
		listed[fpOf(l)] = true
	}
	for _, l := range c.st.Keys {
		if !listed[fpOf(l)] {
			dropped = append(dropped, l)
			if !keep {
				continue
			}
		}
		n.Keys = append(n.Keys, l)
	}
	n.Sandboxes = append([]keystmt.SandboxKey(nil), c.st.Sandboxes...)
	return n, dropped
}

// base is cur.base with the owner told which keys are left out, and why.
func (k *keysEnv) base(cur *current) (keystmt.Statement, []string) {
	next, dropped := cur.base(k.keepRemoved)
	for _, l := range dropped {
		if k.keepRemoved {
			fmt.Fprintf(k.errw, "note: %s is no longer a key of your account at the platform (removed on the website?); -keep-removed: it stays a login key of the new statement\n", fpOf(l))
			continue
		}
		fmt.Fprintf(k.errw, "note: %s %s is left out of the new statement: it is no longer a key of your account at the platform (removed on the website). To keep it all the same: -keep-removed\n", fpOf(l), ownerkey.Printable(keyComment(l)))
	}
	return next, dropped
}

// keyComment is a key line's comment, "" for none.
func keyComment(line string) string {
	if f := strings.Fields(line); len(f) > 2 {
		return strings.Join(f[2:], " ")
	}
	return ""
}

// fetchStatement asks the entry point for the account's statement. Its
// signature is checked to be one (whose key it is, the sandboxes decide).
// A newer one in DIR/key-statement for the same account wins, with a note:
// the platform may offer an older statement, never a forged one.
func fetchStatement(entry *ssh.Client, dir string, errw io.Writer) (*current, error) {
	out, err := ownerkey.RunEntry(entry, []string{"ssh-key", "statement", "--json"})
	if err != nil {
		return nil, fmt.Errorf("the platform's statement of your keys: %w", err)
	}
	return statementFrom([]byte(out), dir, errw)
}

// Latest is the account's newest statement of keys this machine knows:
// the platform's, or the newer one in sbxkey's directory. Signed is ""
// when the account has none yet; Statement then holds the account's keys
// at the platform, seq 0.
type Latest struct {
	Account   string
	Statement *keystmt.Statement
	Signed    string
}

// LatestStatement is what fetchStatement makes of answer, the platform's
// answer to "ssh-key statement --json", and of the statement kept in dir:
// the statement an unlock sends and "keys sync" feeds (trajrl's keys sync
// --all, keys status and doctor, which ask the entry point themselves).
func LatestStatement(answer []byte, dir string, errw io.Writer) (*Latest, error) {
	c, err := statementFrom(answer, dir, errw)
	if err != nil {
		return nil, err
	}
	return &Latest{Account: c.account, Statement: c.st, Signed: c.signed}, nil
}

// statementFrom is fetchStatement after the platform answered out.
func statementFrom(out []byte, dir string, errw io.Writer) (*current, error) {
	var v struct {
		Account string   `json:"account"`
		Keys    []string `json:"keys"`
		Signed  string   `json:"signed"`
	}
	if err := json.Unmarshal(out, &v); err != nil || !keystmt.ValidAccount(v.Account) {
		return nil, errors.New("the platform's answer to \"ssh-key statement --json\" is not one")
	}
	c := &current{account: v.Account, st: &keystmt.Statement{Account: v.Account, Keys: v.Keys}, platform: v.Keys}
	if v.Signed != "" {
		st, err := parseSigned([]byte(v.Signed))
		if err != nil {
			return nil, fmt.Errorf("the platform's statement of your keys: %w", err)
		}
		if st.Account != v.Account {
			return nil, fmt.Errorf("the platform's statement is for account %q, you are %q", st.Account, v.Account)
		}
		c.st, c.signed = st, v.Signed
	}
	if b, err := os.ReadFile(statementCache(dir)); err == nil {
		if mine, err := parseSigned(b); err == nil && mine.Account == c.account {
			switch {
			case mine.Seq > c.st.Seq:
				fmt.Fprintf(errw, "note: the platform offers statement %d of your keys; %s holds %d, newer: that one is used\n", c.st.Seq, statementCache(dir), mine.Seq)
				c.st, c.signed = mine, string(b)
				return c, nil
			}
		}
	}
	if c.signed != "" {
		saveStatement(dir, c.signed)
	}
	return c, nil
}

func parseSigned(b []byte) (*keystmt.Statement, error) {
	text, sig, err := keystmt.Split(b)
	if err != nil {
		return nil, err
	}
	st, err := keystmt.Parse(text)
	if err != nil {
		return nil, err
	}
	if _, err := sshsig.Verify(sig, text, keystmt.Namespace); err != nil {
		return nil, err
	}
	return st, nil
}

func saveStatement(dir, signed string) {
	if dir == "" {
		return
	}
	os.MkdirAll(dir, 0o700)
	p := statementCache(dir)
	if err := os.WriteFile(p+".new", []byte(signed), 0o600); err == nil {
		os.Rename(p+".new", p)
	}
}

// --- signing -------------------------------------------------------------

// loadSigner reads a private key file, asking for its passphrase if it has
// one.
func loadSigner(path string, readSecret func(string) ([]byte, error)) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ssh.ParsePrivateKey(b)
	var pm *ssh.PassphraseMissingError
	if errors.As(err, &pm) && readSecret != nil {
		pass, perr := readSecret("Passphrase of " + path + ": ")
		if perr != nil {
			return nil, perr
		}
		s, err = ssh.ParsePrivateKeyWithPassphrase(b, pass)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// signerFor finds the key that signs the statement after cur: -sign-with,
// -i, or among the SSH agent's keys one that cur trusts, the one that
// logged in to the entry point first.
func (k *keysEnv) signerFor(cur *current) (ssh.Signer, error) {
	open := cur.signed == "" && len(cur.st.Keys) == 0
	trusted := func(s ssh.Signer) bool {
		if open {
			return true
		}
		for _, l := range cur.st.Signers() {
			if _, pk, err := keystmt.ParseKeyLine(l); err == nil && sshsig.Equal(pk, s.PublicKey()) {
				return true
			}
		}
		return false
	}
	var s ssh.Signer
	var err error
	switch {
	case k.signer != nil:
		s = k.signer
	case k.signWith != "":
		s, err = loadSigner(k.signWith, k.readSecret)
	case k.keyFile != "":
		s, err = loadSigner(k.keyFile, k.readSecret)
	default:
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("no key to sign with: give -i KEYFILE or -sign-with FILE, or run an SSH agent")
		}
		conn, derr := net.Dial("unix", sock)
		if derr != nil {
			return nil, fmt.Errorf("your SSH agent: %w", derr)
		}
		defer conn.Close()
		all, aerr := agent.NewClient(conn).Signers()
		if aerr != nil {
			return nil, fmt.Errorf("your SSH agent: %w", aerr)
		}
		var used ssh.PublicKey
		if k.id != nil {
			used = k.id.Used()
		}
		for _, a := range all {
			if trusted(a) && (s == nil || sshsig.Equal(a.PublicKey(), used)) {
				s = a
			}
		}
		if s == nil {
			return nil, errors.New("none of your SSH agent's keys is a key of your current statement: sign with -sign-with FILE (your recovery key, or another key of the statement)")
		}
	}
	if err != nil {
		return nil, err
	}
	if !trusted(s) {
		what := "a login key"
		if cur.st.Recovery != "" {
			what = "a login key or the recovery key"
		}
		return nil, fmt.Errorf("%s %s is not %s of your current statement (seq %d): your sandboxes would refuse what it signs. Sign with -sign-with FILE",
			ssh.FingerprintSHA256(s.PublicKey()), s.PublicKey().Type(), what, cur.st.Seq)
	}
	return s, nil
}

// put signs the statement after cur, stores it at the platform and in
// DIR/key-statement.
func (k *keysEnv) put(cur *current, next *keystmt.Statement) (string, error) {
	next.Account, next.Seq = cur.account, cur.st.Seq+1
	if cur.signed != "" && len(next.Keys) == 0 {
		return "", errors.New("the new statement would have no login key: nothing would open your sandboxes. Add the key you use now first (on the website, or " + ownerkey.Command("keys add") + "), or -keep-removed")
	}
	s, err := k.signerFor(cur)
	if err != nil {
		return "", err
	}
	if cur.signed == "" {
		// The first statement: the key that signs it is a login key in it.
		mine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
		has := false
		for _, l := range next.Keys {
			has = has || fpOf(l) == fpOf(mine)
		}
		if !has {
			next.Keys = append([]string{mine}, next.Keys...)
		}
		for _, l := range cur.st.Keys {
			if fpOf(l) != fpOf(mine) {
				fmt.Fprintf(k.errw, "note: %s is a key of your account at the platform and is not in your first statement: if it is yours, %s it\n", fpOf(l), ownerkey.Command("keys add"))
			}
		}
	}
	signed, err := keystmt.Sign(next, s)
	if err != nil {
		return "", err
	}
	out, err := ownerkey.RunEntryInput(k.entry, []string{"ssh-key", "statement", "put"}, signed)
	if err != nil {
		return "", fmt.Errorf("the platform did not store the statement: %w", err)
	}
	saveStatement(k.dir, string(signed))
	if o := strings.TrimSpace(ownerkey.Printable(out)); o != "" {
		fmt.Fprintln(k.out, o)
	}
	fmt.Fprintf(k.out, "statement %d of %s's keys signed with %s and stored.\n", next.Seq, next.Account, ssh.FingerprintSHA256(s.PublicKey()))
	return string(signed), nil
}

// --- key arguments --------------------------------------------------------

// keyArg is a key given on the command line: an authorized_keys line, or a
// file holding one. Remove also takes a fingerprint.
func keyArg(arg string, fingerprintOK bool) (line string, fp string, err error) {
	if fingerprintOK && strings.HasPrefix(arg, "SHA256:") {
		return "", arg, nil
	}
	if l, k, err := keystmt.ParseKeyLine(arg); err == nil {
		return l, ssh.FingerprintSHA256(k), nil
	}
	b, err := os.ReadFile(arg)
	if err != nil {
		return "", "", fmt.Errorf("%q is neither a public key nor a file holding one", arg)
	}
	var found []string
	for _, l := range strings.Split(string(b), "\n") {
		if pl, _, err := keystmt.ParseKeyLine(l); err == nil {
			found = append(found, pl)
		}
	}
	if len(found) != 1 {
		return "", "", fmt.Errorf("%s holds %d public keys; give a file with one", arg, len(found))
	}
	_, k, _ := keystmt.ParseKeyLine(found[0])
	return found[0], ssh.FingerprintSHA256(k), nil
}

func fpOf(line string) string {
	if _, k, err := keystmt.ParseKeyLine(line); err == nil {
		return ssh.FingerprintSHA256(k)
	}
	return "?"
}

// sandboxID is the ID of the sandbox NAME in the owner's record, or NAME
// itself if it is an ID.
func sandboxID(dir, name string) (string, error) {
	if strings.HasPrefix(name, "sbx-") {
		return name, nil
	}
	st, err := ownerkey.OpenState(filepath.Join(dir, "sandboxes.json"), filepath.Join(dir, "known_hosts"))
	if err != nil {
		return "", err
	}
	r := st.ByName(name)
	if r == nil {
		show := "ssh ENTRY show " + name + " --json"
		if ownerkey.Tool != "sbxkey" {
			show = ownerkey.Tool + " show " + name + " --json"
		}
		return "", fmt.Errorf("your record (%s) has no sandbox called %s: give its ID (sbx-..., \"%s\")", dir, name, show)
	}
	return r.ID, nil
}

// --- the commands ---------------------------------------------------------

func keysAdd(k *keysEnv, arg, sandbox string) error {
	line, fp, err := keyArg(arg, false)
	if err != nil {
		return err
	}
	cur, err := fetchStatement(k.entry, k.dir, k.errw)
	if err != nil {
		return err
	}
	next, _ := k.base(cur)
	if sandbox == "" {
		for _, l := range next.Keys {
			if fpOf(l) == fp {
				return fmt.Errorf("%s is a login key already", fp)
			}
		}
		next.Keys = append(next.Keys, line)
	} else {
		id, err := sandboxID(k.dir, sandbox)
		if err != nil {
			return err
		}
		for _, sk := range next.Sandboxes {
			if sk.Sandbox == id && fpOf(sk.Key) == fp {
				return fmt.Errorf("%s is a key of %s already", fp, sandbox)
			}
		}
		next.Sandboxes = append(next.Sandboxes, keystmt.SandboxKey{Sandbox: id, Key: line})
	}
	if _, err := k.put(cur, &next); err != nil {
		return err
	}
	where := "a login key: it opens the entry point now, and your sandboxes"
	if sandbox != "" {
		where = "a key of " + sandbox + " only: it opens " + sandbox
	}
	fmt.Fprintf(k.out, "%s is %s at their next unlock, or now: %s\n", fp, where, syncHint(sandbox))
	return nil
}

func keysRemove(k *keysEnv, arg, sandbox string) error {
	_, fp, err := keyArg(arg, true)
	if err != nil {
		return err
	}
	cur, err := fetchStatement(k.entry, k.dir, k.errw)
	if err != nil {
		return err
	}
	base, dropped := k.base(cur)
	next := base
	next.Keys, next.Sandboxes = nil, nil
	found := false
	id := ""
	if sandbox != "" {
		if id, err = sandboxID(k.dir, sandbox); err != nil {
			return err
		}
	}
	for _, l := range base.Keys {
		if sandbox == "" && fpOf(l) == fp {
			found = true
			continue
		}
		next.Keys = append(next.Keys, l)
	}
	for _, sk := range base.Sandboxes {
		if sandbox != "" && sk.Sandbox == id && fpOf(sk.Key) == fp {
			found = true
			continue
		}
		next.Sandboxes = append(next.Sandboxes, sk)
	}
	if !found && sandbox == "" && !k.keepRemoved {
		// Removed on the website already: it goes with this statement.
		for _, l := range dropped {
			found = found || fpOf(l) == fp
		}
	}
	if !found {
		if sandbox != "" {
			return fmt.Errorf("%s is not a key of %s in your statement", fp, sandbox)
		}
		return fmt.Errorf("%s is not a login key in your statement", fp)
	}
	if _, err := k.put(cur, &next); err != nil {
		return err
	}
	fmt.Fprintf(k.out, "%s removed. Your sandboxes drop it at their next unlock, or now: %s (a sandbox that never gets the statement still accepts it)\n", fp, syncHint(sandbox))
	return nil
}

func keysList(k *keysEnv, asJSON bool) error {
	cur, err := fetchStatement(k.entry, k.dir, k.errw)
	if err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(k.out).Encode(map[string]any{"account": cur.account, "statement": cur.st, "signed": cur.signed})
	}
	if cur.signed == "" {
		fmt.Fprintf(k.out, "%s has no signed statement of keys yet. Its keys at the platform:\n", cur.account)
	} else {
		fmt.Fprintf(k.out, "statement %d of %s's keys:\n", cur.st.Seq, cur.account)
	}
	names := map[string]string{}
	if st, err := ownerkey.OpenState(filepath.Join(k.dir, "sandboxes.json"), filepath.Join(k.dir, "known_hosts")); err == nil {
		for _, r := range st.Records() {
			names[r.ID] = r.Name
		}
	}
	for _, l := range cur.st.Keys {
		fmt.Fprintf(k.out, "  login     %s  %s\n", fpOf(l), ownerkey.Printable(l))
	}
	for _, sk := range cur.st.Sandboxes {
		n := names[sk.Sandbox]
		if n == "" {
			n = sk.Sandbox
		}
		fmt.Fprintf(k.out, "  %-9s %s  %s\n", n, fpOf(sk.Key), ownerkey.Printable(sk.Key))
	}
	if cur.st.Recovery != "" {
		fmt.Fprintf(k.out, "  recovery  %s  (signs statements, never logs in)\n", fpOf(cur.st.Recovery))
	} else if cur.signed != "" {
		fmt.Fprintln(k.out, "  no recovery key: "+ownerkey.Command("recovery-key init")+" makes one")
	}
	return nil
}

// keysSync feeds the statement to NAME over the owner's own SSH.
func keysSync(k *keysEnv, name, sshCmd, domain string) error {
	var signed []byte
	if k.entry != nil {
		cur, err := fetchStatement(k.entry, k.dir, k.errw)
		if err != nil {
			return err
		}
		signed = []byte(cur.signed)
	} else if b, err := os.ReadFile(statementCache(k.dir)); err == nil {
		signed = b
	}
	if len(signed) == 0 {
		return errors.New("there is no signed statement of your keys to send (" + ownerkey.Command("keys add") + " makes one)")
	}
	argv := strings.Fields(sshCmd)
	if len(argv) == 0 {
		if domain == "" {
			return fmt.Errorf("how to reach %s over SSH: give -ssh 'ssh root@HOST' or -domain D (ssh root@%s.D)", name, name)
		}
		argv = []string{"ssh", "root@" + name + "." + domain}
	}
	argv = append(argv, "sandbox-keys", "apply")
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin, c.Stdout, c.Stderr = strings.NewReader(string(signed)), k.out, k.errw
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s did not apply the statement (%s): %w", name, strings.Join(argv, " "), err)
	}
	return nil
}

// recoveryKeyInit makes a recovery key, puts its public half in a new
// statement and, once the platform has stored it, shows the private half,
// once.
func recoveryKeyInit(k *keysEnv, replace bool) error {
	cur, err := fetchStatement(k.entry, k.dir, k.errw)
	if err != nil {
		return err
	}
	if cur.st.Recovery != "" && !replace {
		return fmt.Errorf("your statement has a recovery key already (%s); -replace makes a new one in its place", fpOf(cur.st.Recovery))
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	comment := "sbx-recovery-" + cur.account
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return err
	}
	spub, _ := ssh.NewPublicKey(pub)
	next, _ := k.base(cur)
	next.Recovery = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(spub))) + " " + comment
	if _, err := k.put(cur, &next); err != nil {
		return err
	}
	fmt.Fprintf(k.out, `
YOUR RECOVERY KEY. It is shown once. Keep it OFFLINE: printed on paper, or on a
USB stick in a drawer; not on this laptop, not in a password manager that syncs.

It never logs in. It signs a statement of your keys, which your sandboxes
accept once they know it: each learns it at its next unlock, or now with
%s. After a lost laptop, add a new key on the website, then
on the new machine, with this saved as recovery.key (chmod 600):

    %s

If you lose this key AND every key you log in with, nobody can give you back
your sandboxes: not the platform, not its operator.

%s
Fingerprint: %s
`, syncHint(""), ownerkey.Command("keys add ~/.ssh/id_ed25519.pub -sign-with recovery.key"), pem.EncodeToMemory(block), ssh.FingerprintSHA256(spub))
	return nil
}

// syncHint is the command that feeds the new statement to the sandboxes
// now: sandbox's alone where the change is of one sandbox's keys; every
// sandbox of the account under trajrl (keys sync --all, cmd/trajrl), one
// at a time under sbxkey, which has no --all.
func syncHint(sandbox string) string {
	switch {
	case sandbox != "":
		return ownerkey.Command("keys sync " + sandbox)
	case ownerkey.Tool == "sbxkey":
		return ownerkey.Command("keys sync NAME")
	}
	return ownerkey.Command("keys sync --all")
}

// --- the command line -----------------------------------------------------

// parseInterleaved parses flags given before and after the positional
// arguments.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// keysMain is "sbxkey keys ..." and "sbxkey recovery-key ...".
func keysMain(args []string) error {
	keysUsage := renderUsage(keysUsage)
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, keysUsage)
		os.Exit(2)
	}
	cmd := args[0] + " " + args[1]
	switch cmd {
	case "keys add", "keys remove", "keys rm", "keys list", "keys ls", "keys sync", "recovery-key init":
	default:
		fmt.Fprint(os.Stderr, keysUsage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet(ownerkey.Command(cmd), flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, keysUsage) }
	dir := fs.String("dir", defaultDir(), "sbxkey's directory: the record of your sandboxes and your newest statement")
	entryAddr := fs.String("entry", "", "the platform's SSH entry point, host:port")
	entryKey := fs.String("entry-key", "", "the entry point's SSH host key as the platform publishes it")
	keyFile := fs.String("i", "", "your SSH private key file (default: your SSH agent)")
	signWith := fs.String("sign-with", "", "sign with this private key file instead (your recovery key)")
	sandbox := fs.String("sandbox", "", "(add, remove) a key of this sandbox only, by name (or ID)")
	sshCmd := fs.String("ssh", "", "(sync) the command that reaches the sandbox as root; \"sandbox-keys apply\" is run after it")
	domain := fs.String("domain", "", "(sync) the platform's domain for sandbox names")
	asJSON := fs.Bool("json", false, "(list) as JSON")
	replace := fs.Bool("replace", false, "(recovery-key init) replace the recovery key the statement has")
	keepRemoved := fs.Bool("keep-removed", false, "(add, remove, recovery-key init) keep the login keys removed on the website in the new statement")
	pos, err := parseInterleaved(fs, args[2:])
	if err != nil {
		return err
	}
	if cmd == "recovery-key init" && !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("recovery-key init shows your recovery key's private half once, and only on a terminal, never into a file or a pipe: run it on a terminal")
	}
	// keys sync reaches the sandbox over the owner's own SSH: the entry
	// point only if it is given (trajrl's configuration names one always).
	if cmd == "keys sync" {
		applyDefaults(fs, "entry", "entry-key", "i")
	} else {
		applyDefaults(fs)
	}
	k := &keysEnv{dir: *dir, keyFile: *keyFile, signWith: *signWith, out: os.Stdout, errw: os.Stderr, readSecret: askSecret, keepRemoved: *keepRemoved}
	needEntry := cmd != "keys sync" || *entryAddr != ""
	if needEntry {
		if *entryAddr == "" || *entryKey == "" {
			return errors.New("-entry and -entry-key are required")
		}
		id, err := userverify.LoadIdentity(*keyFile)
		if err != nil {
			return err
		}
		if k.entry, err = userverify.DialEntry(*entryAddr, *entryKey, id.Auth); err != nil {
			return err
		}
		defer k.entry.Close()
		k.id = id
	}
	want := func(n int, what string) error {
		if len(pos) != n {
			return fmt.Errorf("usage: %s", ownerkey.Command(cmd+" "+what))
		}
		return nil
	}
	switch cmd {
	case "keys add":
		if err := want(1, "PUBKEY|FILE [-sandbox NAME]"); err != nil {
			return err
		}
		return keysAdd(k, pos[0], *sandbox)
	case "keys remove", "keys rm":
		if err := want(1, "PUBKEY|FILE|SHA256:FP [-sandbox NAME]"); err != nil {
			return err
		}
		return keysRemove(k, pos[0], *sandbox)
	case "keys list", "keys ls":
		if err := want(0, "[-json]"); err != nil {
			return err
		}
		return keysList(k, *asJSON)
	case "keys sync":
		if err := want(1, "NAME"); err != nil {
			return err
		}
		if !ownerkey.ValidName(pos[0]) {
			return fmt.Errorf("%q is not a sandbox name", pos[0])
		}
		d := *domain
		if d == "" && *sshCmd == "" {
			if st, err := ownerkey.OpenState(filepath.Join(*dir, "sandboxes.json"), filepath.Join(*dir, "known_hosts")); err == nil {
				d = st.Domain()
			}
		}
		return keysSync(k, pos[0], *sshCmd, d)
	default: // recovery-key init
		if err := want(0, "[-replace]"); err != nil {
			return err
		}
		return recoveryKeyInit(k, *replace)
	}
}

// unlockStatement is the statement an unlock sends: the platform's, or
// sbxkey's own newer one; "" if there is none, or the platform could not
// say (an older platform: the sandbox's keys stay as they are).
func unlockStatement(entry *ssh.Client, dir, name string, errw io.Writer) string {
	cur, err := fetchStatement(entry, dir, errw)
	if err != nil {
		fmt.Fprintf(errw, "note: no statement of your keys is sent to %s (%v); its keys stay as they are\n", name, err)
		return ""
	}
	if cur.signed == "" {
		return ""
	}
	fmt.Fprintf(errw, "statement %d of your keys sent to %s's TD, which applies it if a key it trusts signed it\n", cur.st.Seq, name)
	return cur.signed
}

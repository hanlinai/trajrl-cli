package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// defaultSite is the website trajrl signs in at; TRAJRL_SITE or -site
// names another (stage).
const defaultSite = "https://sandbox.trajrl.com"

// linkAnswer is a line of the entry point's "link --json": the code a key
// nobody has is offered, or the account the key identifies.
type linkAnswer struct {
	Account         string    `json:"account,omitempty"`
	UserCode        string    `json:"user_code,omitempty"`
	VerificationURI string    `json:"verification_uri,omitempty"`
	URL             string    `json:"url,omitempty"`
	Fingerprint     string    `json:"fingerprint,omitempty"`
	Type            string    `json:"type,omitempty"`
	Expires         time.Time `json:"expires,omitzero"`
}

// authCmd is "auth [login] ..." and "auth status".
func authCmd(args []string) int {
	sub := "login"
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		sub, args = args[1], args[1:]
	}
	switch sub {
	case "login":
		return authLogin(args)
	case "status":
		return authStatus(args)
	}
	return fail(2, "usage: %s auth %s", prog, authUsage())
}

func authUsage() string {
	for _, c := range Commands {
		if c.Name == "auth" {
			return c.Usage
		}
	}
	return ""
}

// authLogin attaches this machine's SSH key to the website account of
// whoever confirms its code, then sets the machine up as setup does.
func authLogin(args []string) int {
	fs := flag.NewFlagSet(prog+" auth login", flag.ContinueOnError)
	site := fs.String("site", "", "the website to sign in at (default: $TRAJRL_SITE, or "+defaultSite+")")
	keyFile := fs.String("i", "", "your SSH private key file (default: your SSH agent, or ~/.ssh/id_ed25519, made if you have no key)")
	sshDir := fs.String("ssh-dir", "", "your ssh's directory (default: ~/.ssh)")
	noBrowser := fs.Bool("no-browser", false, "only print the page and the code, to enter on another device")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return fail(2, "usage: %s auth %s", prog, authUsage())
	}
	c := &config{Identity: *keyFile, SSHDir: *sshDir}
	old, _ := loadConfig()
	if old != nil {
		if *site == "" {
			c.Entry, c.EntryKey = old.Entry, old.EntryKey
		}
		if c.Identity == "" {
			c.Identity = old.Identity
		}
		if c.SSHDir == "" {
			c.SSHDir = old.SSHDir
		}
	}
	if c.Entry == "" || c.EntryKey == "" {
		s := *site
		if s == "" {
			s = os.Getenv("TRAJRL_SITE")
		}
		if s == "" {
			s = defaultSite
		}
		var err error
		if c.Entry, c.EntryKey, err = siteEntry(s); err != nil {
			return fail(1, "%v", err)
		}
	}
	if c.Identity == "" && !userverify.AgentHasKeys() {
		file, locked := c.identityFile()
		if file == "" {
			if len(locked) > 0 {
				return fail(1, "%v", noKey(locked))
			}
			made, err := newSSHKey(sshDirOf(c.SSHDir))
			if err != nil {
				return fail(1, "making an SSH key: %v", err)
			}
			fmt.Printf("You had no SSH key: made %s (no passphrase).\n", made)
			file = made
		}
		c.Identity = file
	}
	if old == nil {
		// The first time: a login given up on is taken up again where it
		// was.
		if err := c.save(); err != nil {
			return fail(1, "%v", err)
		}
	}

	account, err := linkKey(c, func(l linkAnswer) bool {
		fmt.Printf("This machine's SSH key: %s (%s)\n\n", l.Fingerprint, l.Type)
		fmt.Printf("Your one-time code: %s\n\n", l.UserCode)
		if !*noBrowser && openBrowser(l.URL) {
			fmt.Printf("Opened %s in your browser.\n", l.URL)
		} else {
			fmt.Printf("Open %s on any device and enter the code.\n", l.VerificationURI)
		}
		fmt.Printf("Confirm there only if it shows this key's fingerprint. Waiting (the code lasts until %s; Ctrl-C to stop)...\n",
			l.Expires.Local().Format("15:04"))
		return true
	})
	if err != nil {
		return fail(1, "%v", err)
	}
	fmt.Printf("Signed in as %s.\n\n", account)

	setup := []string{"setup", "-entry", c.Entry, "-entry-key", c.EntryKey}
	if c.Identity != "" {
		setup = append(setup, "-i", c.Identity)
	}
	if c.SSHDir != "" {
		setup = append(setup, "-ssh-dir", c.SSHDir)
	}
	return setupCmd(setup)
}

// siteEntry asks a website where its entry point is and for the host key
// to pin: over HTTPS, or plain HTTP to this machine alone.
func siteEntry(site string) (entry, key string, err error) {
	site = strings.TrimRight(site, "/")
	u, err := url.Parse(site)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("%q is not a website's address (https://HOST)", site)
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return "", "", fmt.Errorf("%s: only https:// is trusted to name the entry point", site)
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Get(site + "/sbx/cli")
	if err != nil {
		return "", "", fmt.Errorf("could not reach %s: %v", site, err)
	}
	defer resp.Body.Close()
	var v struct {
		Entry    string `json:"entry"`
		EntryKey string `json:"entry_key"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&v) != nil || v.Entry == "" || v.EntryKey == "" {
		return "", "", fmt.Errorf("%s does not serve sandboxes yet (GET /sbx/cli: %s)", site, resp.Status)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v.EntryKey)); err != nil {
		return "", "", fmt.Errorf("%s gave no usable host key for its entry point", site)
	}
	return v.Entry, v.EntryKey, nil
}

// authStatus says which account this machine's key identifies.
func authStatus(args []string) int {
	asJSON := len(args) == 2 && args[1] == "--json"
	if len(args) > 2 || len(args) == 2 && !asJSON {
		return fail(2, "usage: %s auth %s", prog, authUsage())
	}
	c, err := loadConfig()
	if err != nil {
		return fail(1, "not signed in: run %s auth login", prog)
	}
	var offer linkAnswer
	account, err := linkKey(c, func(l linkAnswer) bool { offer = l; return false })
	if err != nil && offer.Fingerprint == "" {
		return fail(1, "%v", err)
	}
	if asJSON {
		st := map[string]any{"signed_in": account != "", "entry": c.Entry}
		if account != "" {
			st["account"] = account
		} else {
			st["fingerprint"] = offer.Fingerprint
		}
		json.NewEncoder(os.Stdout).Encode(st)
	} else if account != "" {
		fmt.Printf("Signed in as %s at %s.\n", account, c.Entry)
	} else {
		fmt.Printf("Not signed in: this machine's key %s identifies no account at %s. Run: %s auth login\n", offer.Fingerprint, c.Entry, prog)
	}
	if account == "" {
		return 1
	}
	return 0
}

// linkKey runs "link --json" at the entry point. A key that identifies an
// account gets its name at once; a key nobody has gets a link, given to
// onLink, and the connection waits for its confirmation if onLink says so.
func linkKey(c *config, onLink func(linkAnswer) bool) (string, error) {
	client, err := dialEntry(c)
	if err != nil {
		return "", err
	}
	defer client.Close()
	s, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	out, err := s.StdoutPipe()
	if err != nil {
		return "", err
	}
	var said lockedBuffer
	s.Stderr = &said
	if err := s.Start("link --json"); err != nil {
		return "", err
	}
	dec := json.NewDecoder(out)
	// An entry point older than this trajrl has no "link --json": it holds
	// an unknown key's connection with its link in words, on stderr.
	first := time.AfterFunc(20*time.Second, func() { client.Close() })
	answered := false
	for {
		var a linkAnswer
		err := dec.Decode(&a)
		if !answered {
			answered = true
			if !first.Stop() || err != nil && strings.Contains(said.String(), `unknown command "link"`) {
				return "", fmt.Errorf("the entry point is older than this %s (it has no link --json): update it, or sign in with an older %s; what it said: %s",
					prog, prog, strings.Join(strings.Fields(strings.ReplaceAll(said.String(), "\r", "")), " "))
			}
		}
		if err != nil {
			s.Wait()
			msg := strings.TrimSpace(strings.ReplaceAll(said.String(), "\r", ""))
			if i := strings.LastIndex(msg, "\n"); i >= 0 {
				msg = msg[i+1:]
			}
			if msg == "" {
				msg = "the entry point ended the link: " + err.Error()
			}
			return "", errors.New(msg)
		}
		if a.Account != "" {
			return a.Account, nil
		}
		if !onLink(a) {
			return "", errors.New("not signed in")
		}
	}
}

// openBrowser opens u in this computer's browser, where it has one the
// user sits at: not in an ssh session, nor on Linux without a display.
func openBrowser(u string) bool {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return false
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return false
		}
		cmd = exec.Command("xdg-open", u)
	}
	if cmd.Start() != nil {
		return false
	}
	go cmd.Wait()
	return true
}

// newSSHKey makes dir/id_ed25519 and its .pub, as ssh-keygen would with no
// passphrase, and returns the private key's path.
func newSSHKey(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	host, _ := os.Hostname()
	comment := "trajrl@" + host
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", err
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "id_ed25519")
	if _, err := os.Stat(path + ".pub"); err == nil {
		return "", fmt.Errorf("%s.pub exists without its private key: move it away, or give -i KEYFILE", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(pem.EncodeToMemory(block)); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment + "\n"
	pf, err := os.OpenFile(path+".pub", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := pf.WriteString(line); err != nil {
		pf.Close()
		return "", err
	}
	return path, pf.Close()
}

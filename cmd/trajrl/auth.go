package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

const defaultSite = "https://sandbox.trajrl.com"

type credentials struct {
	Site    string `json:"site"`
	Token   string `json:"token"`
	Account string `json:"account,omitempty"`
	Device  bool   `json:"device,omitempty"`
}

type pendingDevice struct {
	Site                    string    `json:"site"`
	DeviceCode              string    `json:"device_code"`
	UserCode                string    `json:"user_code"`
	VerificationURI         string    `json:"verification_uri"`
	VerificationURIComplete string    `json:"verification_uri_complete"`
	Expires                 time.Time `json:"expires"`
	Interval                int       `json:"interval"`
}

func credentialsPath() string { return filepath.Join(dir(), "credentials.json") }
func devicePath() string      { return filepath.Join(dir(), "device.json") }

func writePrivate(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	os.Chmod(filepath.Dir(path), 0o700)
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func storedCredentials() *credentials {
	var c credentials
	if readJSONFile(credentialsPath(), &c) != nil || c.Token == "" || c.Site == "" {
		return nil
	}
	return &c
}

func siteOf(flagSite string) string {
	switch {
	case flagSite != "":
		return strings.TrimRight(flagSite, "/")
	case os.Getenv("TRAJRL_SITE") != "":
		return strings.TrimRight(os.Getenv("TRAJRL_SITE"), "/")
	}
	if c, err := readConfigFile(); err == nil && c.Site != "" {
		return c.Site
	}
	return defaultSite
}

func activeCredentials() (cred *credentials, fromEnv bool) {
	if t := strings.TrimSpace(os.Getenv("TRAJRL_TOKEN")); t != "" {
		return &credentials{Site: siteOf(""), Token: t}, true
	}
	return storedCredentials(), false
}

func checkSite(site string) error {
	u, err := url.Parse(site)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a website's address (https://HOST)", site)
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return fmt.Errorf("%s: only https:// is trusted", site)
	}
	return nil
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

func siteCall(site, method, path, token string, in, out any) (int, error) {
	if err := checkSite(site); err != nil {
		return 0, err
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, site+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("could not reach %s: %v", site, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if out != nil {
		json.Unmarshal(raw, out)
	}
	return resp.StatusCode, nil
}

func ticketAuth() ([]ssh.AuthMethod, error) {
	cred, fromEnv := activeCredentials()
	if cred == nil {
		return nil, nil
	}
	var v struct {
		Ticket string `json:"ticket"`
		Error  string `json:"error"`
	}
	code, err := siteCall(cred.Site, "POST", "/sbx/entry/ticket", cred.Token, map[string]string{}, &v)
	if err != nil {
		return nil, err
	}
	if code == 403 {
		return nil, fmt.Errorf("this token may not open the entry point (%s): sign in with %s auth login, or use a token made with %s token new --cmds entry", v.Error, prog, prog)
	}
	if code == 401 {
		if fromEnv {
			return nil, fmt.Errorf("TRAJRL_TOKEN was refused by %s: %s", cred.Site, v.Error)
		}
		return nil, fmt.Errorf("your sign-in at %s is no longer valid (%s): run %s auth login", cred.Site, v.Error, prog)
	}
	if code != 200 || v.Ticket == "" {
		return nil, fmt.Errorf("%s gave no entry ticket (HTTP %d): %s", cred.Site, code, v.Error)
	}
	return []ssh.AuthMethod{ssh.Password(v.Ticket)}, nil
}

func init() { userverify.EntryAuth = ticketAuth }

func authCmd(args []string) int {
	sub := "login"
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		sub, args = args[1], args[1:]
	}
	switch sub {
	case "login":
		return authLogin(args)
	case "whoami", "status":
		return authWhoami(args)
	case "logout":
		return authLogout(args)
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

func authLogin(args []string) int {
	fs := flag.NewFlagSet(prog+" auth login", flag.ContinueOnError)
	site := fs.String("site", "", "the website to sign in at (default: $TRAJRL_SITE, or "+defaultSite+")")
	asJSON := fs.Bool("json", false, "print one JSON object")
	noWait := fs.Bool("no-wait", false, "start the sign-in, print its code and page, and return; finish it with --wait")
	wait := fs.Bool("wait", false, "wait for the sign-in started with --no-wait")
	tokenStdin := fs.Bool("token-stdin", false, "sign in with a token read from standard input")
	noBrowser := fs.Bool("no-browser", false, "do not open a browser")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *noWait && *wait || *tokenStdin && (*noWait || *wait) {
		return fail(2, "usage: %s auth %s", prog, authUsage())
	}
	jsonMode = jsonMode || *asJSON

	if *wait {
		var p pendingDevice
		if err := readJSONFile(devicePath(), &p); err != nil || p.DeviceCode == "" {
			return fail(1, "no sign-in is waiting on this machine: run %s auth login", prog)
		}
		return pollDevice(&p, *asJSON)
	}

	s := siteOf(*site)
	if _, err := fetchEntry(s); err != nil {
		return fail(1, "%v", err)
	}

	if *tokenStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		token := strings.TrimSpace(line)
		if token == "" {
			if err == nil || err == io.EOF {
				return fail(2, "no token on standard input")
			}
			return fail(1, "%v", err)
		}
		account, cmds, err := tokenInfo(s, token)
		if err != nil {
			return fail(1, "%v", err)
		}
		if !slices.Contains(cmds, "entry") {
			return fail(1, "this token may not open the entry point (its commands: %s): use one made with %s token new --cmds entry", strings.Join(cmds, ","), prog)
		}
		return signedIn(&credentials{Site: s, Token: token, Account: account}, *asJSON)
	}

	host, _ := os.Hostname()
	var v struct {
		pendingDevice
		ExpiresIn int    `json:"expires_in"`
		Error     string `json:"error"`
	}
	code, err := siteCall(s, "POST", "/sbx/device/code", "", map[string]string{"label": host}, &v)
	if err != nil {
		return fail(1, "%v", err)
	}
	if code != 200 || v.DeviceCode == "" {
		return fail(1, "%s did not start a sign-in (HTTP %d): %s", s, code, v.Error)
	}
	p := v.pendingDevice
	p.Site, p.Expires = s, time.Now().Add(time.Duration(v.ExpiresIn)*time.Second)
	if err := writePrivate(devicePath(), &p); err != nil {
		return fail(1, "%v", err)
	}
	if *noWait {
		if *asJSON {
			return printJSON(map[string]any{"user_code": p.UserCode, "verification_uri": p.VerificationURI,
				"verification_uri_complete": p.VerificationURIComplete, "expires": p.Expires.UTC(), "next": prog + " auth login --wait"})
		}
		fmt.Printf("Your one-time code: %s\nOpen %s and enter it, or open %s\nThen run: %s auth login --wait (the code lasts until %s)\n",
			p.UserCode, p.VerificationURI, p.VerificationURIComplete, prog, p.Expires.Local().Format("15:04"))
		return 0
	}
	out := os.Stdout
	if *asJSON {
		out = os.Stderr
	}
	fmt.Fprintf(out, "Your one-time code: %s\n\n", p.UserCode)
	if !*noBrowser && openBrowser(p.VerificationURIComplete) {
		fmt.Fprintf(out, "Opened %s in your browser.\n", p.VerificationURIComplete)
	} else {
		fmt.Fprintf(out, "Open %s on any device and enter the code.\n", p.VerificationURI)
	}
	fmt.Fprintf(out, "Waiting for you to approve it there (the code lasts until %s; Ctrl-C to stop, %s auth login --wait to go on)...\n",
		p.Expires.Local().Format("15:04"), prog)
	return pollDevice(&p, *asJSON)
}

func pollDevice(p *pendingDevice, asJSON bool) int {
	interval := time.Duration(max(p.Interval, 1)) * time.Second
	for {
		if !time.Now().Before(p.Expires) {
			os.Remove(devicePath())
			return fail(1, "the code %s expired before it was approved: run %s auth login again", p.UserCode, prog)
		}
		time.Sleep(interval)
		var v struct {
			AccessToken string `json:"access_token"`
			Account     string `json:"account"`
			Error       string `json:"error"`
			Description string `json:"error_description"`
			Interval    int    `json:"interval"`
		}
		code, err := siteCall(p.Site, "POST", "/sbx/device/token", "", map[string]string{"device_code": p.DeviceCode}, &v)
		if err == nil && v.Error == "" && code != 200 {
			err = fmt.Errorf("%s answered HTTP %d", p.Site, code)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v; trying again\n", prog, err)
			continue
		}
		switch {
		case code == 200 && v.AccessToken != "":
			os.Remove(devicePath())
			return signedIn(&credentials{Site: p.Site, Token: v.AccessToken, Account: v.Account, Device: true}, asJSON)
		case v.Error == "authorization_pending":
		case v.Error == "slow_down":
			interval += 5 * time.Second
			if v.Interval > 0 {
				interval = time.Duration(v.Interval) * time.Second
			}
		case v.Error == "access_denied":
			os.Remove(devicePath())
			return fail(1, "the sign-in %s was denied on the website", p.UserCode)
		case v.Error == "expired_token":
			os.Remove(devicePath())
			return fail(1, "the code %s expired or was used: run %s auth login again", p.UserCode, prog)
		default:
			return fail(1, "%s refused the sign-in (HTTP %d): %s %s", p.Site, code, v.Error, v.Description)
		}
	}
}

func tokenAccount(site, token string) (string, error) {
	a, _, err := tokenInfo(site, token)
	return a, err
}

func tokenInfo(site, token string) (string, []string, error) {
	var v struct {
		Account string   `json:"account"`
		Cmds    []string `json:"cmds"`
		Error   string   `json:"error"`
	}
	code, err := siteCall(site, "GET", "/sbx/token", token, nil, &v)
	if err != nil {
		return "", nil, err
	}
	if code != 200 || v.Account == "" {
		return "", nil, fmt.Errorf("%s refused the token (HTTP %d): %s", site, code, v.Error)
	}
	return v.Account, v.Cmds, nil
}

func signedIn(c *credentials, asJSON bool) int {
	if err := discover(c.Site); err != nil {
		return fail(1, "signed in, but %v; nothing was saved: run %s auth login again", err, prog)
	}
	if old := storedCredentials(); old != nil && old.Device && old.Token != c.Token && old.Site == c.Site {
		siteCall(old.Site, "DELETE", "/sbx/token", old.Token, nil, nil)
	}
	if err := writePrivate(credentialsPath(), c); err != nil {
		return fail(1, "%v", err)
	}
	if asJSON {
		return printJSON(map[string]any{"signed_in": true, "account": c.Account, "site": c.Site})
	}
	fmt.Printf("Signed in as %s at %s.\n", c.Account, c.Site)
	fmt.Printf("Next: %s new NAME [-i KEYFILE, the SSH key your sandbox takes]. Nothing in your ~/.ssh was changed (%s setup adds ssh root@NAME.DOMAIN, if you want it).\n", prog, prog)
	return 0
}

type siteEntry struct {
	Entry    string `json:"entry"`
	EntryKey string `json:"entry_key"`
	Domain   string `json:"domain"`
}

func fetchEntry(site string) (*siteEntry, error) {
	if err := checkSite(site); err != nil {
		return nil, err
	}
	var v siteEntry
	code, err := siteCall(site, "GET", "/sbx/cli", "", nil, &v)
	if err != nil {
		return nil, err
	}
	if code != 200 || v.Entry == "" || v.EntryKey == "" {
		return nil, fmt.Errorf("%s does not serve sandboxes yet (GET /sbx/cli: HTTP %d)", site, code)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v.EntryKey)); err != nil {
		return nil, fmt.Errorf("%s gave no usable host key for its entry point", site)
	}
	return &v, nil
}

func discover(site string) error {
	v, err := fetchEntry(site)
	if err != nil {
		return err
	}
	c, err := readConfigFile()
	if err != nil {
		c = &config{}
	}
	if c.Site == site && c.Entry == v.Entry && c.EntryKey == v.EntryKey && c.Domain == v.Domain {
		return nil
	}
	c.Site, c.Entry, c.EntryKey = site, v.Entry, v.EntryKey
	if v.Domain != "" {
		c.Domain = v.Domain
	}
	return c.save()
}

func authWhoami(args []string) int {
	asJSON := len(args) == 2 && (args[1] == "--json" || args[1] == "-json")
	if len(args) > 2 || len(args) == 2 && !asJSON {
		return fail(2, "usage: %s auth %s", prog, authUsage())
	}
	cred, fromEnv := activeCredentials()
	if cred == nil {
		if asJSON {
			printJSON(map[string]any{"signed_in": false})
		} else {
			fmt.Printf("Not signed in. Run: %s auth login\n", prog)
		}
		return 1
	}
	var v struct {
		Account string     `json:"account"`
		ID      string     `json:"id"`
		Label   string     `json:"label"`
		Expires *time.Time `json:"expires"`
		Error   string     `json:"error"`
	}
	code, err := siteCall(cred.Site, "GET", "/sbx/token", cred.Token, nil, &v)
	if err != nil {
		return fail(255, "%v", err)
	}
	source := credentialsPath()
	if fromEnv {
		source = "TRAJRL_TOKEN"
	}
	if code != 200 {
		if asJSON {
			printJSON(map[string]any{"signed_in": false, "site": cred.Site, "source": source, "error": v.Error})
		} else {
			fmt.Printf("Not signed in: the token from %s is no longer valid at %s (%s). Run: %s auth login\n", source, cred.Site, v.Error, prog)
		}
		return 1
	}
	if asJSON {
		return printJSON(map[string]any{"signed_in": true, "account": v.Account, "site": cred.Site, "token_id": v.ID, "expires": v.Expires, "source": source})
	}
	until := "no expiry"
	if v.Expires != nil {
		until = "until " + v.Expires.Local().Format("2006-01-02")
	}
	fmt.Printf("Signed in as %s at %s (token %s from %s, %s).\n", v.Account, cred.Site, v.ID, source, until)
	return 0
}

func authLogout(args []string) int {
	if len(args) != 1 {
		return fail(2, "usage: %s auth %s", prog, authUsage())
	}
	os.Remove(devicePath())
	cred := storedCredentials()
	if cred == nil {
		if os.Getenv("TRAJRL_TOKEN") != "" {
			return fail(1, "TRAJRL_TOKEN is set in your environment: unset it (and revoke it on the website if it should stop working)")
		}
		fmt.Println("Not signed in on this machine.")
		return 0
	}
	if !cred.Device {
		if err := os.Remove(credentialsPath()); err != nil {
			return fail(1, "%v", err)
		}
		fmt.Printf("Signed out: the token given with --token-stdin is removed from %s. It was not revoked, as it may be used elsewhere: trajrl token rm ID revokes it.\n", credentialsPath())
		return 0
	}
	code, err := siteCall(cred.Site, "DELETE", "/sbx/token", cred.Token, nil, nil)
	if err != nil {
		return fail(255, "%v; nothing was removed: try again", err)
	}
	if code != 200 && code != 401 {
		return fail(1, "%s did not revoke the token (HTTP %d); nothing was removed: try again", cred.Site, code)
	}
	if err := os.Remove(credentialsPath()); err != nil {
		return fail(1, "%v", err)
	}
	fmt.Printf("Signed out: the token is revoked at %s and removed from %s.\n", cred.Site, credentialsPath())
	return 0
}

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

func needAccessKey(c *config, args []string) error {
	if cred, _ := activeCredentials(); cred == nil {
		return nil
	}
	if f := flagValue(append([]string{""}, args...), "i"); len(args) > 0 && f != "" {
		if abs, err := filepath.Abs(f); err == nil && abs != c.Identity {
			c.Identity = abs
			if c.Entry != "" {
				return c.save()
			}
		}
		return nil
	}
	if file, locked := c.identityFile(); file != "" || userverify.AgentHasKeys() {
		return nil
	} else {
		return noAccessKey(locked)
	}
}

func noAccessKey(locked []string) error {
	msg := fmt.Sprintf("no SSH key for your sandboxes: give yours with -i KEYFILE (it is remembered; make one with ssh-keygen -t ed25519), or load one into your SSH agent. %s makes none for you", prog)
	for _, l := range locked {
		msg += fmt.Sprintf("\n  %s has a passphrase, which %s does not ask for: load it into your SSH agent (ssh-add %s)", l, prog, l)
	}
	return errors.New(msg)
}

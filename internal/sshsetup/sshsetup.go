// Package sshsetup is how "trajrl setup" installs a machine's SSH settings
// (#123), the only installer of them: it checks the ssh_config lines an
// entry point gives ("ssh-config --json") against the one shape
// internal/control writes, puts the path of the trajrl that runs setup in
// their ProxyCommand (Localize), then installs them with its own
// installers, install-ssh.sh and install-ssh.ps1 (embedded). Nothing the
// entry point sends is run.
//
// The lines are one "Host *.DOMAIN" block whose ProxyCommand is "trajrl
// proxy %h %p": the user's ssh reaches a sandbox through trajrl, which
// dials the entry point itself, its key pinned in trajrl's configuration.
// There is no Host block for the entry point, no Port, no ProxyJump and no
// pin of the entry point's key in the user's known_hosts: the entry point
// answers only trajrl. An older setup's block (ProxyJump, "# BEGIN sandbox
// SSH entry: NAME") is replaced (Install's legacyPin, Installed).
package sshsetup

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

//go:embed install-ssh.sh
var installSSH string

//go:embed install-ssh.ps1
var installSSHPowerShell string

// UserKnownHostsLine is the line of the "Host *.DOMAIN" block that names
// the known-hosts files (internal/control, sandboxSSHLines).
const UserKnownHostsLine = "    UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/sbx_known_hosts"

// ProxyCommandLine is the block's ProxyCommand as the entry point writes
// it; Localize puts the path of the trajrl that runs setup in place of
// "trajrl".
const ProxyCommandLine = "    ProxyCommand trajrl proxy %h %p"

const proxyArgs = " proxy %h %p"

var (
	domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	numberRe = regexp.MustCompile(`^[0-9]{1,5}$`)
	// bareRe is a program path that needs no quotes in ssh_config or in
	// the shell ssh runs ProxyCommand with.
	bareRe = regexp.MustCompile(`^[A-Za-z0-9/._+:@,=-]+$`)
)

// Check checks text, the entry point's answer to "ssh-config", against the
// only shape internal/control's sshConfig writes, for the domain the entry
// point answered to "domain":
//
//	# comment lines
//	Host *.DOMAIN
//	    ProxyCommand TRAJRL proxy %h %p
//	    User root
//	    UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/sbx_known_hosts
//	    ServerAliveInterval N
//	    ServerAliveCountMax N
//	    [StrictHostKeyChecking yes]
//
// TRAJRL is "trajrl" (what the entry point writes), or the absolute path of
// a trajrl program (trajrl or trajrl.exe), bare or in double quotes, as
// Localize writes it. Anything else is refused: a Host block for anything
// but *.DOMAIN (Host *, the entry point's own), another keyword (ProxyJump,
// LocalCommand, Include, Match, Port ...), another value, a ProxyCommand
// that is not trajrl proxy %h %p, '%' elsewhere, a byte that is not
// printable ASCII.
func Check(text, domain string) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("the entry point's ssh_config lines are not the ones it should give, nothing was installed: "+format, a...)
	}
	if domain == "" || !domainRe.MatchString(domain) || len(domain) > 253 {
		return bad("the domain for sandbox names %q is not one", domain)
	}
	if text == "" || !strings.HasSuffix(text, "\n") {
		return bad("they are empty or end without a newline")
	}
	for i := 0; i < len(text); i++ {
		if b := text[i]; b != '\n' && (b < ' ' || b > '~') {
			return bad("they hold the byte %#x", b)
		}
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	i := 0
	for i < len(lines) && strings.HasPrefix(lines[i], "#") {
		if strings.Contains(lines[i], "%") {
			return bad("a comment holds a %%")
		}
		i++
	}
	next := func() string {
		if i >= len(lines) {
			return ""
		}
		i++
		return lines[i-1]
	}
	peek := func() string {
		if i >= len(lines) {
			return ""
		}
		return lines[i]
	}
	value := func(key string) (string, bool) {
		return strings.CutPrefix(peek(), "    "+key+" ")
	}
	if l := next(); l != "Host *."+domain {
		return bad("the block is for %q, not for *.%s alone", strings.TrimPrefix(l, "Host "), domain)
	}
	pc, ok := value("ProxyCommand")
	if !ok || !trajrlProxy(pc) {
		return bad("%q where \"ProxyCommand trajrl proxy %%h %%p\" belongs", peek())
	}
	next()
	for _, want := range []string{"    User root", UserKnownHostsLine} {
		if l := next(); l != want {
			return bad("%q where %q belongs", l, want)
		}
	}
	for _, key := range []string{"ServerAliveInterval", "ServerAliveCountMax"} {
		v, ok := value(key)
		if !ok || !numberRe.MatchString(v) {
			return bad("%q where %s N belongs", peek(), key)
		}
		next()
	}
	if peek() == "    StrictHostKeyChecking yes" {
		next()
	}
	if i != len(lines) {
		return bad("%q after the end", lines[i])
	}
	return nil
}

// trajrlProxy: v is "TRAJRL proxy %h %p", TRAJRL as Check allows it.
func trajrlProxy(v string) bool {
	prog, ok := strings.CutSuffix(v, proxyArgs)
	if !ok || prog == "" || strings.Contains(prog, "%") {
		return false
	}
	if prog == "trajrl" {
		return true
	}
	if q, ok := strings.CutPrefix(prog, `"`); ok {
		if prog, ok = strings.CutSuffix(q, `"`); !ok || prog == "" || strings.ContainsAny(prog, "\"$`\\") {
			return false
		}
	} else if !bareRe.MatchString(prog) {
		return false
	}
	base := prog[strings.LastIndex(prog, "/")+1:]
	abs := strings.HasPrefix(prog, "/") || (len(prog) > 2 && prog[1] == ':' && prog[2] == '/')
	return abs && (base == "trajrl" || strings.EqualFold(base, "trajrl.exe"))
}

// ProxyProgram is how the ProxyCommand line names the trajrl program at
// exe (os.Executable(), absolute) on goos: as it is, or in double quotes
// if it has a space or another character the shell would take apart. On
// Windows its backslashes are slashes, which Windows' own OpenSSH, and
// Windows, take as they are. A path ssh_config or the shell could not
// carry is refused.
func ProxyProgram(exe, goos string) (string, error) {
	p := exe
	if goos == "windows" {
		p = strings.ReplaceAll(p, `\`, "/")
	}
	abs := strings.HasPrefix(p, "/") || (goos == "windows" && len(p) > 2 && p[1] == ':' && p[2] == '/')
	if !abs {
		return "", fmt.Errorf("trajrl's path %q is not absolute", exe)
	}
	for _, r := range p {
		if r < ' ' || r == 0x7f {
			return "", fmt.Errorf("trajrl's path %q holds a control character", exe)
		}
	}
	if strings.ContainsAny(p, "\"%$`\\") {
		return "", fmt.Errorf("ssh_config cannot name trajrl at %q (a quote, %%, $, ` or backslash in it): move trajrl to a directory without one and run setup again", exe)
	}
	if bareRe.MatchString(p) {
		return p, nil
	}
	return `"` + p + `"`, nil
}

// Localize is text, lines Check accepted, with the trajrl at exe (on this
// machine's system) in its ProxyCommand.
func Localize(text, exe string) (string, error) {
	return localize(text, exe, runtime.GOOS)
}

func localize(text, exe, goos string) (string, error) {
	prog, err := ProxyProgram(exe, goos)
	if err != nil {
		return "", err
	}
	lines := strings.SplitAfter(text, "\n")
	n := 0
	for i, l := range lines {
		if v, ok := strings.CutPrefix(strings.TrimSuffix(l, "\n"), "    ProxyCommand "); ok && trajrlProxy(v) {
			lines[i], n = "    ProxyCommand "+prog+proxyArgs+"\n", n+1
		}
	}
	if n != 1 {
		return "", errors.New("the lines have no ProxyCommand for trajrl")
	}
	return strings.Join(lines, ""), nil
}

// PowerShell is the script that installs (or with remove takes out) the
// lines sshConfig for domain, with Windows' own OpenSSH: the settings as
// variables, then install-ssh.ps1, read by "powershell -NoProfile -Command
// -". legacyPin, the known_hosts line an older setup pinned the entry
// point's key with, is taken out too ("": none).
func PowerShell(remove bool, domain, legacyPin, sshConfig string) string {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by trajrl setup: the settings for \"ssh root@NAME.%s\"\n", domain)
	b.WriteString("# for Windows' own OpenSSH ($env:SBX_SSH_DIR: another directory than your .ssh).\n")
	fmt.Fprintf(&b, "$SbxRemove = $%t\n$SbxDomain = %s\n$SbxLegacyPin = %s\n$SbxConfig = @()\n", remove, quote(domain), quote(legacyPin))
	for _, line := range strings.Split(strings.TrimSuffix(sshConfig, "\n"), "\n") {
		fmt.Fprintf(&b, "$SbxConfig += %s\n", quote(line))
	}
	b.WriteString(strings.TrimRight(installSSHPowerShell, "\n") + "\n\n")
	return b.String()
}

// Install installs sshConfig, the lines for domain, into sshDir ("":
// ~/.ssh), or with remove takes them out, with the installer of this
// platform: install-ssh.sh run by sh, or on Windows the PowerShell script.
// Either way an older setup's block for domain is taken out, and with
// legacyPin (the known_hosts line it pinned the entry point's key with;
// "": none) that pin. What the installer says goes to out and errw.
func Install(remove bool, domain, sshConfig, legacyPin, sshDir string, out, errw io.Writer) error {
	if !domainRe.MatchString(domain) {
		return fmt.Errorf("%q is not a domain for sandbox names", domain)
	}
	if legacyPin != "" && (strings.ContainsAny(legacyPin, "\r\n") || len(strings.Fields(legacyPin)) != 3) {
		return errors.New("the older setup's pin is not one known_hosts line")
	}
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "-")
		cmd.Stdin = strings.NewReader(PowerShell(remove, domain, legacyPin, sshConfig))
		cmd.Stdout, cmd.Stderr = out, errw
		if sshDir != "" {
			cmd.Env = append(os.Environ(), "SBX_SSH_DIR="+sshDir)
		}
		return cmd.Run()
	}
	kit, err := os.MkdirTemp("", "trajrl-setup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(kit)
	files := map[string]string{"ssh_config": sshConfig, "domain": domain + "\n", "install-ssh.sh": installSSH}
	if remove && sshConfig == "" {
		files["ssh_config"] = "# (removal)\n"
	}
	if legacyPin != "" {
		files["legacy_pin"] = legacyPin + "\n"
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(kit, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	args := []string{filepath.Join(kit, "install-ssh.sh")}
	if remove {
		args = append(args, "--remove")
	}
	if sshDir != "" {
		args = append(args, sshDir)
	}
	cmd := exec.Command("sh", args...)
	cmd.Stdout, cmd.Stderr = out, errw
	return cmd.Run()
}

// Shape is what Installed found in an ssh config file for a domain.
type Shape int

const (
	// NotInstalled: no block of setup's for the domain.
	NotInstalled Shape = iota
	// Current: setup's block, its ProxyCommand trajrl proxy.
	Current
	// Legacy: an older setup's block for the domain, through the entry
	// point with ProxyJump, which the entry point no longer answers.
	// trajrl setup, run again, replaces it.
	Legacy
)

// Installed says which of setup's blocks the ssh config file at path holds
// for domain (a missing file holds none). The older one is "# BEGIN
// sandbox SSH entry: NAME" with ProxyJump in it and *.DOMAIN among its
// Host lines.
func Installed(path, domain string) (Shape, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NotInstalled, nil
	}
	if err != nil {
		return NotInstalled, err
	}
	shape := NotInstalled
	var block []string
	end := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case end == "" && line == "# BEGIN trajrl ssh: "+domain:
			end, block = "# END trajrl ssh: "+domain, nil
		case end == "" && strings.HasPrefix(line, "# BEGIN sandbox SSH entry: "):
			end, block = "# END sandbox SSH entry: "+strings.TrimPrefix(line, "# BEGIN sandbox SSH entry: "), nil
		case end != "" && line == end:
			mine, jump, proxy := false, false, false
			for _, l := range block {
				key, value := configWords(l)
				switch strings.ToLower(key) {
				case "host":
					mine = mine || slicesContainsFold(strings.Fields(value), "*."+domain)
				case "proxyjump":
					jump = true
				case "proxycommand":
					proxy = strings.HasSuffix(value, proxyArgs)
				}
			}
			switch {
			case mine && jump:
				return Legacy, nil
			case mine && proxy && strings.HasPrefix(end, "# END trajrl ssh: "):
				shape = Current
			}
			end = ""
		case end != "":
			block = append(block, line)
		}
	}
	return shape, nil
}

func slicesContainsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// DropKnownHostsCommand comments out, in the ssh config file at path, the
// KnownHostsCommand lines that ask the entry point for a sandbox's host key
// ("... known-hosts %H", written by older setups such as the stage kit) in
// a Host block whose patterns include *.DOMAIN. Where owners hold the keys
// the platform has no sandbox's host key, and such a line fails every
// "ssh root@NAME.DOMAIN". It returns the lines it commented out, as they
// were; with any, the file was first copied to backup
// (PATH.before-trajrl.XXXXXX). A missing file changes nothing.
func DropKnownHostsCommand(path, domain string) (changed []string, backup string, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	lines := strings.SplitAfter(string(b), "\n")
	inBlock := false
	for i, line := range lines {
		body := strings.TrimRight(line, "\r\n")
		key, value := configWords(body)
		switch strings.ToLower(key) {
		case "host":
			inBlock = false
			for _, p := range strings.Fields(value) {
				if strings.EqualFold(p, "*."+domain) {
					inBlock = true
				}
			}
		case "match":
			inBlock = false
		case "knownhostscommand":
			if inBlock && strings.Contains(" "+value+" ", " known-hosts ") {
				indent := body[:len(body)-len(strings.TrimLeft(body, " \t"))]
				changed = append(changed, strings.TrimSpace(body))
				lines[i] = indent + "# (trajrl setup: off, the platform holds no host keys) " + strings.TrimLeft(line, " \t")
			}
		}
	}
	if len(changed) == 0 {
		return nil, "", nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, "", err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".before-trajrl.")
	if err != nil {
		return nil, "", err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), fi.Mode().Perm())
	}
	if err != nil {
		os.Remove(f.Name())
		return nil, "", err
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), fi.Mode().Perm()); err != nil {
		return nil, f.Name(), err
	}
	return changed, f.Name(), nil
}

// configWords splits an ssh_config line into its keyword and the rest
// ("Key value", "Key=value"); a comment or empty line has no keyword.
func configWords(line string) (key, value string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	key, value = line[:i], strings.TrimLeft(line[i:], " \t")
	value = strings.TrimSpace(strings.TrimPrefix(value, "="))
	return key, value
}

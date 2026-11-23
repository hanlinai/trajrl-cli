package ownerkey

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The owner's ssh and the host keys this tool has recorded (#114).
//
// A sandbox is logged in to as NAME.DOMAIN, through the platform's entry
// point (trajrl proxy, the ProxyCommand trajrl setup writes). The session is between the owner's ssh and the
// sandbox's sshd, so what tells the owner's sandbox from anything the
// platform could put in its place is the sandbox's SSH host key: the one
// its TD reported at its first boot, inside the session whose quote the
// unlock verified. The platform does not know that key, so it cannot hand
// it out. This file brings it to where the owner's ssh looks:
//
//   - the key is pinned under NAME and NAME.DOMAIN (SandboxHosts);
//   - a mirror of every recorded key, under both names, is written to a
//     file in the owner's SSH directory (WriteSSHMirror), which the
//     ssh_config lines "trajrl setup" installs name as a second
//     known-hosts file for *.DOMAIN, with StrictHostKeyChecking yes.
//
// DOMAIN is the platform's word and is not checked. A wrong one cannot
// weaken anything: the pin then sits under a name the owner's ssh never
// looks up, and strict checking refuses the login.

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// CleanDomain is s as a domain for sandbox names: in lower case, without
// space or dots around it. It reports whether that is a DNS name of at
// least two labels.
func CleanDomain(s string) (string, bool) {
	d := strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
	return d, len(d) <= 253 && domainRe.MatchString(d)
}

// SandboxHosts are the host names a sandbox's SSH host key is pinned for:
// NAME, and NAME.DOMAIN where a domain is known.
func SandboxHosts(name, domain string) []string {
	if domain == "" {
		return []string{name}
	}
	return []string{name, name + "." + domain}
}

// Domain is the platform's domain for sandbox names as last recorded, or "".
func (s *State) Domain() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.Domain
}

// SetDomain records the platform's domain for sandbox names.
func (s *State) SetDomain(domain string) error {
	d, ok := CleanDomain(domain)
	if !ok {
		return errors.New("not a domain for sandbox names")
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.reload(); err != nil {
		return err
	}
	if s.doc.Domain == d {
		return nil
	}
	s.doc.Domain = d
	return s.write()
}

// PinSandbox writes the line that pins key for SandboxHosts(name, domain)
// into the known_hosts file, and drops the lines that pinned a sandbox's
// key in an earlier form: for name or for was (its name before a rename),
// alone or with the domain name. Lines for other host lists (-known-host)
// are left as they are.
func (s *State) PinSandbox(was, name, domain, key string) (string, error) {
	line, err := KnownHostsLine(SandboxHosts(name, domain), key)
	if err != nil {
		return "", err
	}
	drop := map[string]bool{}
	for _, n := range []string{was, name} {
		drop[n] = true
		drop[strings.Join(SandboxHosts(n, domain), ",")] = true
	}
	unlock, err := s.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	old, err := os.ReadFile(s.KnownHosts)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var out []string
	for _, l := range strings.Split(string(old), "\n") {
		if f := strings.Fields(l); len(f) > 0 && !drop[f[0]] {
			out = append(out, l)
		}
	}
	out = append(out, line)
	return line, writeAtomic(s.KnownHosts, []byte(strings.Join(out, "\n")+"\n"), 0o644)
}

// sshMirrorHeader says whose the file is: lines put there by hand are gone
// at the next unlock.
const sshMirrorHeader = "# Written by sbxkey: the SSH host keys of your sandboxes, as their TDs reported\n" +
	"# them at their first boots. Rewritten at every unlock, from sbxkey's record:\n" +
	"# lines of your own belong in known_hosts, not here.\n"

// mirrorLines are the known_hosts lines of the mirror and the names they
// are for: for every sandbox on record with an SSH host key, by name, one
// line for NAME and, with a domain, one for NAME.DOMAIN. The caller holds
// s.mu.
func (s *State) mirrorLines(domain string) (lines, names []string) {
	for _, r := range s.doc.Sandboxes {
		if ValidName(r.Name) && r.SSHHostKey != "" {
			names = append(names, r.Name)
		}
	}
	sort.Strings(names)
	var kept []string
	for _, name := range names {
		var key string
		for _, r := range s.doc.Sandboxes {
			if r.Name == name {
				key = r.SSHHostKey
			}
		}
		var own []string
		for _, h := range SandboxHosts(name, domain) {
			line, err := KnownHostsLine([]string{h}, key)
			if err != nil {
				own = nil
				break
			}
			own = append(own, line)
		}
		if own != nil {
			lines, kept = append(lines, own...), append(kept, name)
		}
	}
	return lines, kept
}

// WriteSSHMirror writes the mirror to path, atomically: exactly the lines
// of the sandboxes on record now, read from the state file under its lock,
// so that of two runs side by side neither leaves the other's sandbox out.
// It makes the directory if there is none. It returns the names it wrote
// keys for.
func (s *State) WriteSSHMirror(path, domain string) ([]string, error) {
	if domain != "" {
		d, ok := CleanDomain(domain)
		if !ok {
			return nil, errors.New("not a domain for sandbox names")
		}
		domain = d
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.reload(); err != nil {
		return nil, err
	}
	lines, names := s.mirrorLines(domain)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	body := sshMirrorHeader
	if len(lines) > 0 {
		body += strings.Join(lines, "\n") + "\n"
	}
	return names, writeAtomic(path, []byte(body), 0o600)
}

package keycmd

// sbxkey new -env KEY=VALUE (#75). The pairs become a short shell prelude in
// front of the owner's setup script, so they travel as the script does:
// encrypted to the TD, inside the attested session of the first boot, never
// seen by the platform. Nothing in the protocol, the initrd or what the guest
// measures changes. The values are the owner's secrets as far as this program
// is concerned: no message of sbxkey prints one.

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	// maxEnvPairs is the most -env pairs one sandbox gets.
	maxEnvPairs = 64
	// envFile and envDropIn are where the prelude puts the pairs: login
	// sessions (pam_env, every user) and services (the system manager).
	envFile   = "/etc/environment"
	envDropIn = "/etc/systemd/system.conf.d/50-sbx-env.conf"
	// envOwnerScript is where the prelude puts the owner's script, run as
	// its own file so that its #! line is kept.
	envOwnerScript = "/var/lib/tdx-sandbox/setup.owner"
	// envEndMarker is the prelude's last line; the owner's script follows it.
	envEndMarker = "# sbxkey -env: end of prelude"
)

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// parseEnv checks -env arguments. A key matches envKeyRE; a value is
// printable ASCII without '"', '\', '$', '`' (so that neither /etc/environment
// nor systemd's DefaultEnvironment= needs escaping). At most maxEnvPairs, and
// a key once. Errors name an argument by its position or its key, never its
// value: the argument may be a secret typed in the wrong form.
func parseEnv(args []string) ([][2]string, error) {
	if len(args) > maxEnvPairs {
		return nil, fmt.Errorf("-env given %d times; at most %d", len(args), maxEnvPairs)
	}
	seen := map[string]bool{}
	pairs := make([][2]string, 0, len(args))
	for i, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("-env #%d is not KEY=VALUE", i+1)
		}
		if !envKeyRE.MatchString(k) {
			return nil, fmt.Errorf("-env #%d: the name before '=' is not a variable name (a letter or '_', then letters, digits or '_', at most 64)", i+1)
		}
		if seen[k] {
			return nil, fmt.Errorf("-env %s is given twice", k)
		}
		seen[k] = true
		for _, c := range []byte(v) {
			if c < 0x20 || c > 0x7e || c == '"' || c == '\\' || c == '$' || c == '`' {
				return nil, fmt.Errorf("-env %s: the value may hold only printable ASCII characters other than \" \\ $ and `", k)
			}
		}
		pairs = append(pairs, [2]string{k, v})
	}
	return pairs, nil
}

// envFileText is what the prelude appends to /etc/environment: KEY="VALUE"
// lines, read by pam_env for every login session.
func envFileText(pairs [][2]string) string {
	var b strings.Builder
	for _, p := range pairs {
		fmt.Fprintf(&b, "%s=\"%s\"\n", p[0], p[1])
	}
	return b.String()
}

// envDropInText is the systemd drop-in: DefaultEnvironment= for every
// service the system manager starts.
func envDropInText(pairs [][2]string) string {
	var b strings.Builder
	b.WriteString("[Manager]\nDefaultEnvironment=")
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "\"%s=%s\"", p[0], p[1])
	}
	b.WriteString("\n")
	return b.String()
}

// envPrelude is the shell text that sets the pairs at the first boot: lines
// appended to /etc/environment, the drop-in with DefaultEnvironment=, and
// systemctl daemon-reexec so that services started after it see them. Empty
// for no pairs. No value can end a here-document early: none holds a newline.
func envPrelude(pairs [][2]string) string {
	if len(pairs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# sbxkey -env (#75): the owner's environment variables, set at the first boot.\n")
	b.WriteString("set -e\n")
	b.WriteString("umask 022\n")
	// A last line without its newline would run into the first pair.
	fmt.Fprintf(&b, "if [ -s %[1]s ] && [ -n \"$(tail -c 1 %[1]s)\" ]; then echo >>%[1]s; fi\n", envFile)
	fmt.Fprintf(&b, "cat >>%s <<'SBXKEY_ENV'\n%sSBXKEY_ENV\n", envFile, envFileText(pairs))
	fmt.Fprintf(&b, "mkdir -p %s\n", envDropIn[:strings.LastIndexByte(envDropIn, '/')])
	fmt.Fprintf(&b, "cat >%s <<'SBXKEY_ENV'\n%sSBXKEY_ENV\n", envDropIn, envDropInText(pairs))
	// Bounded, and not fatal: a reexec that fails or hangs costs the
	// services of this boot the variables, not the owner's script.
	b.WriteString("timeout 120 systemctl daemon-reexec || echo 'sbxkey -env: systemctl daemon-reexec failed; services see the variables from the next boot' >&2\n")
	return b.String()
}

// withEnv puts the prelude in front of the owner's script. The script is run
// as its own file, so that its #! line, whatever its language, is kept, with
// the pairs exported to it; with no script the prelude alone is the setup
// script. With no pairs the script is returned as it is.
func withEnv(pairs [][2]string, script string) string {
	p := envPrelude(pairs)
	if p == "" || script == "" {
		return p + script
	}
	var exp strings.Builder
	for _, kv := range pairs {
		fmt.Fprintf(&exp, "export %s=\"%s\"\n", kv[0], kv[1])
	}
	return p + exp.String() +
		fmt.Sprintf("sed '1,/^%s$/d' \"$0\" >%s\n", envEndMarker, envOwnerScript) +
		fmt.Sprintf("chmod 700 %s\n", envOwnerScript) +
		fmt.Sprintf("exec %s\n", envOwnerScript) +
		envEndMarker + "\n" + script
}

// setupWithEnv is what -setup-script and -env give together, refused when it
// is over proto.MaxSetupScript.
func setupWithEnv(envArgs []string, script string, max int) (string, error) {
	pairs, err := parseEnv(envArgs)
	if err != nil {
		return "", err
	}
	s := withEnv(pairs, script)
	if len(s) > max {
		if len(pairs) > 0 {
			return "", fmt.Errorf("the setup script with the -env prelude is %d bytes; at most %d", len(s), max)
		}
		return "", fmt.Errorf("the setup script is %d bytes; at most %d", len(s), max)
	}
	return s, nil
}

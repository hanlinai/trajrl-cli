package keycmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

func mustParseEnv(t *testing.T, args ...string) [][2]string {
	t.Helper()
	p, err := parseEnv(args)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnvPreludeExact(t *testing.T) {
	pairs := mustParseEnv(t, "FOO=bar baz", "_B2=it's a=b #1", "EMPTY=")
	want := `#!/bin/sh
# sbxkey -env (#75): the owner's environment variables, set at the first boot.
set -e
umask 022
if [ -s /etc/environment ] && [ -n "$(tail -c 1 /etc/environment)" ]; then echo >>/etc/environment; fi
cat >>/etc/environment <<'SBXKEY_ENV'
FOO="bar baz"
_B2="it's a=b #1"
EMPTY=""
SBXKEY_ENV
mkdir -p /etc/systemd/system.conf.d
cat >/etc/systemd/system.conf.d/50-sbx-env.conf <<'SBXKEY_ENV'
[Manager]
DefaultEnvironment="FOO=bar baz" "_B2=it's a=b #1" "EMPTY="
SBXKEY_ENV
timeout 120 systemctl daemon-reexec || echo 'sbxkey -env: systemctl daemon-reexec failed; services see the variables from the next boot' >&2
`
	if got := envPrelude(pairs); got != want {
		t.Fatalf("prelude:\n%s\nwant:\n%s", got, want)
	}
	script := "#!/bin/bash\necho hi\n"
	wantAll := want + `export FOO="bar baz"
export _B2="it's a=b #1"
export EMPTY=""
sed '1,/^# sbxkey -env: end of prelude$/d' "$0" >/var/lib/tdx-sandbox/setup.owner
chmod 700 /var/lib/tdx-sandbox/setup.owner
exec /var/lib/tdx-sandbox/setup.owner
# sbxkey -env: end of prelude
` + script
	if got := withEnv(pairs, script); got != wantAll {
		t.Fatalf("prelude and script:\n%s\nwant:\n%s", got, wantAll)
	}
	if got := withEnv(nil, script); got != script {
		t.Fatalf("no -env changed the script: %q", got)
	}
	if got := withEnv(nil, ""); got != "" {
		t.Fatalf("no -env and no script gave %q", got)
	}
}

func TestEnvPreludeBashSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	pairs := mustParseEnv(t, "FOO=bar baz", "_B2=it's a=b #1 ;&|<>(){}*?~!%", "EMPTY=")
	for name, text := range map[string]string{
		"prelude":            envPrelude(pairs),
		"prelude and script": withEnv(pairs, "#!/bin/sh\necho hi\n"),
	} {
		f := filepath.Join(t.TempDir(), "setup")
		if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
			t.Errorf("bash -n refuses the %s: %v\n%s", name, err, out)
		}
	}
}

// The text appended to /etc/environment, read by a shell as pam_env's
// KEY="VALUE" lines are: every value comes back exactly.
func TestEnvEnvironmentFileReadsBack(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	vals := map[string]string{"FOO": "bar baz", "_B2": "it's a=b #1 ;&|<>(){}*?~!%", "EMPTY": ""}
	pairs := mustParseEnv(t, "FOO="+vals["FOO"], "_B2="+vals["_B2"], "EMPTY=")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "environment"), []byte(envFileText(pairs)), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range vals {
		cmd := exec.Command("env", "-i", "bash", "-c", `set -a; . ./environment; printf %s "$`+k+`"`)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", k, err, out)
		}
		if string(out) != v {
			t.Errorf("%s: got %q, want %q", k, out, v)
		}
	}
}

// The prelude run for real, its absolute paths moved into a temporary
// directory and systemctl a stand-in: both files written, an existing
// /etc/environment kept and its unterminated last line ended, daemon-reexec
// called, and the owner's script run as its own file with its #! line.
func TestEnvPreludeRuns(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	root := t.TempDir()
	for _, d := range []string{"etc", "var/lib/tdx-sandbox", "bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "etc/environment"), []byte(`PATH="/usr/bin:/bin"`), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\necho \"$@\" >" + filepath.Join(root, "systemctl.called") + "\n"
	if err := os.WriteFile(filepath.Join(root, "bin/systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	pairs := mustParseEnv(t, "FOO=bar baz", "TOKEN=s3cr3t")
	owner := "#!/bin/bash\n# the owner's own script, in bash\necho \"owner ran as $0 with ${BASH_VERSION:+bash}, FOO=$FOO\"\n"
	text := withEnv(pairs, owner)
	text = strings.ReplaceAll(text, "/etc/", root+"/etc/")
	text = strings.ReplaceAll(text, "/var/lib/tdx-sandbox/", root+"/var/lib/tdx-sandbox/")
	setup := filepath.Join(root, "var/lib/tdx-sandbox/setup.ran")
	if err := os.WriteFile(setup, []byte(text), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(setup)
	cmd.Env = []string{"PATH=" + filepath.Join(root, "bin") + ":" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	ownerPath := filepath.Join(root, "var/lib/tdx-sandbox/setup.owner")
	if want := "owner ran as " + ownerPath + " with bash, FOO=bar baz\n"; string(out) != want {
		t.Errorf("output %q, want %q", out, want)
	}
	if b, _ := os.ReadFile(ownerPath); string(b) != owner {
		t.Errorf("owner's script as run:\n%s\nwant:\n%s", b, owner)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/environment")); string(b) != "PATH=\"/usr/bin:/bin\"\nFOO=\"bar baz\"\nTOKEN=\"s3cr3t\"\n" {
		t.Errorf("/etc/environment:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system.conf.d/50-sbx-env.conf")); string(b) != "[Manager]\nDefaultEnvironment=\"FOO=bar baz\" \"TOKEN=s3cr3t\"\n" {
		t.Errorf("drop-in:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "systemctl.called")); string(b) != "daemon-reexec\n" {
		t.Errorf("systemctl called with %q", b)
	}
}

func TestEnvRefused(t *testing.T) {
	const secret = "s3cr3t"
	many := make([]string, maxEnvPairs+1)
	for i := range many {
		many[i] = fmt.Sprintf("K%d=v", i)
	}
	for name, args := range map[string][]string{
		"key 1A":             {"1A=" + secret},
		"key A-B":            {"A-B=" + secret},
		"empty key":          {"=" + secret},
		"key of 65":          {strings.Repeat("A", 65) + "=" + secret},
		"no =":               {secret},
		`value with "`:       {`FOO=` + secret + `"`},
		"value with $":       {"FOO=" + secret + "$HOME"},
		`value with \`:       {`FOO=` + secret + `\`},
		"value with `":       {"FOO=" + secret + "`id`"},
		"value with newline": {"FOO=" + secret + "\nBAR=x"},
		"value with tab":     {"FOO=" + secret + "\t"},
		"value not ASCII":    {"FOO=" + secret + "é"},
		"key twice":          {"FOO=" + secret, "FOO=x"},
		"65 pairs":           many,
	} {
		_, err := parseEnv(args)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error shows the value: %v", name, err)
		}
		if _, err := setupWithEnv(args, "", proto.MaxSetupScript); err == nil {
			t.Errorf("%s: setupWithEnv accepted", name)
		}
	}
	if _, err := parseEnv(many[:maxEnvPairs]); err != nil {
		t.Errorf("%d pairs refused: %v", maxEnvPairs, err)
	}
	if _, err := parseEnv([]string{strings.Repeat("A", 64) + "=x", "_=x", "a_1=x"}); err != nil {
		t.Errorf("valid keys refused: %v", err)
	}
}

func TestEnvSizeLimitCountsPrelude(t *testing.T) {
	script := "#!/bin/sh\n" + strings.Repeat("#", proto.MaxSetupScript-len("#!/bin/sh\n")-1) + "\n"
	if len(script) != proto.MaxSetupScript {
		t.Fatal(len(script))
	}
	if s, err := setupWithEnv(nil, script, proto.MaxSetupScript); err != nil || s != script {
		t.Fatalf("a script of exactly %d bytes without -env: %v", proto.MaxSetupScript, err)
	}
	_, err := setupWithEnv([]string{"FOO=s3cr3t"}, script, proto.MaxSetupScript)
	if err == nil || !strings.Contains(err.Error(), "-env prelude") {
		t.Fatalf("prelude and a %d-byte script: %v", proto.MaxSetupScript, err)
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("the error shows the value: %v", err)
	}
	if _, err := setupWithEnv(nil, script+"x", proto.MaxSetupScript); err == nil {
		t.Fatal("a script over the limit was accepted")
	}
	small := "#!/bin/sh\ntrue\n"
	if s, err := setupWithEnv([]string{"FOO=s3cr3t"}, small, proto.MaxSetupScript); err != nil || !strings.HasSuffix(s, envEndMarker+"\n"+small) {
		t.Fatalf("prelude and a small script: %v", err)
	}
}

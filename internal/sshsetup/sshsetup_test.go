package sshsetup

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// good is what internal/control's sshConfig writes in owner-key mode.
const good = "# For ~/.ssh/config.\n# trajrl setup installs them.\nHost *.sbx.example\n" + ProxyCommandLine + "\n    User root\n" +
	UserKnownHostsLine + "\n    ServerAliveInterval 30\n    ServerAliveCountMax 4\n    StrictHostKeyChecking yes\n"

// legacy is an older entry point's lines, through it with ProxyJump.
const legacy = "# For ~/.ssh/config.\nHost entry.example\n    Port 2222\nHost *.sbx.example\n    ProxyJump entry.example\n    User root\n" +
	UserKnownHostsLine + "\n    ServerAliveInterval 30\n    ServerAliveCountMax 4\n"

// Check: the one shape, and the ProxyCommand trajrl proxy %h %p alone.
func TestCheck(t *testing.T) {
	withProg := func(prog string) string {
		return strings.Replace(good, "ProxyCommand trajrl ", "ProxyCommand "+prog+" ", 1)
	}
	for name, text := range map[string]string{
		"as the entry point writes it": good,
		"without strict checking":      strings.Replace(good, "    StrictHostKeyChecking yes\n", "", 1),
		"no comments":                  strings.TrimPrefix(good, "# For ~/.ssh/config.\n# trajrl setup installs them.\n"),
		"an absolute path":             withProg("/usr/local/bin/trajrl"),
		"a path in quotes":             withProg(`"/Users/Jo Doe/bin/trajrl"`),
		"a Windows path":               withProg(`"C:/Users/Jo Doe/AppData/Local/trajrl/trajrl.exe"`),
		"a bare Windows path":          withProg("C:/trajrl/trajrl.exe"),
	} {
		if err := Check(text, "sbx.example"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, text := range map[string]string{
		"Host *":                strings.Replace(good, "Host *.sbx.example", "Host *", 1),
		"another domain":        strings.Replace(good, "*.sbx.example", "*.other.example", 1),
		"a second pattern":      strings.Replace(good, "Host *.sbx.example", "Host *.sbx.example !entry.sbx.example", 1),
		"an entry block":        strings.Replace(good, "Host *.sbx.example", "Host entry.example\n    Port 2222\nHost *.sbx.example", 1),
		"ProxyJump (older)":     legacy,
		"ProxyJump added":       strings.Replace(good, "    User root\n", "    User root\n    ProxyJump entry.example\n", 1),
		"no ProxyCommand":       strings.Replace(good, ProxyCommandLine+"\n", "", 1),
		"ProxyCommand nc":       strings.Replace(good, "trajrl proxy %h %p", "nc %h %p", 1),
		"ProxyCommand sh":       strings.Replace(good, "trajrl proxy %h %p", "sh -c id", 1),
		"another program":       withProg("/usr/bin/nc"),
		"a relative path":       withProg("bin/trajrl"),
		"trajrl in a name":      withProg("/tmp/trajrl-evil"),
		"a quote unclosed":      withProg(`"/usr/bin/trajrl`),
		"a dollar":              withProg(`"/tmp/$(id)/trajrl"`),
		"a backtick":            withProg("\"/tmp/`id`/trajrl\""),
		"a space unquoted":      withProg("/tmp/a b/trajrl"),
		"more arguments":        strings.Replace(good, "proxy %h %p", "proxy %h %p -x", 1),
		"%r":                    strings.Replace(good, "proxy %h %p", "proxy %r %p", 1),
		"% elsewhere":           good + "# 100%\n",
		"two ProxyCommands":     strings.Replace(good, ProxyCommandLine+"\n", ProxyCommandLine+"\n"+ProxyCommandLine+"\n", 1),
		"strict no":             strings.Replace(good, "StrictHostKeyChecking yes", "StrictHostKeyChecking no", 1),
		"known hosts":           strings.Replace(good, UserKnownHostsLine, "    UserKnownHostsFile /dev/null", 1),
		"crlf":                  strings.ReplaceAll(good, "\n", "\r\n"),
		"not ascii":             good + "# é\n",
		"LocalCommand":          strings.Replace(good, "    User root\n", "    User root\n    LocalCommand id\n", 1),
		"Port":                  strings.Replace(good, "    User root\n", "    User root\n    Port 2222\n", 1),
		"user":                  strings.Replace(good, "User root", "User admin", 1),
		"Match":                 good + "Match all\n",
		"Include":               "Include /tmp/x\n" + good,
		"Include after":         good + "Include /tmp/x\n",
		"no newline at the end": strings.TrimSuffix(good, "\n"),
	} {
		if err := Check(text, "sbx.example"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, d := range []string{"", "ENTRY", "sbx", "SBX.example", "*.example"} {
		if err := Check(good, d); err == nil {
			t.Errorf("domain %q accepted", d)
		}
	}
}

// ProxyProgram and Localize: the absolute path of trajrl, quoted where it
// has a space, slashes on Windows; refused where ssh_config or the shell
// could not carry it.
func TestLocalize(t *testing.T) {
	for _, c := range []struct{ exe, goos, want string }{
		{"/usr/local/bin/trajrl", "linux", "/usr/local/bin/trajrl"},
		{"/Users/Jo Doe/bin/trajrl", "darwin", `"/Users/Jo Doe/bin/trajrl"`},
		{"/home/jo/.local/bin/trajrl", "linux", "/home/jo/.local/bin/trajrl"},
		{"/opt/trajrl (1)/trajrl", "linux", `"/opt/trajrl (1)/trajrl"`},
		{`C:\Users\Jo Doe\AppData\Local\trajrl\trajrl.exe`, "windows", `"C:/Users/Jo Doe/AppData/Local/trajrl/trajrl.exe"`},
		{`C:\trajrl\trajrl.exe`, "windows", "C:/trajrl/trajrl.exe"},
	} {
		got, err := ProxyProgram(c.exe, c.goos)
		if err != nil || got != c.want {
			t.Errorf("ProxyProgram(%q, %s) = %q %v, want %q", c.exe, c.goos, got, err, c.want)
			continue
		}
		text, err := localize(good, c.exe, c.goos)
		if err != nil || text != strings.Replace(good, "ProxyCommand trajrl ", "ProxyCommand "+c.want+" ", 1) {
			t.Errorf("localize with %q: %v\n%s", c.exe, err, text)
		}
		if err := Check(text, "sbx.example"); err != nil {
			t.Errorf("Check refuses what Localize wrote for %q: %v", c.exe, err)
		}
	}
	for _, c := range []struct{ exe, goos string }{
		{"trajrl", "linux"},
		{`C:\trajrl.exe`, "linux"},
		{"/tmp/100%/trajrl", "linux"},
		{`/tmp/"x"/trajrl`, "linux"},
		{"/tmp/$HOME/trajrl", "linux"},
		{"/tmp/a\\b/trajrl", "linux"},
		{"/tmp/a\nb/trajrl", "linux"},
	} {
		if p, err := ProxyProgram(c.exe, c.goos); err == nil {
			t.Errorf("ProxyProgram(%q, %s) = %q", c.exe, c.goos, p)
		}
	}
	if _, err := localize(legacy, "/usr/bin/trajrl", "linux"); err == nil {
		t.Error("localize found a ProxyCommand in the older lines")
	}
}

// files is an SSH directory's config and known_hosts ("" for none).
func files(t *testing.T, dir string) [2]string {
	t.Helper()
	var f [2]string
	for i, name := range []string{"config", "known_hosts"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			f[i] = string(b)
		}
	}
	return f
}

// install-ssh.sh: the block at the top of config, the user's lines after
// it; a second run changes nothing; an older setup's block for the domain,
// and with its pin that pin, are replaced; another domain's older block
// and another key under the entry point's name stay; --remove leaves the
// files as they were. Installed tells the shapes apart.
func TestInstallScript(t *testing.T) {
	for _, p := range []string{"sh", "ssh", "ssh-keygen", "awk"} {
		if _, err := exec.LookPath(p); err != nil {
			t.Skipf("%s is not installed", p)
		}
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	other := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHoEhcBu6/W6qJhv7Q4l1smyWD0uiE2Wn1EwnVg0Wmc4"
	text, err := localize(good, "/opt/trajrl/bin/trajrl", "linux")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	mine := "Host mine\n    User me\n"
	otherDomain := "# BEGIN sandbox SSH entry: e.other\nHost e.other\nHost *.other.example\n    ProxyJump e.other\n\nHost *\n# END sandbox SSH entry: e.other\n"
	oldBlock := "# BEGIN sandbox SSH entry: entry.example\n" + legacy + "\nHost *\n# END sandbox SSH entry: entry.example\n"
	knownBefore := "mine " + key + "\n[entry.example]:2222 " + other + "\n"
	os.WriteFile(cfg, []byte(oldBlock+otherDomain+mine), 0o600)
	os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(knownBefore+"\n[entry.example]:2222 "+key+"\n"), 0o600)
	shape := func() Shape {
		s, err := Installed(cfg, "sbx.example")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if shape() != Legacy {
		t.Fatalf("the older block: %v", shape())
	}
	var out bytes.Buffer
	if err := Install(false, "sbx.example", text, "[entry.example]:2222 "+key, dir, &out, &out); err != nil {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	// Another directory than ~/.ssh: the known-hosts files are its own.
	block := strings.Replace(text, UserKnownHostsLine, `    UserKnownHostsFile "`+dir+`/known_hosts" "`+dir+`/sbx_known_hosts"`, 1)
	want := [2]string{"# BEGIN trajrl ssh: sbx.example\n" + block + "\nHost *\n# END trajrl ssh: sbx.example\n" + otherDomain + mine, knownBefore}
	if got := files(t, dir); got != want {
		t.Fatalf("after install:\n%s\n%s\nwant:\n%s\n%s\n%s", got[0], got[1], want[0], want[1], out.String())
	}
	if shape() != Current {
		t.Errorf("after install: %v", shape())
	}
	if !strings.Contains(out.String(), "Installed trajrl's lines for *.sbx.example in "+dir) {
		t.Errorf("the installer said:\n%s", out.String())
	}
	if err := Install(false, "sbx.example", text, "", dir, &out, &out); err != nil || files(t, dir) != want {
		t.Fatalf("install twice: %v\n%v", err, files(t, dir))
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "*.before-entry.*"))
	if len(backups) != 2 {
		t.Errorf("backups: %q", backups)
	}
	// ssh reads it: web.sbx.example goes through trajrl proxy, the
	// entry point and other names are untouched.
	g, err := exec.Command("ssh", "-G", "-F", cfg, "web.sbx.example").Output()
	if err != nil || !strings.Contains(string(g), "\nproxycommand /opt/trajrl/bin/trajrl proxy %h %p\n") || !strings.Contains(string(g), "\nuser root\n") {
		t.Errorf("ssh -G web.sbx.example: %v\n%s", err, g)
	}
	if g, _ := exec.Command("ssh", "-G", "-F", cfg, "entry.example").Output(); strings.Contains(string(g), "proxycommand") {
		t.Errorf("ssh -G entry.example:\n%s", g)
	}

	if err := Install(true, "sbx.example", "", "", dir, &out, &out); err != nil {
		t.Fatalf("remove: %v\n%s", err, out.String())
	}
	if got := files(t, dir); got != [2]string{otherDomain + mine, knownBefore} {
		t.Fatalf("after remove:\n%s\n%s", got[0], got[1])
	}
	if shape() != NotInstalled {
		t.Errorf("after remove: %v", shape())
	}
	// Into an empty directory, and out again: nothing left.
	empty := filepath.Join(t.TempDir(), "ssh")
	if err := Install(false, "sbx.example", text, "", empty, &out, &out); err != nil {
		t.Fatal(err)
	}
	if err := Install(true, "sbx.example", "", "", empty, &out, &out); err != nil || files(t, empty) != [2]string{} {
		t.Fatalf("install and remove in an empty directory: %v %v", err, files(t, empty))
	}
	// An incomplete block: nothing is changed.
	os.WriteFile(cfg, []byte("# BEGIN trajrl ssh: sbx.example\nHost x\n"+mine), 0o600)
	if err := Install(false, "sbx.example", text, "", dir, &out, &out); err == nil {
		t.Error("installed over an incomplete block")
	}
}

// The PowerShell script carries the settings as PowerShell strings, the
// installer after them, with no empty line inside it (a statement read
// from standard input ends at one).
func TestPowerShellScript(t *testing.T) {
	text, err := localize(good, `C:\Users\O'Neil\trajrl\trajrl.exe`, "windows")
	if err != nil {
		t.Fatal(err)
	}
	ps := PowerShell(false, "sbx.example", "[entry.example]:2222 ssh-ed25519 AAAA", text)
	for _, want := range []string{"$SbxRemove = $false\n", "$SbxDomain = 'sbx.example'\n", "$SbxLegacyPin = '[entry.example]:2222 ssh-ed25519 AAAA'\n",
		"$SbxConfig += '    ProxyCommand \"C:/Users/O''Neil/trajrl/trajrl.exe\" proxy %h %p'\n", "# BEGIN trajrl ssh: $SbxDomain"} {
		if !strings.Contains(ps, want) {
			t.Errorf("the PowerShell script has no %q", want)
		}
	}
	body := installSSHPowerShell[strings.Index(installSSHPowerShell, "& {"):]
	if strings.Contains(strings.TrimRight(body, "\n"), "\n\n") {
		t.Error("an empty line inside the PowerShell installer")
	}
	for _, gone := range []string{"$SbxPin", "Connect from your own terminal"} {
		if strings.Contains(installSSHPowerShell, gone) {
			t.Errorf("the PowerShell installer still has %q", gone)
		}
	}
}

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The entry point's commands the skills may name as "trajrl WORD": they are
// forwarded (internal/control/sshd.go). Every other word must be a command
// of trajrl's own table.
var entryCommands = []string{"ls", "show", "sizes", "images", "wait", "stop", "restart", "rm", "share", "domain", "egress", "snapshot", "whoami"}

// What no released binary may hold (release/build-owner-tools.sh), and the
// skills are in the binary.
var releaseForbidden = []string{"dev-insecure-rehearsal", "AllowUnattestedRehearsal", "unattestedRehearsal", "NOT FOR ANY REAL USE",
	"LoadTCBException", "experimental-tcb-exception", "EXPERIMENTAL: TDX module TCB"}

// The skills trajrl carries: each a SKILL.md with a name and a description,
// naming only commands that exist, with the rules on secrets and on the
// flags that need a person's yes, and nothing a release refuses.
func TestSkills(t *testing.T) {
	all, err := skills()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range all {
		names = append(names, s.Name)
	}
	if !slices.Equal(names, []string{"trajrl-sandbox", "trajrl-verify"}) {
		t.Fatalf("skills %q", names)
	}
	local := map[string]bool{}
	for _, c := range Commands {
		local[c.Name] = true
	}
	for _, old := range []string{"entry", "sbxkey", "sbxverify", "sbxapi"} {
		delete(local, old) // not what a skill should teach
	}
	word := regexp.MustCompile(`\btrajrl ([a-z][a-z-]*)`)
	for _, s := range all {
		body := string(s.Body)
		n := 0
		for _, m := range word.FindAllStringSubmatch(body, -1) {
			n++
			if !local[m[1]] && !slices.Contains(entryCommands, m[1]) {
				t.Errorf("%s names \"trajrl %s\": neither trajrl's command nor one of the entry point's listed here", s.Name, m[1])
			}
		}
		if n < 5 {
			t.Errorf("%s names %d commands: the pattern finds nothing", s.Name, n)
		}
		for _, f := range releaseForbidden {
			if strings.Contains(body, f) {
				t.Errorf("%s holds %q, which no release may", s.Name, f)
			}
		}
		for _, consent := range []string{"`rm NAME --yes`", "`-accept-older N`", "`-accept-newer N`", "`-accept-recovered`", "`-first-boot`", "`rollback-accept NAME --yes`", "**Ask the human first, every time**"} {
			if !strings.Contains(body, consent) {
				t.Errorf("%s lacks %s in its rule on a person's yes", s.Name, consent)
			}
		}
		if !strings.Contains(body, "**Secrets stay unseen.**") || !strings.Contains(body, "passphrase files") {
			t.Errorf("%s lacks the rule on key files and passphrases", s.Name)
		}
	}
	if !strings.Contains(string(all[0].Body), "--json") {
		t.Error("trajrl-sandbox does not tell to use --json")
	}
	for _, v := range []string{"`VERIFIED`", "`NOT VERIFIED`", "`REFUSED`"} {
		if !strings.Contains(string(all[1].Body), v) {
			t.Errorf("trajrl-verify does not explain %s", v)
		}
	}
}

// skills list, show, and install: into ~/.claude/skills by default, again
// with nothing to do, refused (nothing written) where a SKILL.md differs,
// and replaced with -force.
func TestSkillsInstall(t *testing.T) {
	h := newHome(t, nil)
	out, _, code := trajrl(t, "", "skills", "list")
	if code != 0 || !strings.HasPrefix(out, "trajrl-sandbox ") || !strings.Contains(out, "\ntrajrl-verify ") {
		t.Fatalf("skills list: %d %q", code, out)
	}
	all, _ := skills()
	if out, _, code := trajrl(t, "", "skills", "show", "trajrl-verify"); code != 0 || out != string(all[1].Body) {
		t.Fatalf("skills show: %d %q", code, out)
	}
	if _, _, code := trajrl(t, "", "skills", "show", "nope"); code != 1 {
		t.Fatalf("skills show nope: %d", code)
	}

	dir := filepath.Join(h.dir, "home", ".claude", "skills")
	if out, errs, code := trajrl(t, "", "skills", "install"); code != 0 || strings.Count(out, ": installed\n") != 2 {
		t.Fatalf("skills install: %d %q %q", code, out, errs)
	}
	for _, s := range all {
		if b, err := os.ReadFile(filepath.Join(dir, s.Name, "SKILL.md")); err != nil || string(b) != string(s.Body) {
			t.Fatalf("%s after install: %v", s.Name, err)
		}
	}
	if out, _, code := trajrl(t, "", "skills", "install"); code != 0 || strings.Count(out, ": already installed\n") != 2 {
		t.Fatalf("skills install again: %d %q", code, out)
	}

	// One of them changed by its user, the other removed: nothing is written.
	mine := filepath.Join(dir, "trajrl-verify", "SKILL.md")
	os.WriteFile(mine, []byte("mine\n"), 0o644)
	os.RemoveAll(filepath.Join(dir, "trajrl-sandbox"))
	_, errs, code := trajrl(t, "", "skills", "install")
	if code != 1 || !strings.Contains(errs, mine) || !strings.Contains(errs, "-force") {
		t.Fatalf("skills install over a changed one: %d %q", code, errs)
	}
	if b, _ := os.ReadFile(mine); string(b) != "mine\n" {
		t.Fatal("the changed SKILL.md was replaced without -force")
	}
	if _, err := os.Stat(filepath.Join(dir, "trajrl-sandbox")); !os.IsNotExist(err) {
		t.Fatal("a refused install wrote the other skill")
	}
	if _, _, code := trajrl(t, "", "skills", "install", "-force"); code != 0 {
		t.Fatalf("skills install -force: %d", code)
	}
	if b, _ := os.ReadFile(mine); string(b) != string(all[1].Body) {
		t.Fatal("-force did not replace it")
	}

	// -dir and one skill by name.
	other := filepath.Join(h.dir, "agent-skills")
	if out, _, code := trajrl(t, "", "skills", "install", "-dir", other, "trajrl-verify"); code != 0 || strings.Count(out, "installed") != 1 {
		t.Fatalf("skills install -dir: %d %q", code, out)
	}
	if ents, _ := os.ReadDir(other); len(ents) != 1 || ents[0].Name() != "trajrl-verify" {
		t.Fatalf("-dir holds %v", ents)
	}
	if _, _, code := trajrl(t, "", "skills", "install", "-dir", other, "nope"); code != 1 {
		t.Fatalf("skills install nope: %d", code)
	}
}

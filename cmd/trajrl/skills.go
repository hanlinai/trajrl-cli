package main

import (
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// skillFS holds the skills trajrl carries for coding agents (#123): one
// directory each, skills/NAME/SKILL.md, in the layout Claude Code reads
// from ~/.claude/skills.
//
//go:embed skills
var skillFS embed.FS

// skill is one embedded skill.
type skill struct {
	Name, Description string
	Body              []byte
}

// skills are the embedded skills, by name.
func skills() ([]skill, error) {
	ents, err := fs.ReadDir(skillFS, "skills")
	if err != nil {
		return nil, err
	}
	var out []skill
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		b, err := skillFS.ReadFile(path.Join("skills", e.Name(), "SKILL.md"))
		if err != nil {
			return nil, err
		}
		s, err := parseSkill(b)
		if err != nil {
			return nil, fmt.Errorf("skill %s: %w", e.Name(), err)
		}
		if s.Name != e.Name() {
			return nil, fmt.Errorf("skill %s is named %q in its SKILL.md", e.Name(), s.Name)
		}
		out = append(out, s)
	}
	return out, nil
}

// parseSkill reads a SKILL.md's front matter: name and description.
func parseSkill(b []byte) (skill, error) {
	s := skill{Body: b}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return s, errors.New("no front matter")
	}
	head, _, ok := strings.Cut(text[4:], "\n---\n")
	if !ok {
		return s, errors.New("the front matter does not end")
	}
	for _, line := range strings.Split(head, "\n") {
		k, v, _ := strings.Cut(line, ":")
		switch strings.TrimSpace(k) {
		case "name":
			s.Name = strings.TrimSpace(v)
		case "description":
			s.Description = strings.TrimSpace(v)
		}
	}
	if s.Name == "" || s.Description == "" {
		return s, errors.New("the front matter lacks a name or a description")
	}
	return s, nil
}

// defaultSkillDir is where Claude Code reads a user's skills.
func defaultSkillDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".claude", "skills")
	}
	return filepath.Join(home, ".claude", "skills")
}

// skillsCmd is "skills list | show NAME | install [-dir DIR] [-force]".
func skillsCmd(args []string) int {
	usage := func() int {
		return fail(2, "usage: %s skills list | show NAME | install [-dir DIR] [-force] [NAME...]", prog)
	}
	if len(args) < 2 {
		return usage()
	}
	all, err := skills()
	if err != nil {
		return fail(1, "%v", err)
	}
	switch args[1] {
	case "list", "ls":
		if len(args) != 2 {
			return usage()
		}
		for _, s := range all {
			fmt.Printf("%-16s  %s\n", s.Name, s.Description)
		}
		return 0
	case "show":
		if len(args) != 3 {
			return usage()
		}
		for _, s := range all {
			if s.Name == args[2] {
				os.Stdout.Write(s.Body)
				return 0
			}
		}
		return fail(1, "no skill %q (%s skills list)", args[2], prog)
	case "install":
		return skillsInstall(args[2:], all)
	}
	return usage()
}

// skillsInstall writes DIR/NAME/SKILL.md for each skill asked for (all of
// them by default). A SKILL.md there already with other content is refused,
// and nothing is written, unless -force.
func skillsInstall(args []string, all []skill) int {
	fl := flag.NewFlagSet(prog+" skills install", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	dir := fl.String("dir", defaultSkillDir(), "the skills directory")
	force := fl.Bool("force", false, "replace a SKILL.md that differs")
	if err := fl.Parse(args); err != nil {
		return fail(2, "skills install: %v\nusage: %s skills install [-dir DIR] [-force] [NAME...]", err, prog)
	}
	want := all
	if fl.NArg() > 0 {
		want = nil
		for _, n := range fl.Args() {
			found := false
			for _, s := range all {
				if s.Name == n {
					want, found = append(want, s), true
				}
			}
			if !found {
				return fail(1, "no skill %q (%s skills list)", n, prog)
			}
		}
	}
	var differ []string
	for _, s := range want {
		old, err := os.ReadFile(filepath.Join(*dir, s.Name, "SKILL.md"))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return fail(1, "%v", err)
		case !bytes.Equal(old, s.Body):
			differ = append(differ, filepath.Join(*dir, s.Name, "SKILL.md"))
		}
	}
	if len(differ) > 0 && !*force {
		return fail(1, "not installed: these differ from trajrl's and would be replaced:\n  %s\n(-force replaces them)", strings.Join(differ, "\n  "))
	}
	for _, s := range want {
		p := filepath.Join(*dir, s.Name, "SKILL.md")
		if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, s.Body) {
			fmt.Printf("%s: already installed\n", p)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fail(1, "%v", err)
		}
		if err := os.WriteFile(p, s.Body, 0o644); err != nil {
			return fail(1, "%v", err)
		}
		fmt.Printf("%s: installed\n", p)
	}
	return 0
}

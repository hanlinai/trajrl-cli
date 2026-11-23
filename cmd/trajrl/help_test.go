package main

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// entryHelp is the entry point's help text, from internal/control/sshd.go
// (its const help); the test is skipped where that file is not (the
// exported tree carries no service code). The path is joined, not
// written out, so that the export does not take it for test data.
func entryHelp(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "control", "sshd.go"))
	if err != nil {
		t.Skip("no internal/control/sshd.go here")
	}
	_, rest, ok := strings.Cut(string(b), "const help = `")
	text, _, ok2 := strings.Cut(rest, "`")
	if !ok || !ok2 {
		t.Fatal("no const help in sshd.go")
	}
	return text
}

// trajrl help lists every command a user needs: each of trajrl's own in
// one group, and the platform's that people use, marked as the
// platform's, each one the entry point really has. It asks the entry
// point nothing.
func TestHelpListsEveryCommand(t *testing.T) {
	var grouped []string
	for _, g := range ownGroups {
		for _, n := range g.Names {
			if slices.Contains(grouped, n) {
				t.Errorf("%s in two groups", n)
			}
			if _, ok := ownCommand(n); !ok {
				t.Errorf("group %q names %s, not in the table", g.Title, n)
			}
			grouped = append(grouped, n)
		}
	}
	for _, c := range Commands {
		if !slices.Contains(grouped, c.Name) {
			t.Errorf("%s is in no group of trajrl help", c.Name)
		}
	}

	e := newFakeEntry(t, echo)
	newHome(t, e)
	out, _, code := trajrl(t, "", "help")
	if code != 0 {
		t.Fatalf("help: %d", code)
	}
	for _, w := range []string{"ls", "show", "new", "stop", "rm", "rename", "snapshot", "resize", "resize-disk", "set-image",
		"domain", "share", "egress", "tag", "comment", "defaults", "token", "team", "billing", "stat", "backup", "account delete",
		"whoami", "register", "wait", "sizes", "status", "doctor", "setup", "tui"} {
		if !strings.Contains(out, "\n  trajrl "+w+" ") && !strings.Contains(out, "\n  trajrl "+w+"\n") {
			t.Errorf("help does not list trajrl %s", w)
		}
	}
	for _, s := range []string{"snapshot new NAME | ls NAME | restore NAME ID --yes", "backup new NAME | ls NAME | status NAME | restore NAME",
		"Sandboxes (the platform's)", "Account (the platform's)", "trajrl entry help: the platform's full reference", "trajrl help COMMAND"} {
		if !strings.Contains(out, s) {
			t.Errorf("help has no %q", s)
		}
	}
	if strings.Contains(out, "ssh ENTRY") || strings.Contains(out, "ssh-setup") {
		t.Errorf("help sends people to the entry point's ssh:\n%s", out)
	}
	if execs, conns := e.seen(); conns != 0 {
		t.Fatalf("help reached the entry point: %q", execs)
	}
	// No arguments without a terminal: the same list.
	if noargs, _, code := trajrl(t, ""); code != 0 || noargs != out {
		t.Errorf("trajrl with no arguments: %d, not the help", code)
	}

	// Each platform command listed is the entry point's (register is the
	// newcomer's, before an account, and not in its help), and is not one
	// of trajrl's own unless trajrl hands it on (share, backup).
	text := entryHelp(t)
	for _, g := range Platform {
		for _, c := range g.Commands {
			words := strings.Fields(c.Words)
			if c.Words != "register" && helpSection(text, words) == "" {
				t.Errorf("%s: not in the entry point's help", c.Words)
			}
			if handlers[words[0]] != nil && !slices.Contains([]string{"share", "backup"}, words[0]) {
				t.Errorf("%s is listed as the platform's but trajrl runs it itself", c.Words)
			}
		}
	}
}

// helpSection takes the entry point's text for the words: every entry
// with a form that starts with them, with its lines, and nothing of the
// prose after the list.
func TestHelpSection(t *testing.T) {
	text := entryHelp(t)
	for _, c := range []struct {
		words      []string
		has, hasnt []string
	}{
		{[]string{"stop"}, []string{"  start NAME | stop NAME | restart NAME\n"}, []string{"rm NAME"}},
		{[]string{"share", "port"}, []string{"share port NAME PORT [--direct]", "3000-9999"}, []string{"share ssh NAME", "set-public"}},
		{[]string{"share"}, []string{"share set-public", "share port NAME", "share ssh NAME ACCOUNT", "share ipv6-ssh"}, []string{"egress"}},
		{[]string{"images"}, []string{"sizes | images"}, nil},
		{[]string{"account", "delete"}, []string{"account delete --confirm ACCOUNT", "refused while it has"}, []string{"whoami"}},
		{[]string{"ls"}, []string{"ls [-l] [--tag TAG]", "with tag TAG"}, []string{"show NAME"}},
		{[]string{"nosuch"}, nil, nil},
	} {
		sec := helpSection(text, c.words)
		for _, s := range c.has {
			if !strings.Contains(sec, s) {
				t.Errorf("%q: no %q in\n%s", c.words, s, sec)
			}
		}
		for _, s := range c.hasnt {
			if strings.Contains(sec, s) {
				t.Errorf("%q: %q in\n%s", c.words, s, sec)
			}
		}
		if strings.Contains(sec, "add --json") || strings.Contains(sec, "ssh -p PORT") {
			t.Errorf("%q: prose after the list in\n%s", c.words, sec)
		}
		if len(c.has) == 0 && sec != "" {
			t.Errorf("%q: %q", c.words, sec)
		}
	}
}

// trajrl help COMMAND: one of trajrl's own from the table (new also with
// the platform's new); one of the platform's from the entry point's help,
// or its line of the list when the entry point cannot be reached; neither:
// exit 2.
func TestHelpCommand(t *testing.T) {
	text := entryHelp(t)
	e := newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		if cmd != "help" {
			io.WriteString(errw, "unexpected "+cmd+"\n")
			return 2
		}
		io.WriteString(out, text)
		return 0
	})
	h := newHome(t, e)
	out, _, code := trajrl(t, "", "help", "egress")
	if code != 0 || !strings.HasPrefix(out, "trajrl egress is the platform's command") || !strings.Contains(out, "egress NAME open | egress NAME none") {
		t.Errorf("help egress: %d\n%s", code, out)
	}
	out, _, code = trajrl(t, "", "help", "share", "port")
	if code != 0 || !strings.HasPrefix(out, "  trajrl share ssh NAME ACCOUNT") || !strings.Contains(out, "The platform's share port") ||
		!strings.Contains(out, "share port NAME PORT [--direct]") || strings.Contains(out, "share ipv6-ssh") {
		t.Errorf("help share port: %d\n%s", code, out)
	}
	out, _, code = trajrl(t, "", "help", "verify")
	if code != 0 || !strings.HasPrefix(out, "  trajrl verify NAME [-owner]") || strings.Contains(out, "platform") {
		t.Errorf("help verify: %d\n%s", code, out)
	}
	out, _, code = trajrl(t, "", "help", "new")
	if code != 0 || !strings.HasPrefix(out, "  trajrl new [flags] NAME") || !strings.Contains(out, "The platform's new") || !strings.Contains(out, "--setup-script") {
		t.Errorf("help new: %d\n%s", code, out)
	}
	if _, errs, code := trajrl(t, "", "help", "nosuch"); code != 2 || !strings.Contains(errs, "not a command") {
		t.Errorf("help nosuch: %d %q", code, errs)
	}
	// The entry point out of reach: the line of the list, and why.
	gone := *h.cfg
	gone.Entry = "127.0.0.1:1"
	if err := gone.save(); err != nil {
		t.Fatal(err)
	}
	out, errs, code := trajrl(t, "", "help", "resize-disk")
	if code != 0 || out != "  trajrl resize-disk NAME GIB\n      grow NAME's disk to GIB (stopped only; disks only grow)\n" || !strings.Contains(errs, "not read") {
		t.Errorf("help resize-disk, no entry point: %d %q %q", code, out, errs)
	}
}

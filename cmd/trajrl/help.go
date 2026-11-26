package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

// ownGroups are trajrl's own commands (Commands) as trajrl help groups
// them; every one is in exactly one group (TestHelp).
var ownGroups = []struct {
	Title string
	Names []string
}{
	{"Start here", []string{"auth", "setup", "doctor", "status", "tui"}},
	{"Sandboxes, checked on this machine", []string{"new", "start", "unlock", "verify", "ssh", "proxy", "exec", "cp", "rename", "known-hosts"}},
	{"Your keys and the images you accept", []string{"key", "keys", "recovery-key", "policy"}},
	{"Sharing and backups", []string{"share", "backup"}},
	{"More", []string{"skills", "version", "help", "entry", "sbxkey", "sbxverify", "sbxapi"}},
}

// withPlatformText are trajrl's own commands that hand flags or
// subcommands to the platform's command of the same name: trajrl help
// NAME shows the platform's text too.
var withPlatformText = []string{"new", "share", "backup"}

// helpLine writes one command of the help: its line, then what it does.
func helpLine(w io.Writer, words, usage, what string) {
	line := "  " + prog + " " + words
	if usage != "" {
		line += " " + usage
	}
	fmt.Fprintf(w, "%s\n      %s\n", line, what)
}

// help writes every command a user needs, trajrl's own and the platform's
// it forwards, grouped. It asks nothing of the entry point.
func help(w io.Writer) {
	fmt.Fprintf(w, "usage: %s COMMAND [ARGS...]\n\n", prog)
	fmt.Fprintf(w, "%s is the client of your TrajRL sandboxes. Sign in once with %s auth login, then create\n"+
		"one with %s new NAME.\n", prog, prog, prog)
	for _, g := range ownGroups {
		fmt.Fprintf(w, "\n%s\n", g.Title)
		for _, name := range g.Names {
			if c, ok := ownCommand(name); ok {
				helpLine(w, c.Name, c.Usage, c.Help)
			}
		}
	}
	fmt.Fprintf(w, "\nThe platform's commands, which %s sends to its entry point as they are:\n", prog)
	for _, g := range Platform {
		fmt.Fprintf(w, "\n%s (the platform's)\n", g.Title)
		for _, c := range g.Commands {
			helpLine(w, c.Words, c.Usage, c.Help)
		}
	}
	fmt.Fprintf(w, "\n%s help COMMAND: one command in full (the platform's from its own reference).\n", prog)
	fmt.Fprintf(w, "%s entry help: the platform's full reference. Add --json to a platform command for JSON.\n", prog)
}

// ownCommand is trajrl's command name from the table.
func ownCommand(name string) (Command, bool) {
	i := slices.IndexFunc(Commands, func(c Command) bool { return c.Name == name })
	if i < 0 {
		return Command{}, false
	}
	return Commands[i], true
}

// helpCmd is "help [COMMAND...]": the list, or one command. For one of
// the platform's it shows that command's part of the entry point's own
// help ("trajrl entry help"), or, with the entry point out of reach, the
// short line of the list.
func helpCmd(args []string) int {
	if len(args) < 2 {
		help(os.Stdout)
		return 0
	}
	words := args[1:]
	if c, ok := ownCommand(words[0]); ok {
		helpLine(os.Stdout, c.Name, c.Usage, c.Help)
		if slices.Contains(withPlatformText, c.Name) {
			if text, err := platformHelp(); err == nil {
				if sec := helpSection(text, words); sec != "" {
					fmt.Printf("\nThe platform's %s, which %s hands the rest to:\n%s", strings.Join(words, " "), prog, sec)
				}
			}
		}
		return 0
	}
	var known []PlatformCommand
	for _, g := range Platform {
		for _, c := range g.Commands {
			if f := strings.Fields(c.Words); len(f) <= len(words) && slices.Equal(f, words[:len(f)]) ||
				len(f) > len(words) && slices.Equal(f[:len(words)], words) {
				known = append(known, c)
			}
		}
	}
	text, err := platformHelp()
	if err == nil {
		if sec := helpSection(text, words); sec != "" {
			fmt.Printf("%s %s is the platform's command; %s sends it as it is. From its reference:\n\n%s",
				prog, strings.Join(words, " "), prog, sec)
			return 0
		}
	}
	if len(known) == 0 {
		return fail(2, "help: %s is not a command of %s's or of the platform's; %s help lists them", strings.Join(words, " "), prog, prog)
	}
	for _, c := range known {
		helpLine(os.Stdout, c.Words, c.Usage, c.Help)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: the platform's full text not read: %v\n", prog, err)
	}
	return 0
}

// platformHelp is the entry point's help.
func platformHelp() (string, error) {
	c, err := loadConfig()
	if err != nil {
		return "", err
	}
	out, err := entryOutput(c, "help")
	return strings.ReplaceAll(string(out), "\r", ""), err
}

// usageEnd is where a command's usage ends on its line of the entry
// point's help, and what it does begins.
var usageEnd = regexp.MustCompile(`\s{2,}`)

// helpSection is the part of the entry point's help (its "commands:"
// list, internal/control/sshd.go) that is about the command words: every
// entry one of whose forms ("a | b") starts with them, with the lines
// under it. The list starts after the line "commands:" (or at the top if
// there is none); an entry is a line indented by two spaces, the lines
// under it are indented further, and the list ends at the first line not
// indented.
func helpSection(text string, words []string) string {
	var b strings.Builder
	in := false
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "commands:" {
			lines = lines[i+1:]
			break
		}
	}
	for _, l := range lines {
		if l != "" && l[0] != ' ' {
			break
		}
		if strings.HasPrefix(l, "  ") && len(l) > 2 && l[2] != ' ' {
			usage := usageEnd.Split(strings.TrimSpace(l), 2)[0]
			in = false
			for _, form := range strings.Split(usage, "|") {
				if f := strings.Fields(form); len(f) >= len(words) && slices.Equal(f[:len(words)], words) {
					in = true
				}
			}
		} else if strings.TrimSpace(l) == "" {
			in = false
		}
		if in {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

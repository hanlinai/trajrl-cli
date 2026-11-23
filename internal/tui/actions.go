package tui

import (
	"errors"
	"strings"
)

// Mode is how an action's command runs.
type Mode int

const (
	// Background: the screen stays, the output goes to the results panel.
	Background Mode = iota
	// Terminal: the screen pauses and the command has the terminal (it
	// asks for a passphrase, or is a login).
	Terminal
)

// Action is one command the screen runs: trajrl's own argv (Args[0] is the
// program's name) and how.
type Action struct {
	Args []string
	Mode Mode
}

// Line is the action's command line as the screen shows it and "c"
// copies it: one a shell takes as it is.
func (a Action) Line() string { return JoinLine(a.Args) }

// keyActions are the keys that act on the selected sandbox, in the order
// the help screen lists them. "r" and "d" are there too; their command
// depends on the state, or on a confirmation.
var keyActions = []struct{ key, what string }{
	{"u", "unlock: verify its TD and give it your key"},
	{"s", "ssh: log in, its verified host key pinned"},
	{"v", "verify: check it from this machine"},
	{"x", "stop"},
	{"r", "start (stopped) or restart (running)"},
	{"d", "delete, after you type its name"},
}

// actionFor is the command of key for sandbox sb; ok is false for a key
// that is no such action. "d" and "n" are not here: they ask first.
func actionFor(prog, key string, sb Sandbox) (Action, bool) {
	switch key {
	case "u":
		return Action{[]string{prog, "unlock", sb.Name}, Terminal}, true
	case "s":
		return Action{[]string{prog, "ssh", sb.Name}, Terminal}, true
	case "v":
		return Action{[]string{prog, "verify", sb.Name}, Background}, true
	case "x":
		return Action{[]string{prog, "stop", sb.Name}, Background}, true
	case "r":
		if startable(sb.State) {
			return Action{[]string{prog, "start", sb.Name}, Terminal}, true
		}
		return Action{[]string{prog, "restart", sb.Name}, Background}, true
	}
	return Action{}, false
}

// startable: a sandbox in this state is started, not restarted.
func startable(state string) bool {
	return state == "stopped" || strings.HasPrefix(state, "start failed")
}

// deleteAction is "d" once its name was typed.
func deleteAction(prog, name string) Action {
	return Action{[]string{prog, "rm", name, "--yes"}, Background}
}

// newAction is "n": a name, and a size or "" for the platform's default.
func newAction(prog, name, size string) Action {
	args := []string{prog, "new", name}
	if size != "" {
		args = append(args, "--size", size)
	}
	return Action{args, Terminal}
}

// setupAction is the "trajrl setup ..." line pasted on first use: the
// words of that line, run as they are. Only a setup line is taken.
func setupAction(prog, line string) (Action, error) {
	words, err := SplitLine(strings.TrimSpace(line))
	if err != nil {
		return Action{}, err
	}
	if len(words) < 2 || words[0] != prog || words[1] != "setup" {
		return Action{}, errors.New("that is not a " + prog + " setup line: copy it from the website's Settings page")
	}
	return Action{words, Terminal}, nil
}

// JoinLine is argv as one shell command line: a word with anything but
// [A-Za-z0-9@%+=:,./_-] is single-quoted.
func JoinLine(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = quote(a)
	}
	return strings.Join(q, " ")
}

func quote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./_-", r)) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

// SplitLine splits a command line as a POSIX shell would split a simple
// command: words split by blanks, single quotes literal, double quotes
// with \" \\ \$ \` escapes, a backslash outside quotes escaping the next
// character. Anything a shell would expand ($, `, globs, ;, |, &, <, >,
// parentheses) is refused rather than taken literally.
func SplitLine(s string) ([]string, error) {
	var words []string
	var w strings.Builder
	in := false
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == ' ' || r == '\t':
			if in {
				words = append(words, w.String())
				w.Reset()
				in = false
			}
		case r == '\'':
			in = true
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j == len(rs) {
				return nil, errors.New("a quote is not closed")
			}
			w.WriteString(string(rs[i+1 : j]))
			i = j
		case r == '"':
			in = true
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				switch {
				case rs[j] == '\\' && j+1 < len(rs) && strings.ContainsRune("\"\\$`", rs[j+1]):
					j++
					w.WriteRune(rs[j])
				case rs[j] == '$' || rs[j] == '`':
					return nil, errors.New("the line has a shell expansion: paste it as the website gives it")
				default:
					w.WriteRune(rs[j])
				}
			}
			if j == len(rs) {
				return nil, errors.New("a quote is not closed")
			}
			i = j
		case r == '\\':
			if i+1 == len(rs) {
				return nil, errors.New("the line ends in a backslash")
			}
			in = true
			i++
			w.WriteRune(rs[i])
		case strings.ContainsRune("$`*?[]{}~;|&<>()#\n\r", r):
			return nil, errors.New("the line has shell syntax (" + string(r) + "): paste it as the website gives it")
		default:
			in = true
			w.WriteRune(r)
		}
	}
	if in {
		words = append(words, w.String())
	}
	return words, nil
}

package main

import (
	"os"

	"golang.org/x/term"

	"github.com/hanlinai/trajrl-cli/internal/tui"
)

// noArgs is trajrl with no arguments: the interactive screen when stdin
// and stdout are a terminal (and TRAJRL_NO_TUI is not set); otherwise, for
// an agent, a pipe or CI, the command table, exit 0, and never a terminal
// control sequence.
func noArgs() int {
	if v := os.Getenv("TRAJRL_NO_TUI"); (v == "" || v == "0") && interactive() {
		return runTUI()
	}
	help(os.Stdout)
	return 0
}

// tuiCmd is "tui": the screen, asked for by name. Without a terminal it
// refuses and says what an agent uses instead.
func tuiCmd(args []string) int {
	if len(args) != 1 {
		return fail(2, "usage: %s tui", prog)
	}
	if !interactive() {
		return fail(2, "tui needs a terminal on stdin and stdout; scripts and agents use: %s status --json, and the commands of %s help", prog, prog)
	}
	return runTUI()
}

// interactive: stdin and stdout are a terminal a screen can be drawn on.
func interactive() bool {
	return os.Getenv("TERM") != "dumb" && term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// runTUI shows the screen. Its data is loadStatus's, the details the entry
// point's "show NAME --json", and every key runs trajrl itself again.
func runTUI() int {
	self, err := os.Executable()
	if err != nil {
		return fail(1, "%v", err)
	}
	cmds := make([]tui.Command, len(Commands))
	for i, c := range Commands {
		cmds[i] = tui.Command{Name: c.Name, Usage: c.Usage, Help: c.Help}
	}
	err = tui.Run(tui.Options{
		Prog:     prog,
		Commands: cmds,
		Load:     loadStatus,
		Show: func(name string) ([]byte, error) {
			c, err := loadConfig()
			if err != nil {
				return nil, err
			}
			return entryOutput(c, "show", name, "--json")
		},
		Runner: tui.ExecRunner{Self: self},
		Flags:  screenFlags,
		Copy:   tui.CopyOSC52,
	})
	if err != nil {
		return fail(1, "%v", err)
	}
	return 0
}

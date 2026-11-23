package tui

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"
)

// Run shows the screen until the user quits. The caller has checked that
// stdin and stdout are a terminal.
func Run(o Options) error {
	_, err := tea.NewProgram(New(o), tea.WithAltScreen()).Run()
	return err
}

// ExecRunner runs an action as a child process of the program at Self
// (trajrl itself), with the action's arguments after its name.
type ExecRunner struct{ Self string }

func (r ExecRunner) Run(a Action) tea.Cmd {
	if a.Mode == Terminal {
		h := &handover{self: r.Self, a: a}
		return tea.Exec(h, func(err error) tea.Msg { return DoneMsg{Action: a, Code: h.code, Err: err} })
	}
	return func() tea.Msg {
		cmd := exec.Command(r.Self, a.Args[1:]...)
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code, err = ee.ExitCode(), nil
		}
		return DoneMsg{Action: a, Output: string(out), Code: code, Err: err}
	}
}

// handover is a command given the terminal while the screen is paused: it
// shows its command line first, and at its end waits for enter, so what
// it printed can be read before the screen comes back.
type handover struct {
	self     string
	a        Action
	in       io.Reader
	out, err io.Writer
	code     int
}

func (h *handover) SetStdin(r io.Reader)  { h.in = r }
func (h *handover) SetStdout(w io.Writer) { h.out = w }
func (h *handover) SetStderr(w io.Writer) { h.err = w }

func (h *handover) Run() error {
	fmt.Fprintf(h.out, "$ %s\n", h.a.Line())
	cmd := exec.Command(h.self, h.a.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = h.in, h.out, h.err
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		h.code, err = ee.ExitCode(), nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(h.out, "\n%s: exit status %d. Press enter to go back.", h.a.Args[0], h.code)
	bufio.NewReader(h.in).ReadString('\n')
	return nil
}

// CopyOSC52 puts line on the clipboard of the terminal the screen is in,
// over SSH too, with the OSC 52 sequence.
func CopyOSC52(line string) error {
	_, err := fmt.Fprintf(os.Stdout, "\x1b]52;c;%s\a", base64.StdEncoding.EncodeToString([]byte(line)))
	return err
}

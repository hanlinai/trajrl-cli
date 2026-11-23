package tui

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

var update = flag.Bool("update", false, "write the golden screens in testdata/")

func TestMain(m *testing.M) {
	// No colour, and times as UTC: the screens are the same everywhere.
	lipgloss.SetColorProfile(termenv.Ascii)
	time.Local = time.UTC
	os.Exit(m.Run())
}

// fakeRunner records the actions it is asked to run and runs none.
type fakeRunner struct{ ran []Action }

func (r *fakeRunner) Run(a Action) tea.Cmd { r.ran = append(r.ran, a); return nil }

func (r *fakeRunner) lines() []string {
	var l []string
	for _, a := range r.ran {
		l = append(l, a.Line())
	}
	return l
}

var verified = time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

// fixedStatus is the status every screen test shows.
func fixedStatus() Status {
	return Status{Configured: true, Entry: "entry.example:2222", Sandboxes: []Sandbox{
		{Name: "web", ID: "sbx-1", State: "waiting for its owner's key", Size: "small", WaitingForKey: true,
			URL: "https://web.sbx.example", Next: "trajrl unlock web"},
		{Name: "api", ID: "sbx-2", State: "running", Size: "medium", VerifiedHostKey: true, LastVerified: &verified,
			URL: "https://api.sbx.example"},
		{Name: "db", ID: "sbx-3", State: "running", Size: "large", URL: "https://db.sbx.example", Next: "trajrl verify db"},
		{Name: "old", ID: "sbx-4", State: "stopped", Size: "small"},
	}}
}

const showWeb = `{"name":"web","id":"sbx-1","state":"waiting for its owner's key","size":"small","vcpus":2,"memory_gib":4,"disk_gib":20,"created":"2026-11-18T09:30:00Z","public":true,"https_url":"https://web.sbx.example","tags":["demo"],"boots":1}`

var commands = []Command{
	{"setup", "...", "set this machine up"},
	{"status", "[--json]", "your sandboxes, and the command to run next"},
	{"verify", "NAME", "check a running sandbox from here"},
}

// newModel is the screen with st loaded, w by h, its runner and the
// clipboard recorded.
func newModel(t *testing.T, st Status, w, h int) (*Model, *fakeRunner, *[]string) {
	t.Helper()
	r := &fakeRunner{}
	var copied []string
	rd := lipgloss.NewRenderer(io.Discard)
	rd.SetColorProfile(termenv.Ascii)
	m := New(Options{
		Prog: "trajrl", Commands: commands, Runner: r, Renderer: rd,
		Load: func() (Status, error) { return st, nil },
		Show: func(name string) ([]byte, error) { return []byte(showWeb), nil },
		Copy: func(l string) error { copied = append(copied, l); return nil },
	})
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	m.Update(statusMsg{st: st})
	return m, r, &copied
}

// keys presses each key: a name of Bubble Tea's ("enter", "esc", "up")
// or text, typed rune by rune.
func keys(m *Model, ks ...string) {
	special := map[string]tea.KeyType{"enter": tea.KeyEnter, "esc": tea.KeyEsc, "up": tea.KeyUp, "down": tea.KeyDown, "backspace": tea.KeyBackspace}
	for _, k := range ks {
		if kt, ok := special[k]; ok {
			feed(m, tea.KeyMsg{Type: kt})
			continue
		}
		for _, r := range k {
			feed(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		}
	}
}

// feed gives the screen one message. The commands it returns are not run
// (a cursor's blink waits), except the details' show, given at once.
func feed(m *Model, msg tea.Msg) {
	m.Update(msg)
	if m.scr == scrDetail && m.detail == nil && m.detailErr == "" {
		raw, err := m.o.Show(m.detailName)
		m.Update(showMsg{m.detailName, raw, err})
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs from %s:\n--- got ---\n%s\n--- want ---\n%s", name, path, got, want)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("%s: an escape sequence with colour off", name)
	}
	lines := strings.Split(got, "\n")
	w := 80
	if strings.HasSuffix(name, "-50") {
		w = 50
	}
	if len(lines) != 24 {
		t.Errorf("%s: %d lines, not 24", name, len(lines))
	}
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			t.Errorf("%s: line %d is %d columns wide, more than %d: %q", name, i+1, lipgloss.Width(l), w, l)
		}
	}
}

func TestScreens(t *testing.T) {
	for _, w := range []int{80, 50} {
		sfx := "-" + map[int]string{80: "80", 50: "50"}[w]
		t.Run("list"+sfx, func(t *testing.T) {
			m, _, _ := newModel(t, fixedStatus(), w, 24)
			golden(t, "list"+sfx, m.View())
		})
		t.Run("detail"+sfx, func(t *testing.T) {
			m, _, _ := newModel(t, fixedStatus(), w, 24)
			keys(m, "enter")
			golden(t, "detail"+sfx, m.View())
		})
		t.Run("first-use"+sfx, func(t *testing.T) {
			m, _, _ := newModel(t, Status{Message: "this machine is not set up"}, w, 24)
			golden(t, "first-use"+sfx, m.View())
		})
		t.Run("help"+sfx, func(t *testing.T) {
			m, _, _ := newModel(t, fixedStatus(), w, 24)
			keys(m, "?")
			golden(t, "help"+sfx, m.View())
		})
	}
}

// Each key gives the command of item 19, shown at the bottom before it
// runs, and runs it the way item 18 says.
func TestKeys(t *testing.T) {
	cases := []struct {
		name  string
		press []string
		want  string
		mode  Mode
	}{
		{"unlock", []string{"u"}, "trajrl unlock web", Terminal},
		{"ssh", []string{"s"}, "trajrl ssh web", Terminal},
		{"verify", []string{"down", "down", "v"}, "trajrl verify db", Background},
		{"stop", []string{"j", "x"}, "trajrl stop api", Background},
		{"restart running", []string{"j", "r"}, "trajrl restart api", Background},
		{"start stopped", []string{"j", "j", "j", "r"}, "trajrl start old", Terminal},
		{"k back up", []string{"j", "j", "k", "u"}, "trajrl unlock api", Terminal},
		{"from the details", []string{"j", "j", "enter", "v"}, "trajrl verify db", Background},
		{"new", []string{"n", "box", "enter", "medium", "enter"}, "trajrl new box --size medium", Terminal},
		{"new, default size", []string{"n", "box", "enter", "enter"}, "trajrl new box", Terminal},
		{"delete", []string{"j", "d", "api", "enter"}, "trajrl rm api --yes", Background},
		{"delete in the details", []string{"enter", "d", "web", "enter"}, "trajrl rm web --yes", Background},
		{"filter then act", []string{"/", "ol", "enter", "r"}, "trajrl start old", Terminal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, r, _ := newModel(t, fixedStatus(), 80, 24)
			keys(m, c.press...)
			if len(r.ran) != 1 || r.ran[0].Line() != c.want || r.ran[0].Mode != c.mode {
				t.Fatalf("ran %q (%v), want only %q (mode %v)", r.lines(), r.ran, c.want, c.mode)
			}
			if !strings.Contains(m.View(), "$ "+c.want) {
				t.Errorf("the command line is not shown at the bottom:\n%s", m.View())
			}
		})
	}
}

// Options.Flags (a rehearsal build's -dev-insecure-rehearsal) go after the
// command word of the commands they name, as run, shown and copied; the
// other commands are as they were.
func TestFlags(t *testing.T) {
	flags := map[string][]string{"unlock": {"-x"}, "start": {"-x"}, "new": {"-x"}, "verify": {"-x"}}
	for _, c := range []struct {
		press []string
		want  string
	}{
		{[]string{"u"}, "trajrl unlock -x web"},
		{[]string{"n", "box", "enter", "medium", "enter"}, "trajrl new -x box --size medium"},
		{[]string{"/", "ol", "enter", "r"}, "trajrl start -x old"},
		{[]string{"j", "r"}, "trajrl restart api"},
		{[]string{"j", "j", "v"}, "trajrl verify -x db"},
		{[]string{"s"}, "trajrl ssh web"},
	} {
		m, r, _ := newModel(t, fixedStatus(), 80, 24)
		m.o.Flags = flags
		keys(m, c.press...)
		if len(r.ran) != 1 || r.ran[0].Line() != c.want || !strings.Contains(m.View(), "$ "+c.want) {
			t.Errorf("%q ran %q, want %q", c.press, r.lines(), c.want)
		}
	}
	m, _, _ := newModel(t, fixedStatus(), 80, 24)
	m.o.Flags = flags
	keys(m, "enter")
	if v := m.View(); !strings.Contains(v, "u  trajrl unlock -x web") || !strings.Contains(v, "s  trajrl ssh web") {
		t.Errorf("the details do not show the flags:\n%s", v)
	}
}

// d runs nothing unless the sandbox's name is typed exactly.
func TestDeleteNeedsTheName(t *testing.T) {
	for _, typed := range [][]string{{"enter"}, {"we", "enter"}, {"web2", "enter"}, {"WEB", "enter"}, {" ", "enter"}, {"web", "esc"}, {"api", "enter"}} {
		m, r, _ := newModel(t, fixedStatus(), 80, 24)
		keys(m, "d")
		keys(m, typed...)
		if len(r.ran) != 0 {
			t.Errorf("d then %q ran %q", typed, r.lines())
		}
		if strings.Contains(m.View(), "rm web") {
			t.Errorf("d then %q shows a delete command:\n%s", typed, m.View())
		}
	}
}

// Keys that are no action run nothing; the help screen acts on nothing.
func TestNoActionKeys(t *testing.T) {
	m, r, _ := newModel(t, fixedStatus(), 80, 24)
	keys(m, "a", "z", "?", "u", "s", "v", "x", "r", "esc", "n", "esc", "/", "zz", "esc")
	if len(r.ran) != 0 {
		t.Errorf("ran %q", r.lines())
	}
	// Not set up: only the pasted setup line runs.
	m, r, _ = newModel(t, Status{}, 80, 24)
	keys(m, "u", "v", "enter")
	if len(r.ran) != 0 {
		t.Errorf("not set up, ran %q", r.lines())
	}
}

func TestCopy(t *testing.T) {
	m, _, copied := newModel(t, fixedStatus(), 80, 24)
	keys(m, "c")
	m.Update(DoneMsg{})
	keys(m, "j", "j", "x", "c")
	want := []string{"trajrl unlock web", "trajrl stop db"}
	if strings.Join(*copied, "|") != strings.Join(want, "|") {
		t.Errorf("copied %q, want %q", *copied, want)
	}
	m, _, copied = newModel(t, fixedStatus(), 80, 24)
	keys(m, "j", "c")
	if len(*copied) != 0 || !strings.Contains(m.View(), "no command to copy") {
		t.Errorf("api has no next command, copied %q", *copied)
	}
	m.o.Copy = func(string) error { return errors.New("no clipboard") }
	keys(m, "u", "c")
	if !strings.Contains(m.View(), "not copied: no clipboard") {
		t.Errorf("a failed copy is not said:\n%s", m.View())
	}
}

func TestFirstUseRunsTheSetupLine(t *testing.T) {
	line := `trajrl setup -entry entry.example:2222 -entry-key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB+x/y='`
	m, r, _ := newModel(t, Status{Message: "not set up"}, 80, 24)
	keys(m, line, "enter")
	want := []string{"trajrl", "setup", "-entry", "entry.example:2222", "-entry-key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB+x/y="}
	if len(r.ran) != 1 || strings.Join(r.ran[0].Args, "\x00") != strings.Join(want, "\x00") || r.ran[0].Mode != Terminal {
		t.Fatalf("ran %#v", r.ran)
	}
	if r.ran[0].Line() != line {
		t.Errorf("shown as %q, pasted %q", r.ran[0].Line(), line)
	}
	for _, bad := range []string{"trajrl rm web --yes", "ssh entry setup", "trajrl setup $(curl x)", "trajrl setup -entry x; rm -rf ~", "trajrl setup 'open"} {
		m, r, _ := newModel(t, Status{Message: "not set up"}, 80, 24)
		keys(m, bad, "enter")
		if len(r.ran) != 0 {
			t.Errorf("%q ran %q", bad, r.lines())
		}
	}
}

func TestSplitAndJoin(t *testing.T) {
	for _, args := range [][]string{
		{"trajrl", "unlock", "web"},
		{"trajrl", "setup", "-entry", "h:22", "-entry-key", "ssh-ed25519 AAAA+/="},
		{"trajrl", "new", "it's", ""},
	} {
		got, err := SplitLine(JoinLine(args))
		if err != nil || strings.Join(got, "\x00") != strings.Join(args, "\x00") {
			t.Errorf("%q: %q, %v", args, got, err)
		}
	}
	got, err := SplitLine(`a "b c" d\ e 'f"g'`)
	if err != nil || strings.Join(got, "|") != `a|b c|d e|f"g` {
		t.Errorf("got %q, %v", got, err)
	}
}

// The results panel shows a background command's output, and a verify's
// last line goes to the details.
func TestResultsPanel(t *testing.T) {
	m, r, _ := newModel(t, fixedStatus(), 80, 24)
	keys(m, "j", "j", "v")
	if !strings.Contains(m.View(), "$ trajrl verify db  (running)") {
		t.Errorf("no running panel:\n%s", m.View())
	}
	m.Update(DoneMsg{Action: r.ran[0], Output: "checking db\nVERIFIED db\n", Code: 0})
	v := m.View()
	if !strings.Contains(v, "$ trajrl verify db  (exit status 0)") || !strings.Contains(v, "VERIFIED db") {
		t.Errorf("no result:\n%s", v)
	}
	keys(m, "enter")
	if !strings.Contains(m.View(), "this session: VERIFIED db (exit status 0)") {
		t.Errorf("the details do not show the session's check:\n%s", m.View())
	}
	if len(strings.Split(m.View(), "\n")) != 24 {
		t.Errorf("not 24 lines")
	}
}

// A load that fails keeps the last list and says why; it is never the
// first-use screen.
func TestLoadError(t *testing.T) {
	m, _, _ := newModel(t, fixedStatus(), 80, 24)
	m.Update(statusMsg{err: errors.New("the entry point: connection refused")})
	v := m.View()
	if !strings.Contains(v, "web") || !strings.Contains(v, "connection refused") {
		t.Errorf("%s", v)
	}
	m2 := New(Options{Prog: "trajrl", Runner: &fakeRunner{}})
	m2.Update(statusMsg{err: errors.New("connection refused")})
	if v := m2.View(); strings.Contains(v, "not set up") || !bytes.Contains([]byte(v), []byte("could not be loaded")) {
		t.Errorf("%s", v)
	}
}

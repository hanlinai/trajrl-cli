package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Options are what the screen is given: where its data comes from and how
// it runs a command. cmd/trajrl fills them in; the tests give fixed ones.
type Options struct {
	// Prog is the program's name, the first word of every command line.
	Prog string
	// Commands is the command table, for the help screen.
	Commands []Command
	// Load is "trajrl status": the data of the list.
	Load func() (Status, error)
	// Show is the entry point's "show NAME --json", for the details.
	Show func(name string) ([]byte, error)
	// Runner runs an action's command.
	Runner Runner
	// Copy puts a command line on the clipboard.
	Copy func(line string) error
	// Flags are added after the command word of the commands the screen
	// runs and shows, by command ("unlock": its flags). cmd/trajrl gives
	// none, except in a rehearsal build started for the rehearsal.
	Flags map[string][]string
	// Every is how often the list is refreshed (default 10s).
	Every time.Duration
	// Renderer styles the screen (default: lipgloss's, which follows the
	// terminal and NO_COLOR).
	Renderer *lipgloss.Renderer
}

// Runner runs an action's command. The command it returns ends with a
// DoneMsg.
type Runner interface {
	Run(a Action) tea.Cmd
}

// DoneMsg is the end of an action's command: its output (Background
// only), its exit status, or Err if it could not be run at all.
type DoneMsg struct {
	Action Action
	Output string
	Code   int
	Err    error
}

type statusMsg struct {
	st  Status
	err error
}

type showMsg struct {
	name string
	raw  []byte
	err  error
}

type tickMsg struct{}

type screen int

const (
	scrList screen = iota
	scrDetail
	scrHelp
)

type inputKind int

const (
	inNone inputKind = iota
	inFilter
	inNewName
	inNewSize
	inDelete
	inSetup
)

// Model is the screen's state. Its Update and View are Bubble Tea's.
type Model struct {
	o  Options
	st styles

	w, h int

	status  Status
	loaded  bool
	loadErr string
	sel     int
	selName string
	filter  string

	scr        screen
	detailName string
	detail     []byte
	detailErr  string
	off        int // scroll of the details and help

	input   inputKind
	ti      textinput.Model
	newName string
	delName string

	current string // the command line at the bottom
	msg     string // one line: what happened
	msgErr  bool

	panel      viewport.Model
	panelOn    bool
	panelTitle string
	running    int
	// checked is the last line of this session's "verify NAME", by name.
	checked map[string]string
}

type styles struct {
	header, sel, colHead, warn, ok, bad, dim, cmd lipgloss.Style
}

// New is the screen with nothing loaded yet; Init loads it.
func New(o Options) *Model {
	if o.Every == 0 {
		o.Every = 10 * time.Second
	}
	r := o.Renderer
	if r == nil {
		r = lipgloss.DefaultRenderer()
	}
	m := &Model{o: o, w: 80, h: 24, checked: map[string]string{}}
	m.st = styles{
		header:  r.NewStyle().Bold(true),
		sel:     r.NewStyle().Reverse(true),
		colHead: r.NewStyle().Faint(true),
		warn:    r.NewStyle().Foreground(lipgloss.Color("3")).Bold(true),
		ok:      r.NewStyle().Foreground(lipgloss.Color("2")),
		bad:     r.NewStyle().Foreground(lipgloss.Color("1")),
		dim:     r.NewStyle().Faint(true),
		cmd:     r.NewStyle().Foreground(lipgloss.Color("6")),
	}
	m.ti = textinput.New()
	m.panel = viewport.New(m.w, 6)
	return m
}

func (m *Model) Init() tea.Cmd { return tea.Batch(m.load(), m.tick()) }

func (m *Model) load() tea.Cmd {
	return func() tea.Msg {
		st, err := m.o.Load()
		return statusMsg{st, err}
	}
}

func (m *Model) tick() tea.Cmd {
	return tea.Tick(m.o.Every, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *Model) show(name string) tea.Cmd {
	return func() tea.Msg {
		raw, err := m.o.Show(name)
		return showMsg{name, raw, err}
	}
}

// visible are the sandboxes the filter lets through.
func (m *Model) visible() []Sandbox {
	if m.filter == "" {
		return m.status.Sandboxes
	}
	var v []Sandbox
	for _, s := range m.status.Sandboxes {
		if strings.Contains(s.Name, m.filter) {
			v = append(v, s)
		}
	}
	return v
}

func (m *Model) selected() *Sandbox {
	v := m.visible()
	if m.sel < 0 || m.sel >= len(v) {
		return nil
	}
	return &v[m.sel]
}

// target is the sandbox an action key acts on: the one in the details, or
// the one selected in the list.
func (m *Model) target() *Sandbox {
	switch m.scr {
	case scrDetail:
		for _, s := range m.status.Sandboxes {
			if s.Name == m.detailName {
				return &s
			}
		}
		return &Sandbox{Name: m.detailName}
	case scrList:
		return m.selected()
	}
	return nil
}

func (m *Model) setSel(i int) {
	v := m.visible()
	if i >= len(v) {
		i = len(v) - 1
	}
	if i < 0 {
		i = 0
	}
	m.sel = i
	m.selName = ""
	if i < len(v) {
		m.selName = v[i].Name
	}
	m.current = ""
}

func (m *Model) say(err bool, format string, a ...any) {
	m.msg, m.msgErr = fmt.Sprintf(format, a...), err
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case statusMsg:
		if msg.err != nil {
			m.loadErr = msg.err.Error()
			return m, nil
		}
		m.loaded, m.loadErr = true, ""
		m.status = msg.st
		sel := 0
		for i, s := range m.visible() {
			if s.Name == m.selName {
				sel = i
			}
		}
		cur := m.current
		m.setSel(sel)
		m.current = cur
		if !m.status.Configured && m.input == inNone {
			return m, m.ask(inSetup, "setup> ", "")
		}
		if m.status.Configured && m.input == inSetup {
			m.input = inNone
		}
		return m, nil
	case tickMsg:
		return m, tea.Batch(m.load(), m.tick())
	case showMsg:
		if msg.name == m.detailName {
			m.detail, m.detailErr = msg.raw, ""
			if msg.err != nil {
				m.detailErr = msg.err.Error()
			}
		}
		return m, nil
	case DoneMsg:
		return m, m.done(msg)
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.input != inNone {
			return m, m.key(msg)
		}
		return m, m.press(msg.String())
	}
	if m.input != inNone {
		var c tea.Cmd
		m.ti, c = m.ti.Update(msg)
		return m, c
	}
	return m, nil
}

// done is an action's command ended: say so, and load the list again.
func (m *Model) done(d DoneMsg) tea.Cmd {
	line := d.Action.Line()
	end := fmt.Sprintf("exit status %d", d.Code)
	if d.Err != nil {
		end = d.Err.Error()
	}
	if d.Action.Mode == Background {
		m.running--
		out := strings.TrimRight(d.Output, "\n")
		m.panelTitle = "$ " + line + "  (" + end + ")"
		m.panel.SetContent(out)
		m.panel.GotoTop()
		if len(d.Action.Args) == 3 && d.Action.Args[1] == "verify" {
			last := ""
			for _, l := range strings.Split(out, "\n") {
				if strings.TrimSpace(l) != "" {
					last = strings.TrimSpace(l)
				}
			}
			m.checked[d.Action.Args[2]] = fmt.Sprintf("%s (%s)", last, end)
		}
	}
	m.say(d.Code != 0 || d.Err != nil, "%s: %s", line, end)
	cmds := []tea.Cmd{m.load()}
	if m.scr == scrDetail {
		cmds = append(cmds, m.show(m.detailName))
	}
	return tea.Batch(cmds...)
}

// withFlags is a with Options.Flags for its command after the command word.
func (m *Model) withFlags(a Action) Action {
	if len(a.Args) < 2 || len(m.o.Flags[a.Args[1]]) == 0 {
		return a
	}
	args := append([]string{a.Args[0], a.Args[1]}, m.o.Flags[a.Args[1]]...)
	a.Args = append(args, a.Args[2:]...)
	return a
}

// run shows a's command line, then runs it.
func (m *Model) run(a Action) tea.Cmd {
	a = m.withFlags(a)
	m.current = a.Line()
	m.msg = ""
	if a.Mode == Background {
		m.running++
		m.panelOn = true
		m.panelTitle = "$ " + m.current + "  (running)"
		m.panel.SetContent("")
	}
	return m.o.Runner.Run(a)
}

func (m *Model) ask(k inputKind, prompt, value string) tea.Cmd {
	m.input = k
	m.ti.Reset()
	m.ti.Prompt = prompt
	m.ti.SetValue(value)
	return m.ti.Focus()
}

// key is a key while a question is asked.
func (m *Model) key(k tea.KeyMsg) tea.Cmd {
	switch k.String() {
	case "esc":
		if m.input == inSetup {
			return nil
		}
		if m.input == inFilter {
			m.filter = ""
			m.setSel(0)
		}
		if m.input == inDelete {
			m.say(false, "not deleted")
		}
		m.input = inNone
		m.ti.Blur()
		return nil
	case "enter":
		v := strings.TrimSpace(m.ti.Value())
		kind := m.input
		m.input = inNone
		m.ti.Blur()
		switch kind {
		case inFilter:
			m.filter = v
			m.setSel(0)
		case inNewName:
			if v == "" {
				m.say(false, "no new sandbox")
				return nil
			}
			m.newName = v
			return m.ask(inNewSize, "size (enter: the default)> ", "")
		case inNewSize:
			return m.run(newAction(m.o.Prog, m.newName, v))
		case inDelete:
			if v == "" || v != m.delName {
				m.say(true, "not deleted: type %s exactly to delete it", m.delName)
				return nil
			}
			return m.run(deleteAction(m.o.Prog, m.delName))
		case inSetup:
			a, err := setupAction(m.o.Prog, v)
			if err != nil {
				m.say(true, "%v", err)
				return m.ask(inSetup, "setup> ", v)
			}
			return m.run(a)
		}
		return nil
	}
	var c tea.Cmd
	m.ti, c = m.ti.Update(k)
	if m.input == inFilter {
		m.filter = strings.TrimSpace(m.ti.Value())
		m.setSel(0)
	}
	return c
}

// press is a key on the list, the details or the help.
func (m *Model) press(k string) tea.Cmd {
	switch k {
	case "q":
		return tea.Quit
	case "?":
		m.scr, m.off = scrHelp, 0
		return nil
	case "esc", "backspace":
		if m.scr != scrList {
			m.scr, m.off = scrList, 0
			return nil
		}
		if m.panelOn {
			m.panelOn = false
			return nil
		}
		if m.filter != "" {
			m.filter = ""
			m.setSel(0)
		}
		return nil
	case "up", "k":
		if m.scr == scrList {
			m.setSel(m.sel - 1)
		} else if m.off > 0 {
			m.off--
		}
		return nil
	case "down", "j":
		switch m.scr {
		case scrList:
			m.setSel(m.sel + 1)
		case scrHelp:
			m.off = min(m.off+1, max(0, len(m.helpLines())-1))
		case scrDetail:
			m.off = min(m.off+1, max(0, len(m.detailLines())-1))
		}
		return nil
	case "pgup":
		m.panel.ViewUp()
		return nil
	case "pgdown":
		m.panel.ViewDown()
		return nil
	case "R":
		m.say(false, "refreshing")
		return m.load()
	case "c":
		line := m.current
		if line == "" {
			if t := m.target(); t != nil {
				line = t.Next
			}
		}
		if line == "" {
			m.say(true, "no command to copy")
			return nil
		}
		if err := m.o.Copy(line); err != nil {
			m.say(true, "not copied: %v", err)
			return nil
		}
		m.say(false, "copied: %s", line)
		return nil
	}
	if m.scr == scrHelp || !m.loaded || !m.status.Configured {
		return nil
	}
	switch k {
	case "enter":
		if s := m.selected(); s != nil && m.scr == scrList {
			m.scr, m.off = scrDetail, 0
			m.detailName, m.detail, m.detailErr = s.Name, nil, ""
			return m.show(s.Name)
		}
		return nil
	case "/":
		if m.scr == scrList {
			return m.ask(inFilter, "/", m.filter)
		}
		return nil
	case "n":
		return m.ask(inNewName, "name of the new sandbox> ", "")
	case "d":
		if t := m.target(); t != nil {
			m.delName = t.Name
			m.current = ""
			return m.ask(inDelete, fmt.Sprintf("type %s to delete it for good> ", t.Name), "")
		}
		return nil
	}
	if t := m.target(); t != nil {
		if a, ok := actionFor(m.o.Prog, k, *t); ok {
			return m.run(a)
		}
	}
	return nil
}

// --- the view ----------------------------------------------------------------

func (m *Model) View() string {
	var top []string
	head := m.o.Prog
	switch {
	case !m.loaded:
	case !m.status.Configured:
		head += "  not set up"
	default:
		head += fmt.Sprintf("  %s  %d sandboxes", m.status.Entry, len(m.status.Sandboxes))
		if m.filter != "" {
			head += fmt.Sprintf("  filter %q", m.filter)
		}
		if m.running > 0 {
			head += fmt.Sprintf("  %d running", m.running)
		}
	}
	top = append(top, m.st.header.Render(cut(head, m.w)))

	foot := m.footer()
	var panel []string
	if m.panelOn && m.scr == scrList {
		ph := 6
		if m.h < 20 {
			ph = max(2, m.h/4)
		}
		m.panel.Width, m.panel.Height = m.w, ph
		panel = append(panel, m.st.dim.Render(cut("── "+m.panelTitle+" ", m.w)))
		panel = append(panel, strings.Split(m.panel.View(), "\n")...)
	}
	bodyH := m.h - len(top) - len(panel) - len(foot)
	var body []string
	switch {
	case m.scr == scrHelp:
		body = scroll(m.helpLines(), m.off, bodyH)
	case !m.loaded && m.loadErr != "":
		body = []string{"The list could not be loaded (below). R tries again."}
	case !m.loaded:
		body = []string{"loading..."}
	case !m.status.Configured:
		body = m.firstUse()
	case m.scr == scrDetail:
		body = scroll(m.detailLines(), m.off, bodyH)
	default:
		body = m.list(bodyH)
	}
	lines := append(top, body...)
	for len(lines) < m.h-len(panel)-len(foot) {
		lines = append(lines, "")
	}
	lines = lines[:max(0, m.h-len(panel)-len(foot))]
	lines = append(lines, panel...)
	lines = append(lines, foot...)
	return strings.Join(lines, "\n")
}

// footer is three lines: the question asked or what happened, the
// command line, the keys.
func (m *Model) footer() []string {
	var a string
	switch {
	case m.input != inNone:
		m.ti.Width = max(1, m.w-lipgloss.Width(m.ti.Prompt)-1)
		a = m.ti.View()
	case m.loadErr != "":
		a = m.st.bad.Render(cut(m.loadErr, m.w))
	case m.msg != "":
		s := m.st.dim
		if m.msgErr {
			s = m.st.bad
		}
		a = s.Render(cut(m.msg, m.w))
	}
	var b string
	switch {
	case m.current != "":
		b = m.st.cmd.Render(cut("$ "+m.current, m.w))
	default:
		if t := m.target(); t != nil && t.Next != "" && m.loaded && m.status.Configured {
			b = m.st.cmd.Render(cut("next: "+t.Next, m.w))
		}
	}
	var keys string
	switch {
	case m.loaded && !m.status.Configured && m.scr != scrHelp:
		keys = "enter run  ctrl+c quit"
	case m.scr == scrHelp:
		keys = "j k scroll  esc back  q quit"
	case m.scr == scrDetail:
		keys = "u s v x r d act  c copy  j k scroll  esc back  ? help  q quit"
	default:
		keys = "enter details  n new  u s v x r d act  c copy  / filter  ? help  q quit"
	}
	return []string{a, b, m.st.dim.Render(cut(keys, m.w))}
}

// list is the list of sandboxes in h lines: the columns of the spec, only
// name and state below 60 columns.
func (m *Model) list(h int) []string {
	var out []string
	if m.loadErr != "" && len(m.status.Sandboxes) == 0 {
		return []string{"The list could not be loaded (below). R tries again."}
	}
	v := m.visible()
	if len(v) == 0 {
		if m.filter != "" {
			return []string{fmt.Sprintf("No sandbox matches %q. Esc clears the filter.", m.filter)}
		}
		return []string{"No sandboxes yet. n makes one."}
	}
	wide := m.w >= 60
	nameW, stateW := 4, 5
	for _, s := range v {
		nameW = max(nameW, lipgloss.Width(s.Name))
		stateW = max(stateW, lipgloss.Width(shownState(s)))
	}
	nameW, stateW = min(nameW, 16), min(stateW, 20)
	const sizeW, needW, verW = 7, 9, 8
	urlW := m.w - 2 - nameW - stateW - sizeW - needW - verW - 5
	row := func(name, state, size, need, ver, url string) string {
		if !wide {
			return fmt.Sprintf("%-*s %s", nameW, cut(name, nameW), cut(state, max(1, m.w-3-nameW)))
		}
		return fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %s", nameW, cut(name, nameW), stateW, cut(state, stateW),
			sizeW, cut(size, sizeW), needW, need, verW, ver, cut(url, max(0, urlW)))
	}
	out = append(out, m.st.colHead.Render(strings.TrimRight("  "+row("NAME", "STATE", "SIZE", "NEEDS YOU", "VERIFIED", "URL"), " ")))
	first := 0
	if m.sel >= h-1 {
		first = m.sel - (h - 2)
	}
	for i := first; i < len(v) && len(out) < h; i++ {
		s := v[i]
		need, ver := "", "no"
		if s.WaitingForKey {
			need = "u unlock"
		}
		if s.VerifiedHostKey {
			ver = "yes"
		}
		line := strings.TrimRight(row(s.Name, shownState(s), s.Size, need, ver, strings.TrimPrefix(s.URL, "https://")), " ")
		if i == m.sel {
			out = append(out, m.st.sel.Render(cut("› "+line, m.w)))
			continue
		}
		line = "  " + line
		if s.WaitingForKey {
			line = m.st.warn.Render(cut(line, m.w))
		}
		out = append(out, cut(line, m.w))
	}
	return out
}

// shownState is the state as the list shows it, shorter where it is long.
func shownState(s Sandbox) string {
	if s.WaitingForKey {
		return "waiting for key"
	}
	return s.State
}

// detailLines are "show NAME --json"'s fields, what this machine verified
// and the actions.
func (m *Model) detailLines() []string {
	name := m.detailName
	t := m.target()
	out := []string{m.st.header.Render(name)}
	if t.VerifiedHostKey {
		when := ""
		if t.LastVerified != nil {
			when = ", last " + t.LastVerified.Local().Format("2006-01-02 15:04")
		}
		out = append(out, "  verified here: yes, its host key is on record"+when)
	} else {
		out = append(out, "  verified here: no host key of it yet (v)")
	}
	if c := m.checked[name]; c != "" {
		out = append(out, "  this session: "+c)
	}
	out = append(out, "", m.st.header.Render("Actions"))
	for _, k := range keyActions {
		line := ""
		if a, ok := actionFor(m.o.Prog, k.key, *t); ok {
			line = m.withFlags(a).Line()
		} else if k.key == "d" {
			line = deleteAction(m.o.Prog, name).Line() + "  (once you type " + name + ")"
		}
		out = append(out, fmt.Sprintf("  %s  %s", k.key, line))
	}
	out = append(out, "", m.st.header.Render("show "+name+" --json"))
	switch {
	case m.detailErr != "":
		out = append(out, m.st.bad.Render("  "+m.detailErr))
	case m.detail == nil:
		out = append(out, "  loading...")
	default:
		for _, kv := range fields(m.detail) {
			out = append(out, fmt.Sprintf("  %-12s %s", kv[0], kv[1]))
		}
	}
	for i := range out {
		out[i] = cut(out[i], m.w)
	}
	return out
}

// fields are the top-level fields of a JSON object, in the order a person
// reads them first, then the others by name; values as JSON, strings bare.
func fields(raw []byte) [][2]string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return [][2]string{{"(not JSON)", strings.TrimSpace(string(raw))}}
	}
	order := []string{"name", "id", "state", "reason", "size", "vcpus", "memory_gib", "disk_gib", "image", "created", "https_url", "public", "domains", "ssh_command", "recovered", "notice", "tags", "comment"}
	rank := map[string]int{}
	for i, k := range order {
		rank[k] = i + 1
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := rank[keys[i]], rank[keys[j]]
		switch {
		case ri != 0 && rj != 0:
			return ri < rj
		case ri != 0 || rj != 0:
			return ri != 0
		}
		return keys[i] < keys[j]
	})
	var out [][2]string
	for _, k := range keys {
		v := obj[k]
		var s string
		if json.Unmarshal(v, &s) != nil {
			var b bytes.Buffer
			if json.Compact(&b, v) == nil {
				s = b.String()
			} else {
				s = string(v)
			}
		}
		out = append(out, [2]string{k, strings.ReplaceAll(s, "\n", " ")})
	}
	return out
}

func (m *Model) helpLines() []string {
	p := m.o.Prog
	sb := Sandbox{Name: "NAME", State: "running"}
	stopped := Sandbox{Name: "NAME", State: "stopped"}
	line := func(k string) string { a, _ := actionFor(p, k, sb); return a.Line() }
	start, _ := actionFor(p, "r", stopped)
	out := []string{
		m.st.header.Render("Keys") + " (the command each runs is shown at the bottom first)",
		"  up down j k  move",
		"  enter        details: show NAME --json",
		"  n            " + newAction(p, "NAME", "SIZE").Line() + " (asks both)",
		"  u            " + line("u"),
		"  s            " + line("s"),
		"  v            " + line("v"),
		"  x            " + line("x"),
		"  r            " + start.Line() + " | " + line("r"),
		"  d            " + deleteAction(p, "NAME").Line() + " (once you type NAME)",
		"  c            copy the command at the bottom",
		"  R            refresh now (every 10s anyway)",
		"  /            filter by name",
		"  ? esc q      this help, back, quit",
		"",
		m.st.header.Render("Commands") + " (agents use these and " + p + " status --json, not this screen)",
	}
	for _, c := range m.o.Commands {
		out = append(out, fmt.Sprintf("  %-13s %s", c.Name, c.Help))
	}
	out = append(out, "", fmt.Sprintf("Every other command is the entry point's: %s ls, %s show NAME --json.", p, p))
	for i := range out {
		out[i] = cut(out[i], m.w)
	}
	return out
}

func (m *Model) firstUse() []string {
	p := m.o.Prog
	var out []string
	for _, para := range []string{
		"Welcome to " + p + ".",
		"",
		"This machine is not set up yet. Quit and sign in, in a terminal:",
		"",
		"  " + p + " auth login",
		"",
		"Or paste the line under \"Entry point\" on the website's Settings page below and press enter.",
	} {
		if strings.HasPrefix(para, "  ") {
			out = append(out, cut(para, m.w))
			continue
		}
		out = append(out, wrap(para, m.w)...)
	}
	return out
}

// --- text --------------------------------------------------------------------

// cut is s in at most w columns, "…" where it was cut.
func cut(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// wrap breaks text into lines of at most w columns at spaces.
func wrap(s string, w int) []string {
	if s == "" {
		return []string{""}
	}
	var out []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case lipgloss.Width(line)+1+lipgloss.Width(word) <= w:
			line += " " + word
		default:
			out = append(out, cut(line, w))
			line = word
		}
	}
	return append(out, cut(line, w))
}

// scroll is h lines of lines from off.
func scroll(lines []string, off, h int) []string {
	if off > len(lines)-1 {
		off = max(0, len(lines)-1)
	}
	lines = lines[off:]
	if len(lines) > h {
		lines = lines[:max(0, h)]
	}
	return lines
}

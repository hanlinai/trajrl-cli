package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/tui"
)

// lsAnswer is the entry point's "ls --json" for TestStatus: one sandbox in
// each case status tells apart.
const lsAnswer = `[
{"name":"web","id":"sbx-0000000000000001","state":"waiting for its owner's key","size":"small","disk_gib":20,"created":"2026-11-18T09:30:00Z","public":true,"https_url":"https://web.sbx.example"},
{"name":"api","id":"sbx-0000000000000002","state":"running","reason":"","size":"medium","disk_gib":20,"created":"2026-11-18T09:30:00Z","public":false,"host_key":"ssh-ed25519 PLATFORMSAYS"},
{"name":"db","id":"sbx-0000000000000003","state":"running","size":"large","disk_gib":20,"created":"2026-11-18T09:30:00Z","public":false},
{"name":"own","id":"sbx-0000000000000004","state":"running","size":"small","disk_gib":20,"created":"2026-11-18T09:30:00Z","public":false},
{"name":"rh","id":"sbx-0000000000000005","state":"running","size":"small","disk_gib":20,"created":"2026-11-18T09:30:00Z","public":false},
{"name":"old","id":"sbx-0000000000000006","state":"stopped","reason":"stopped by its owner","size":"small","disk_gib":20,"created":"2026-11-18T09:30:00Z","public":false}
]`

func TestStatus(t *testing.T) {
	e := newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		if cmd != "ls --json" {
			fmt.Fprintf(errw, "unexpected %q\n", cmd)
			return 2
		}
		io.WriteString(out, lsAnswer)
		return 0
	})
	h := newHome(t, e)
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnSandboxHostKeyxxxxxxxxxxxxxxxxxxx"
	t1 := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	// trajrl verify's record: api verified; db's pin is of a sandbox gone
	// (another ID), so db is not.
	pins := map[string]any{"sandboxes": map[string]any{
		"api": map[string]any{"name": "api", "id": "sbx-0000000000000002", "ssh_host_key": key, "verified": t1},
		"db":  map[string]any{"name": "db", "id": "sbx-0000000000000000", "ssh_host_key": key, "verified": t1},
	}}
	writeJSON(t, filepath.Join(h.dir, "xdg", "sbx", "verified.json"), pins)
	// The owner's record: own's boot unlocked after its quote was checked;
	// rh's without a quote (a rehearsal), which vouches for nothing.
	owner := map[string]any{"sandboxes": map[string]any{
		"sbx-0000000000000004": map[string]any{"id": "sbx-0000000000000004", "name": "own", "provisioned": true, "epoch": 1, "ssh_host_key": key, "policy": "base", "updated": t2},
		"sbx-0000000000000005": map[string]any{"id": "sbx-0000000000000005", "name": "rh", "provisioned": true, "epoch": 1, "ssh_host_key": key, "updated": t2},
	}}
	writeJSON(t, filepath.Join(h.sbxkey, "sandboxes.json"), owner)

	out, errs, code := trajrl(t, "", "status", "--json")
	if code != 0 || errs != "" {
		t.Fatalf("status --json: %d %q", code, errs)
	}
	var st tui.Status
	d := json.NewDecoder(strings.NewReader(out))
	d.DisallowUnknownFields()
	if err := d.Decode(&st); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !st.Configured || st.Entry != e.addr || len(st.Sandboxes) != 6 {
		t.Fatalf("%+v", st)
	}
	type want struct {
		waiting, verified bool
		last              *time.Time
		next              string
	}
	wants := map[string]want{
		"web": {true, false, nil, "trajrl unlock web"},
		"api": {false, true, &t1, ""},
		"db":  {false, false, nil, "trajrl verify db"},
		"own": {false, true, &t2, ""},
		"rh":  {false, false, nil, "trajrl verify rh"},
		"old": {false, false, nil, ""},
	}
	for _, s := range st.Sandboxes {
		w := wants[s.Name]
		if s.WaitingForKey != w.waiting || s.VerifiedHostKey != w.verified || s.Next != w.next ||
			(s.LastVerified == nil) != (w.last == nil) || (w.last != nil && !s.LastVerified.Equal(*w.last)) {
			t.Errorf("%s: %+v, want %+v", s.Name, s, w)
		}
	}
	web, old := st.Sandboxes[0], st.Sandboxes[5]
	if web.ID != "sbx-0000000000000001" || web.State != "waiting for its owner's key" || web.Size != "small" || web.URL != "https://web.sbx.example" {
		t.Errorf("web: %+v", web)
	}
	if old.State != "stopped" || old.Reason != "stopped by its owner" {
		t.Errorf("old: %+v", old)
	}
	// Every field is there, next too when empty.
	var raw struct {
		Sandboxes []map[string]any `json:"sandboxes"`
	}
	json.Unmarshal([]byte(out), &raw)
	for _, f := range []string{"name", "id", "state", "size", "waiting_for_key", "verified_host_key", "next"} {
		if _, ok := raw.Sandboxes[5][f]; !ok {
			t.Errorf("old has no %q: %v", f, raw.Sandboxes[5])
		}
	}

	// The plain table says the same.
	out, _, code = trajrl(t, "", "status")
	if code != 0 || !strings.Contains(out, "Next:\n  trajrl unlock web\n  trajrl verify db\n  trajrl verify rh\n") {
		t.Errorf("status: %d\n%s", code, out)
	}

	// Not set up: configured false, how to set up, exit 1.
	os.Remove(configPath())
	out, _, code = trajrl(t, "", "status", "--json")
	st = tui.Status{}
	if json.Unmarshal([]byte(out), &st); code != 1 || st.Configured || !strings.Contains(st.Message, "trajrl auth login") {
		t.Errorf("not set up: %d %s", code, out)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// With no arguments and no terminal (an agent, a pipe, CI) trajrl prints
// its help and exits 0, with no terminal control sequence at all.
func TestNoTUIWithoutTerminal(t *testing.T) {
	newHome(t, nil)
	out, errs, code := trajrl(t, "")
	if code != 0 || !strings.HasPrefix(out, "usage: trajrl COMMAND") || !strings.Contains(out, "trajrl status [--json]") || errs != "" {
		t.Errorf("no arguments: %d %q %q", code, out, errs)
	}
	if strings.ContainsRune(out+errs, 0x1b) {
		t.Errorf("an ESC byte in %q", out+errs)
	}
	// tui by name refuses without a terminal, and says what to use.
	out, errs, code = trajrl(t, "", "tui")
	if code != 2 || out != "" || !strings.Contains(errs, "trajrl status --json") || strings.ContainsRune(errs, 0x1b) {
		t.Errorf("tui: %d %q %q", code, out, errs)
	}

	// stdout a terminal and stdin not, or TRAJRL_NO_TUI=1 with both: help
	// all the same, and no screen (no alternate screen, no cursor moves).
	// script(1) gives the terminal. Known and left as it is: in a terminal,
	// Bubble Tea v1's own init (tea_init.go) asks it for its background
	// colour (OSC 11, then a cursor position report) before trajrl runs,
	// whatever the command. With no terminal (the cases above) it does not.
	script, err := exec.LookPath("script")
	if err != nil {
		t.Skip("no script(1) here for a terminal: the terminal cases are not run")
	}
	self, _ := os.Executable()
	const bubbleTeaInit = "\x1b]11;?\x1b\\\x1b[6n"
	for _, c := range []struct{ name, sh, env string }{
		{"stdin not a terminal", "exec " + self + " </dev/null", ""},
		{"TRAJRL_NO_TUI=1", "exec " + self, "TRAJRL_NO_TUI=1"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, script, "-qec", c.sh, "/dev/null")
		cmd.Env = append(os.Environ(), "TRAJRL_TEST_MAIN=1", "TERM=xterm-256color", c.env)
		cmd.Stdin = strings.NewReader("")
		b, err := cmd.CombinedOutput()
		rest := strings.Replace(string(b), bubbleTeaInit, "", 1)
		if err != nil || !strings.HasPrefix(rest, "usage: trajrl COMMAND") || strings.ContainsRune(rest, 0x1b) {
			t.Errorf("%s: %v %q", c.name, err, b)
		}
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestParseWhoami(t *testing.T) {
	for _, c := range []struct {
		out     string
		ok      bool
		name    string
		notices []string
	}{
		{`{"name":"alice","notices":["Your credit runs out in 2 days.","Maintenance\tSunday\u001b[31m 02:00 UTC"]}` + "\n", true, "alice",
			[]string{"Your credit runs out in 2 days.", "Maintenance Sunday [31m 02:00 UTC"}},
		{`{"name":"alice","notices":[]}`, true, "alice", nil},
		{`{"name":"alice","notices":["", "  "]}`, true, "alice", nil},
		{`{"account":"alice"}`, true, "alice", nil}, // an entry point before notices
		{"alice\n", false, "", nil},                 // one that ignores --json
		{"123\n", false, "", nil},
		{"", false, "", nil},
		{`{"name": 1}`, false, "", nil},
	} {
		w, ok := parseWhoami([]byte(c.out))
		if ok != c.ok || w.Name != c.name || !slices.Equal(w.Notices, c.notices) {
			t.Errorf("%q: %v %+v, want %v %q %q", c.out, ok, w, c.ok, c.name, c.notices)
		}
	}
}

// whoamiEntry is an entry point that answers ls --json with no sandboxes
// and whoami --json with answer (exit 2, as an unknown flag, if empty),
// and plain whoami with the name.
func whoamiEntry(t *testing.T, answer string) *fakeEntry {
	return newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		switch {
		case cmd == "ls --json":
			io.WriteString(out, "[]")
		case cmd == "whoami --json" && answer != "":
			io.WriteString(out, answer)
		case cmd == "whoami":
			fmt.Fprintln(out, "alice")
		case cmd == "ssh-key statement --json":
			json.NewEncoder(out).Encode(map[string]any{"account": "alice", "keys": []string{}, "signed": ""})
		default:
			fmt.Fprintf(errw, "%s: flag provided but not defined\n", cmd)
			return 2
		}
		return 0
	})
}

// trajrl status prints the platform's notices above the table, and in
// --json; doctor as info lines, which fail nothing. An entry point
// without whoami --json, or one that answers it with plain text: no
// notices, nothing said, the rest as before.
func TestNotices(t *testing.T) {
	const two = `{"name":"alice","notices":["Your credit runs out in 2 days: trajrl billing topup AMOUNT","Maintenance on Sunday"]}`
	newHome(t, whoamiEntry(t, two))
	out, errs, code := trajrl(t, "", "status")
	if want := "Notice: Your credit runs out in 2 days: trajrl billing topup AMOUNT\nNotice: Maintenance on Sunday\n\nNo sandboxes at "; code != 0 || errs != "" || !strings.HasPrefix(out, want) {
		t.Errorf("status: %d %q %q", code, out, errs)
	}
	out, _, _ = trajrl(t, "", "status", "--json")
	var st struct {
		Notices []string `json:"notices"`
	}
	if json.Unmarshal([]byte(out), &st); len(st.Notices) != 2 {
		t.Errorf("status --json: %s", out)
	}
	rep := doctor()
	var info []string
	for _, c := range rep.Checks {
		if c.Status == "info" {
			info = append(info, c.Name+": "+c.Message)
		}
		if c.Name == "entry" && (c.Status != "ok" || !strings.HasSuffix(c.Message, "you are alice")) {
			t.Errorf("doctor entry: %+v", c)
		}
	}
	if !slices.Equal(info, []string{"notice: Your credit runs out in 2 days: trajrl billing topup AMOUNT", "notice: Maintenance on Sunday"}) {
		t.Errorf("doctor notices: %q", info)
	}
	out, _, _ = trajrl(t, "", "doctor")
	if !strings.Contains(out, "\ninfo  notice        Maintenance on Sunday\n") {
		t.Errorf("doctor:\n%s", out)
	}

	for _, answer := range []string{"", "alice\n", `{"account":"alice"}`} {
		newHome(t, whoamiEntry(t, answer))
		out, errs, code := trajrl(t, "", "status")
		if code != 0 || errs != "" || !strings.HasPrefix(out, "No sandboxes at ") {
			t.Errorf("%q: status: %d %q %q", answer, code, out, errs)
		}
		out, _, _ = trajrl(t, "", "status", "--json")
		if strings.Contains(out, "notices") {
			t.Errorf("%q: status --json: %s", answer, out)
		}
		for _, c := range doctor().Checks {
			if c.Status == "info" || c.Name == "entry" && (c.Status != "ok" || !strings.HasSuffix(c.Message, "you are alice")) {
				t.Errorf("%q: doctor: %+v", answer, c)
			}
		}
	}
}

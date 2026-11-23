package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
	"unicode"
)

// noticeTimeout bounds status's question for the notices.
var noticeTimeout = 5 * time.Second

// whoami is the entry point's answer to "whoami --json": the account's
// name and what the platform has to tell it, a line each.
type whoami struct {
	Name    string
	Notices []string
}

// parseWhoami reads the answer to "whoami --json": {"name", "notices"},
// or {"account"} from an entry point before notices. ok is false if it is
// not a JSON object (an entry point that answered with the plain name).
func parseWhoami(out []byte) (w whoami, ok bool) {
	var v struct {
		Name    string   `json:"name"`
		Account string   `json:"account"`
		Notices []string `json:"notices"`
	}
	b := bytes.TrimSpace(out)
	if len(b) == 0 || b[0] != '{' || json.Unmarshal(b, &v) != nil {
		return whoami{}, false
	}
	w.Name = v.Name
	if w.Name == "" {
		w.Name = v.Account
	}
	for _, n := range v.Notices {
		if n = printable(n); n != "" {
			w.Notices = append(w.Notices, n)
		}
	}
	return w, true
}

// printable is s on one line with no control characters (the platform's
// text is shown in your terminal as it is otherwise).
func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// notices asks the entry point for the account's notices. Any failure,
// an entry point older than whoami --json included, is no notices.
func notices(c *config, limit time.Duration) []string {
	out, _, err := entryOutputWithin(c, limit, "whoami", "--json")
	if err != nil {
		return nil
	}
	w, _ := parseWhoami(out)
	return w.Notices
}

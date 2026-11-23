package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
	"github.com/hanlinai/trajrl-cli/internal/tui"
)

// stateWaitingForKey is the state "ls" gives a sandbox whose TD waits for
// its owner's key (internal/control's StateWaitingForKey).
const stateWaitingForKey = "waiting for its owner's key"

func init() {
	handlers["status"] = statusCmd
	handlers["tui"] = tuiCmd
}

// statusCmd is "status [--json]": the entry point's "ls --json" merged
// with this machine's records, and the command to run next, under the
// platform's notices (whoami --json) if it has any. The screen (trajrl
// tui) shows the same data, without the notices.
func statusCmd(args []string) int {
	fs := flag.NewFlagSet(prog+" status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the status as JSON")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		return fail(2, "usage: %s status [--json]", prog)
	}
	// The notices, asked beside ls: none if the entry point cannot say.
	said := make(chan []string, 1)
	go func() {
		c, err := loadConfig()
		if err != nil {
			said <- nil
			return
		}
		said <- notices(c, noticeTimeout)
	}()
	st, err := loadStatus()
	if err != nil {
		return fail(255, "%v", err)
	}
	if st.Configured {
		st.Notices = <-said
	}
	code := 0
	if !st.Configured {
		code = 1
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(st)
		return code
	}
	if !st.Configured {
		return fail(code, "%s", st.Message)
	}
	for _, n := range st.Notices {
		fmt.Println("Notice: " + n)
	}
	if len(st.Notices) > 0 {
		fmt.Println()
	}
	if len(st.Sandboxes) == 0 {
		fmt.Printf("No sandboxes at %s. Make one with: %s new NAME\n", st.Entry, prog)
		return 0
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tSIZE\tNEEDS YOU\tVERIFIED\tURL")
	var next []string
	for _, s := range st.Sandboxes {
		need, ver := "", "no"
		if s.WaitingForKey {
			need = "unlock"
		}
		if s.VerifiedHostKey {
			ver = "yes"
			if s.LastVerified != nil {
				ver += " " + s.LastVerified.Local().Format("2006-01-02 15:04")
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, s.State, s.Size, need, ver, s.URL)
		if s.Next != "" {
			next = append(next, s.Next)
		}
	}
	w.Flush()
	if len(next) > 0 {
		fmt.Println("\nNext:")
		for _, n := range next {
			fmt.Println("  " + n)
		}
	}
	return 0
}

// loadStatus is the status of the configured account's sandboxes. Not set
// up is a status (Configured false), not an error; an entry point that
// cannot be asked is an error.
func loadStatus() (tui.Status, error) {
	c, err := loadConfig()
	if err != nil {
		if strings.Contains(err.Error(), "is not set up") {
			return tui.Status{Message: err.Error(), Sandboxes: []tui.Sandbox{}}, nil
		}
		return tui.Status{}, err
	}
	out, err := entryOutput(c, "ls", "--json")
	if err != nil {
		return tui.Status{}, err
	}
	var list []struct {
		Name   string `json:"name"`
		ID     string `json:"id"`
		State  string `json:"state"`
		Reason string `json:"reason"`
		Size   string `json:"size"`
		URL    string `json:"https_url"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return tui.Status{}, fmt.Errorf("ls --json: %w", err)
	}
	pins, err := sbxapi.LoadPins(sbxapi.DefaultPinFile())
	if err != nil {
		return tui.Status{}, err
	}
	owner, err := ownerState()
	if err != nil {
		return tui.Status{}, err
	}
	st := tui.Status{Configured: true, Entry: c.Entry, Sandboxes: []tui.Sandbox{}}
	for _, v := range list {
		s := tui.Sandbox{Name: v.Name, ID: v.ID, State: v.State, Reason: v.Reason, Size: v.Size, URL: v.URL,
			WaitingForKey: v.State == stateWaitingForKey}
		// A record vouches for this sandbox only if it is of this ID: a
		// name can be given again after a sandbox is gone.
		seen := func(t time.Time) {
			s.VerifiedHostKey = true
			if !t.IsZero() && (s.LastVerified == nil || t.After(*s.LastVerified)) {
				s.LastVerified = &t
			}
		}
		if p, ok := pins.Sandboxes[v.Name]; ok && p.HostKey != "" && p.ID == v.ID {
			seen(p.Verified)
		}
		if r := owner.ByName(v.Name); r != nil && r.ID == v.ID && r.SSHHostKey != "" && r.Policy != "" {
			seen(r.Updated)
		}
		switch {
		case s.WaitingForKey:
			s.Next = tui.JoinLine([]string{prog, "unlock", s.Name})
		case s.State == "running" && !s.VerifiedHostKey:
			s.Next = tui.JoinLine([]string{prog, "verify", s.Name})
		}
		st.Sandboxes = append(st.Sandboxes, s)
	}
	return st, nil
}

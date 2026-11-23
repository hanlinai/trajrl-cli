package main

// keys sync --all and keys status (#118 B30, #65): which of the account's
// sandboxes applied its newest signed statement of keys, and feeding it to
// every running one that has not.
//
// The platform does not know which statement a sandbox applied: only the
// sandbox does (sandbox-keys show --json, over the owner's own SSH, the
// host key verified here, as trajrl ssh). A sandbox that is not running
// cannot be asked; it gets the statement with its next unlock (keycmd's
// unlockStatement), so it is reported as such, not as a failure.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/cli/keycmd"
)

// keysCmd is "keys ..." and "recovery-key ...": sbxkey's, but for "keys
// sync --all" and "keys status", which are trajrl's own.
func keysCmd(args []string) int {
	if args[0] == "keys" && len(args) > 1 {
		switch {
		case args[1] == "status":
			return keysStatusCmd(args[2:])
		case args[1] == "sync" && hasFlag(args[2:], "all"):
			return keysSyncAllCmd(args[2:])
		}
	}
	keycmd.MainWith(args, keyOptions(loadConfigOrEmpty(), false))
	return 0
}

// hasFlag says whether args has -name or --name.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "-"+name || a == "--"+name {
			return true
		}
	}
	return false
}

// keyProbeTimeout bounds each ssh to a sandbox of keys status and sync
// --all: a sandbox that does not answer is reported, not waited for.
const keyProbeTimeout = 15 * time.Second

// sandboxKeys is one sandbox in keys status and keys sync --all.
type sandboxKeys struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	State string `json:"state"`
	// Applied is the seq of the statement the sandbox applied last, as it
	// says (nil: not asked, or it did not answer).
	Applied *uint64 `json:"applied_seq"`
	// Result: "current", "behind", "will apply at next unlock", "applied",
	// "failed", "not asked".
	Result string `json:"result"`
	// Detail says why, or what to run.
	Detail string `json:"detail,omitempty"`
}

// keyStatusReport is keys status --json.
type keyStatusReport struct {
	Account   string        `json:"account"`
	LatestSeq uint64        `json:"latest_seq"`
	Signed    bool          `json:"signed"`
	Sandboxes []sandboxKeys `json:"sandboxes"`
}

// listedSandbox is a sandbox of "ls --json".
type listedSandbox struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	State string `json:"state"`
}

// keysSetup is what both commands start from: the configuration, the
// newest statement, and the account's sandboxes.
func keysSetup() (*config, *keycmd.Latest, []listedSandbox, error) {
	c, err := loadConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	out, err := entryOutput(c, "ssh-key", "statement", "--json")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("the platform's statement of your keys: %w", err)
	}
	latest, err := keycmd.LatestStatement(out, keycmd.DefaultDir(), os.Stderr)
	if err != nil {
		return nil, nil, nil, err
	}
	out, err = entryOutput(c, "ls", "--json")
	if err != nil {
		return nil, nil, nil, err
	}
	var list []listedSandbox
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, nil, nil, fmt.Errorf("ls --json: %w", err)
	}
	return c, latest, list, nil
}

// appliedSeq asks the running sandbox name which statement it applied.
func appliedSeq(c *config, name string) (uint64, error) {
	var out, errb bytes.Buffer
	code, err := sandboxSSH(c, name, probeOpts(), []string{"sandbox-keys", "show", "--json"}, bytes.NewReader(nil), &out, &errb)
	if err != nil {
		return 0, err
	}
	if code != 0 {
		return 0, fmt.Errorf("sandbox-keys show: exit status %d%s", code, said(errb.String()))
	}
	var v struct {
		Seq *uint64 `json:"seq"`
	}
	if json.Unmarshal(out.Bytes(), &v) != nil || v.Seq == nil {
		return 0, errors.New("its answer to \"sandbox-keys show --json\" is not one (an image before revision 16 has no sandbox-keys)")
	}
	return *v.Seq, nil
}

// probeOpts are the ssh options of a sandbox asked without a person
// watching: no prompt, and a bounded wait.
func probeOpts() []string {
	return []string{"-o", "BatchMode=yes", "-o", fmt.Sprintf("ConnectTimeout=%d", int(keyProbeTimeout/time.Second))}
}

// said is what a command said on stderr, as the end of a message.
func said(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	if s == "" {
		return ""
	}
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return ": " + s
}

// notRunning is the line of a sandbox that cannot be asked now.
func notRunning(s listedSandbox, latest uint64) sandboxKeys {
	r := sandboxKeys{Name: s.Name, ID: s.ID, State: s.State}
	switch s.State {
	case stateWaitingForKey:
		r.Result, r.Detail = "will apply at next unlock", fmt.Sprintf("its unlock sends statement %d: %s unlock %s", latest, prog, s.Name)
	case "stopped", "failed":
		r.Result, r.Detail = "will apply at next unlock", fmt.Sprintf("its next start sends statement %d: %s start %s", latest, prog, s.Name)
	default:
		r.Result, r.Detail = "not asked", "it is "+s.State+"; ask again once it runs"
	}
	return r
}

// keysStatusCmd is "keys status [--json]".
func keysStatusCmd(args []string) int {
	fs := flag.NewFlagSet(prog+" keys status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return fail(2, "usage: %s keys status [--json]", prog)
	}
	c, latest, list, err := keysSetup()
	if err != nil {
		return fail(255, "%v", err)
	}
	rep := keyStatusReport{Account: latest.Account, LatestSeq: latest.Statement.Seq, Signed: latest.Signed != "", Sandboxes: []sandboxKeys{}}
	behind := 0
	for _, s := range list {
		if s.State != "running" {
			rep.Sandboxes = append(rep.Sandboxes, notRunning(s, rep.LatestSeq))
			continue
		}
		r := sandboxKeys{Name: s.Name, ID: s.ID, State: s.State}
		seq, err := appliedSeq(c, s.Name)
		switch {
		case err != nil:
			r.Result, r.Detail = "not asked", err.Error()
		case seq >= rep.LatestSeq:
			r.Applied, r.Result = &seq, "current"
		default:
			r.Applied, r.Result, r.Detail = &seq, "behind", fmt.Sprintf("%s keys sync %s", prog, s.Name)
			behind++
		}
		rep.Sandboxes = append(rep.Sandboxes, r)
	}
	if *asJSON {
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("", "  ")
		e.Encode(rep)
		return 0
	}
	if !rep.Signed {
		fmt.Printf("%s has no signed statement of keys yet: %s keys add makes one.\n", rep.Account, prog)
	} else {
		fmt.Printf("statement %d of %s's keys is the newest.\n", rep.LatestSeq, rep.Account)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tAPPLIED\tKEYS")
	for _, r := range rep.Sandboxes {
		applied := "-"
		if r.Applied != nil {
			applied = fmt.Sprint(*r.Applied)
		}
		what := r.Result
		if r.Detail != "" {
			what += " (" + r.Detail + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, r.State, applied, what)
	}
	w.Flush()
	if behind > 0 {
		fmt.Printf("\n%d running sandboxes have not applied statement %d. Now: %s keys sync --all\n", behind, rep.LatestSeq, prog)
	}
	return 0
}

// keysSyncAllCmd is "keys sync --all": the newest statement fed to every
// running sandbox of the account that has not applied it, one line per
// sandbox; exit 1 if any running one failed.
func keysSyncAllCmd(args []string) int {
	for _, a := range args {
		if a != "-all" && a != "--all" {
			return fail(2, "usage: %s keys sync --all (no other flags or names; one sandbox: %s keys sync NAME)", prog, prog)
		}
	}
	c, latest, list, err := keysSetup()
	if err != nil {
		return fail(255, "%v", err)
	}
	if latest.Signed == "" {
		return fail(1, "there is no signed statement of your keys to send (%s keys add makes one)", prog)
	}
	n := latest.Statement.Seq
	var failed []string
	line := func(r sandboxKeys) {
		msg := r.Name + ": " + r.Result
		if r.Detail != "" {
			msg += ": " + r.Detail
		}
		fmt.Println(msg)
	}
	for _, s := range list {
		if s.State != "running" {
			line(notRunning(s, n))
			continue
		}
		r := sandboxKeys{Name: s.Name, ID: s.ID, State: s.State}
		seq, err := appliedSeq(c, s.Name)
		if err == nil && seq >= n {
			r.Result, r.Detail = "current", fmt.Sprintf("statement %d applied already", seq)
			line(r)
			continue
		}
		if err != nil {
			r.Result, r.Detail = "failed", err.Error()
			line(r)
			failed = append(failed, s.Name)
			continue
		}
		var out, errb bytes.Buffer
		code, err := sandboxSSH(c, s.Name, probeOpts(), []string{"sandbox-keys", "apply"}, strings.NewReader(latest.Signed), &out, &errb)
		switch {
		case err != nil:
			r.Result, r.Detail = "failed", err.Error()
		case code != 0:
			r.Result, r.Detail = "failed", fmt.Sprintf("sandbox-keys apply: exit status %d%s%s", code, said(out.String()), said(errb.String()))
		default:
			r.Result, r.Detail = "applied", fmt.Sprintf("statement %d (it had %d)", n, seq)
		}
		if r.Result == "failed" {
			failed = append(failed, s.Name)
		}
		line(r)
	}
	if len(failed) > 0 {
		return fail(1, "statement %d NOT applied by %d sandboxes: %s", n, len(failed), strings.Join(failed, " "))
	}
	fmt.Fprintf(os.Stderr, "%s: statement %d is applied by every running sandbox; the others get it at their next unlock\n", prog, n)
	return 0
}

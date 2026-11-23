// Package tui is trajrl's interactive screen (#123 Part 4): what "trajrl"
// with no arguments shows in a terminal. It renders one piece of data,
// Status, the same that "trajrl status --json" gives an agent, and every
// action it offers is a trajrl command line, shown before it runs and run
// as a child trajrl process. It holds no logic of the sandboxes, keys or
// verification of its own.
//
// Only cmd/trajrl imports it: the terminal libraries it uses stay out of
// the verifier, the key tools, the old programs and every image program.
package tui

import "time"

// Status is what "trajrl status --json" prints and the screen shows: the
// entry point's "ls --json" merged with this machine's records.
type Status struct {
	// Configured is false until "trajrl setup" has run on this machine;
	// Message then says what to do.
	Configured bool   `json:"configured"`
	Entry      string `json:"entry,omitempty"`
	Message    string `json:"message,omitempty"`
	// Notices are what the platform has to tell the account (whoami
	// --json), one line each; "trajrl status" fills them, the screen does
	// not.
	Notices []string `json:"notices,omitempty"`
	// Sandboxes are the account's, in the entry point's order.
	Sandboxes []Sandbox `json:"sandboxes"`
}

// Sandbox is one sandbox of Status.
type Sandbox struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	Size   string `json:"size,omitempty"`
	// WaitingForKey: its TD waits for its owner's key (trajrl unlock).
	WaitingForKey bool `json:"waiting_for_key"`
	// VerifiedHostKey: this machine holds a host key of this sandbox (this
	// ID) that a check here vouched for: trajrl verify's record, or the
	// owner's record of a boot it unlocked after checking the TD's quote.
	VerifiedHostKey bool `json:"verified_host_key"`
	// LastVerified is when that check was made.
	LastVerified *time.Time `json:"last_verified,omitempty"`
	URL          string     `json:"https_url,omitempty"`
	// Next is the trajrl command to run next, "" if there is none.
	Next string `json:"next"`
}

// Command is one line of trajrl's command table, as the help screen
// lists it.
type Command struct {
	Name, Usage, Help string
}

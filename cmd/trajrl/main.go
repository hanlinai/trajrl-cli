// trajrl is the command line of a TrajRL sandbox's owner (#123): one
// program for what has to happen on the owner's own machine (the disk key,
// verifying a sandbox, its pinned host key for ssh and its API) and, for
// everything else, the platform's entry point, whose commands it forwards
// as they are.
//
//	trajrl setup -entry HOST:PORT -entry-key 'ssh-ed25519 AAAA...'
//	trajrl new web            create web, verify its TD, unlock its first boot
//	trajrl ls --json          any other command: the entry point's
//	trajrl help               every command: its own (commands.go), the platform's (platform.go)
//
// Its own commands are the old programs' (internal/cli: sbxkey, sbxverify,
// sbxapi), with the entry point, its key, your SSH key and the domain from
// its configuration (config.go) and the policies from its policy
// directory. The old programs are also here as they are: trajrl sbxkey ...
// See docs/cli.md.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hanlinai/trajrl-cli/internal/cli/apicmd"
	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/cli/keycmd"
	"github.com/hanlinai/trajrl-cli/internal/cli/verifycmd"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// version is trajrl's version, set here in the source (no -X at build).
const version = "0.4.0"

const prog = "trajrl"

func main() { os.Exit(run(os.Args[1:])) }

// handlers are the commands of the table, by name.
var handlers = map[string]func(args []string) int{
	"auth":         authCmd,
	"setup":        setupCmd,
	"key":          keyCmd,
	"keys":         keysCmd,
	"recovery-key": keysCmd,
	"new":          bootCmd,
	"start":        bootCmd,
	"unlock":       bootCmd,
	"known-hosts":  knownHostsCmd,
	"rename":       renameCmd,
	"verify":       verifyCmd,
	"ssh":          sshCmd,
	"proxy":        proxyCmd,
	"exec":         apiCmd,
	"cp":           apiCmd,
	"policy":       policyCmd,
	"share":        shareCmd,
	"backup":       backupCmd,
	"doctor":       doctorCmd,
	"skills":       skillsCmd,
	"version":      versionCmd,
	"help":         helpCmd,
	"entry":        func(args []string) int { return forwardCmd(args[1:]) },
	"sbxkey":       legacy,
	"sbxverify":    legacy,
	"sbxapi":       legacy,
}

// rehearsalScreen is set only in a binary built with the tag "rehearsal"
// (rehearsal.go): it takes the screen's rehearsal flag off args.
var rehearsalScreen func(args []string) []string

// screenFlags are added after the command word of the screen's commands,
// by command: none, but in a rehearsal build started for the rehearsal.
var screenFlags map[string][]string

// run is trajrl with the arguments args; it returns the exit status (the
// old programs' code exits by itself).
func run(args []string) int {
	if rehearsalScreen != nil {
		args = rehearsalScreen(args)
	}
	if len(args) == 0 {
		return noArgs()
	}
	switch args[0] {
	case "-h", "-help", "--help":
		help(os.Stdout)
		return 0
	case "-version", "--version":
		args = []string{"version"}
	}
	if args[0] != "sbxkey" && args[0] != "sbxverify" && args[0] != "sbxapi" {
		jsonMode = clierr.WantsJSON(args)
	}
	h := handlers[args[0]]
	if h == nil {
		// Several commands typed on one line are refused here, not sent
		// to the entry point as one (entry.go); "trajrl entry ..." sends
		// anything as it is.
		if severalCommands(args) {
			return fail(clierr.Usage, "this looks like several commands on one line (%q); run them one per line, e.g. %s ls, then %s whoami", joinArgs(args), prog, prog)
		}
		return forwardCmd(args)
	}
	if args[0] != "sbxkey" && args[0] != "sbxverify" && args[0] != "sbxapi" {
		ownerkey.Tool = prog
	}
	return h(args)
}

// jsonMode: --json was given to one of trajrl's own commands: fail says
// its error as {"error": "...", "code": N} on stderr.
var jsonMode bool

// fail says err as trajrl, or with --json as one JSON object, and returns
// status (clierr: 1 failed, 2 usage, 3 needs the owner, 255 transport).
func fail(status int, format string, a ...any) int {
	clierr.Write(os.Stderr, prog, jsonMode, status, fmt.Sprintf(format, a...))
	return status
}

// versionCmd is "version [--json]".
func versionCmd(args []string) int {
	switch {
	case len(args) == 1:
		fmt.Println(prog, version)
		return 0
	case len(args) == 2 && clierr.IsJSONFlag(args[1]):
		// min_entry: the oldest entry point this trajrl works with; there
		// is no such notion yet, so null.
		return printJSON(struct {
			Version  string  `json:"version"`
			MinEntry *string `json:"min_entry"`
		}{version, nil})
	}
	return fail(clierr.Usage, "usage: %s version [--json]", prog)
}

// printJSON prints v as one line on stdout.
func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fail(clierr.Failed, "%v", err)
	}
	return 0
}

// legacy is "trajrl sbxkey|sbxverify|sbxapi ARGS": the old program as it
// is, its name its own.
func legacy(args []string) int {
	os.Args = append([]string{args[0]}, args[1:]...)
	switch args[0] {
	case "sbxkey":
		keycmd.MainWith(args[1:], keycmd.Options{})
	case "sbxverify":
		verifycmd.MainWith(args[1:], verifycmd.Options{})
	default:
		apicmd.MainWith(args[1:], apicmd.Options{})
	}
	return 0
}

// keyOptions are sbxkey's defaults from the configuration and the policy
// directory.
func keyOptions(c *config, argsAfterName bool) keycmd.Options {
	pols, err := policies()
	if err != nil {
		fail(0, "%v", err)
	}
	id, _ := c.identityFile()
	return keycmd.Options{Entry: c.Entry, EntryKey: c.EntryKey, Identity: id, Domain: c.Domain,
		Policies: pols, NoPolicy: noPolicy(), ArgsAfterName: argsAfterName}
}

// keyCmd is "key init|restore|backup-check": sbxkey's.
func keyCmd(args []string) int {
	if len(args) < 2 || !(args[1] == "init" || args[1] == "restore" || args[1] == "backup-check") {
		return fail(2, "usage: %s key init|restore|backup-check [-dir DIR] [-passphrase-file FILE]", prog)
	}
	keycmd.MainWith(args[1:], keyOptions(loadConfigOrEmpty(), false))
	return 0
}

// bootCmd is new, start, unlock and known-hosts: sbxkey's; start and
// unlock take their flags after NAME too.
func bootCmd(args []string) int {
	if args[0] == "new" {
		args = newFirst(args)
	}
	o := keyOptions(loadConfigOrEmpty(), args[0] == "start" || args[0] == "unlock")
	// --json, before NAME or after it (new: among the platform's flags,
	// taken off them there), is trajrl's: one object on stdout.
	o.JSON = args[0] != "known-hosts" && clierr.WantsJSON(args[1:])
	keycmd.MainWith(args, o)
	return 0
}

// apiCmd is exec and cp: sbxapi's, with the owner's record as a second
// source of the pinned key (exec.go).
func apiCmd(args []string) int {
	c := loadConfigOrEmpty()
	apicmd.MainWith(args, apicmd.Options{Prog: prog, Fallback: apiFallback(c), Explain: waitsForKey(c)})
	return 0
}

// joinArgs is how a command line is shown.
func joinArgs(args []string) string { return strings.Join(args, " ") }

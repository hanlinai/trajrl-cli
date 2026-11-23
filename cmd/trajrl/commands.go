package main

// Command is one of trajrl's own commands. Every other first word, and
// everything after "entry", goes to the platform's entry point as it is.
type Command struct {
	// Name is the command's first word.
	Name string
	// Usage is what follows it.
	Usage string
	// Help says what it does.
	Help string
}

// Commands is trajrl's command table (#123). The tests, and the website's
// tests (tests/sbx.test.mjs), read it: keep one entry a line.
var Commands = []Command{
	{Name: "setup", Usage: "-entry HOST:PORT -entry-key 'ssh-ed25519 AAAA...' [-i KEYFILE] [-ssh-dir DIR] | setup --remove [-ssh-dir DIR]", Help: "set this machine up: the entry point, its key pinned, for trajrl and for your ssh"},
	{Name: "key", Usage: "init|restore|backup-check [-dir DIR] [-passphrase-file FILE]", Help: "your key file: make it, rebuild it from the recovery phrase, check your written phrase"},
	{Name: "keys", Usage: "list|add|remove|sync NAME ... | sync --all | status [--json]", Help: "your signed statement of SSH keys, which your sandboxes follow; sync --all feeds it to every running sandbox, status shows which applied it"},
	{Name: "recovery-key", Usage: "init [-sign-with FILE] [-replace]", Help: "a recovery key, shown once, kept offline"},
	{Name: "new", Usage: "[flags] NAME [flags of the entry point's new ...] [--json]", Help: "create NAME, then verify its TD and unlock its first boot"},
	{Name: "start", Usage: "NAME [flags] [--json]", Help: "verify NAME's TD and unlock its boot (the platform starts it if stopped)"},
	{Name: "unlock", Usage: "NAME [flags] [--json]", Help: "verify NAME's TD and unlock the boot that waits for your key"},
	{Name: "known-hosts", Usage: "[NAME] | --share NAME | --import 'LINE'", Help: "write the SSH host keys on your record where your ssh reads them; --share prints NAME's for a colleague, --import records the one an owner gave you"},
	{Name: "rename", Usage: "OLD NEW", Help: "rename a sandbox at the platform (if it is not yet) and on your record"},
	{Name: "verify", Usage: "NAME [-owner] [--json] | verify --all [-owner -passphrase-file FILE]", Help: "check a running sandbox from here: Intel's signature, the image you expect, your SSH session ends in it"},
	{Name: "ssh", Usage: "NAME [-- ARGS...]", Help: "log in to NAME with your ssh, accepting only the host key verified on this machine"},
	{Name: "proxy", Usage: "HOST PORT", Help: "ssh's ProxyCommand (setup installs it): carries one SSH connection to HOST (NAME.DOMAIN) through the entry point; prints nothing else"},
	{Name: "exec", Usage: "[-cwd DIR] [-env K=V]... [-timeout S] [-stdin] [--json] NAME -- COMMAND [ARG...]", Help: "run a command in NAME over its HTTPS API, pinned to its verified host key"},
	{Name: "cp", Usage: "[flags] [--json] LOCAL NAME:/PATH | NAME:/PATH LOCAL", Help: "copy a file into or out of NAME over its HTTPS API"},
	{Name: "policy", Usage: "list | add FILE | rm NAME", Help: "the launch policies (measurements) you accept, used when no -policy is given"},
	{Name: "share", Usage: "ssh NAME ACCOUNT | ...", Help: "the entry point's share, as it is; after share ssh, the command that gives ACCOUNT NAME's verified host key"},
	{Name: "backup", Usage: "export NAME|ID [BACKUP] [-dir DIR] [--json] | the entry point's backup ...", Help: "export: download a backup of NAME (encrypted, as stored, every chunk checked) for a restore without the platform; a removed sandbox's by its ID, for 30 days"},
	{Name: "doctor", Usage: "[--json]", Help: "check this machine's setup: configuration, entry point, SSH key, your ssh's lines, owner key, recovery key, policies; exit 1 on a failure"},
	{Name: "status", Usage: "[--json]", Help: "your sandboxes with what this machine knows of them, and the command to run next (agents: --json)"},
	{Name: "tui", Usage: "", Help: "the interactive screen (also trajrl with no arguments, in a terminal); every key runs one of these commands"},
	{Name: "skills", Usage: "list | show NAME | install [-dir DIR] [-force] [NAME...]", Help: "the skills trajrl carries for coding agents; install puts them in ~/.claude/skills"},
	{Name: "version", Usage: "[--json]", Help: "trajrl's version"},
	{Name: "help", Usage: "[COMMAND]", Help: "this list; with COMMAND, that command in full, the platform's from its own reference"},
	{Name: "entry", Usage: "ARGS...", Help: "the platform's command ARGS as it is, also one named like one of trajrl's; trajrl entry help is the platform's full reference"},
	{Name: "sbxkey", Usage: "ARGS...", Help: "the old sbxkey, as it is"},
	{Name: "sbxverify", Usage: "ARGS...", Help: "the old sbxverify, as it is"},
	{Name: "sbxapi", Usage: "ARGS...", Help: "the old sbxapi, as it is"},
}

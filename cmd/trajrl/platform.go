package main

// PlatformCommand is one of the platform's commands (the entry point's,
// internal/control/sshd.go) that people use, for trajrl help. trajrl has no
// handler for it: run sends it to the entry point as it is (forwardCmd).
// Its own type, not Command, so it never counts as one of trajrl's own
// (TestCommandTable, the website's tests/sbx.test.mjs).
type PlatformCommand struct {
	// Words is the command's first word, or its first two.
	Words string
	// Usage is what follows them.
	Usage string
	// Help says what it does, short; trajrl help WORDS asks the entry point
	// for its full text.
	Help string
}

// Platform is the platform's commands trajrl help lists, by group. The
// full reference is the entry point's help (trajrl entry help).
var Platform = []struct {
	Title    string
	Commands []PlatformCommand
}{
	{"Sandboxes", []PlatformCommand{
		{Words: "ls", Usage: "[-l] [--tag TAG]", Help: "your sandboxes (trajrl status adds what this machine verified)"},
		{Words: "show", Usage: "NAME [--log [--lines N]]", Help: "one sandbox, with how to log in; --log: its serial console"},
		{Words: "wait", Usage: "NAME [--timeout 30m]", Help: "until NAME is running, or has failed"},
		{Words: "stop", Usage: "NAME", Help: "stop NAME (trajrl start NAME starts it again)"},
		{Words: "restart", Usage: "NAME", Help: "stop NAME and start it again"},
		{Words: "rm", Usage: "NAME --yes", Help: "destroy NAME and its data, for good"},
		{Words: "sizes", Usage: "", Help: "the sizes there are: vCPUs and memory"},
		{Words: "images", Usage: "", Help: "the guest images there are"},
		{Words: "resize", Usage: "NAME --size S", Help: "another size from NAME's next start (stopped only)"},
		{Words: "resize-disk", Usage: "NAME GIB", Help: "grow NAME's disk to GIB (stopped only; disks only grow)"},
		{Words: "set-image", Usage: "NAME --image I", Help: "boot NAME from another image from its next start (stopped only)"},
		{Words: "tag", Usage: "NAME TAG... | tag NAME --rm TAG...", Help: "label NAME, or take labels off (plain text: no secrets)"},
		{Words: "comment", Usage: "NAME TEXT | comment NAME --clear", Help: "one line about NAME (plain text: no secrets)"},
		{Words: "defaults", Usage: "[set KEY=VALUE... | unset KEY...]", Help: "what new uses where its flag is not given: size, image, disk"},
		{Words: "stat", Usage: "NAME [--range 24h|7d|30d]", Help: "NAME's CPU, memory, disk and traffic over time, seen from outside"},
		{Words: "rollback-accept", Usage: "NAME --yes", Help: "after a boot refused as a rollback: use the older disk as it is, once"},
	}},
	{"Copies of a disk", []PlatformCommand{
		{Words: "snapshot", Usage: "new NAME | ls NAME | restore NAME ID --yes | rm NAME ID", Help: "copies of a stopped sandbox's disk, kept on its host"},
		{Words: "backup", Usage: "new NAME | ls NAME | status NAME | restore NAME [ID] --yes", Help: "copies in a store apart from the hosts, every 15 minutes while NAME runs (trajrl backup export downloads one)"},
	}},
	{"Network and sharing", []PlatformCommand{
		{Words: "share", Usage: "set-public NAME | set-private NAME", Help: "carry web traffic for NAME's host names to it, or not"},
		{Words: "share", Usage: "port NAME PORT [--direct] | port-rm NAME PORT", Help: "HTTPS for NAME-ACCOUNT-PORT reaches guest port PORT"},
		{Words: "share", Usage: "ssh NAME ACCOUNT | ssh-rm NAME ACCOUNT", Help: "carry ACCOUNT's ssh to NAME (trajrl adds the host key for them)"},
		{Words: "share", Usage: "ipv6-ssh NAME on|off", Help: "ssh straight to NAME's own IPv6 address, past the platform's checks"},
		{Words: "domain", Usage: "add NAME DOMAIN | rm NAME DOMAIN | ls [NAME]", Help: "a host name of your own for NAME"},
		{Words: "egress", Usage: "NAME [open | none | allow DEST...]", Help: "what NAME may connect to on the Internet; without a word, what it may now"},
	}},
	{"Account", []PlatformCommand{
		{Words: "register", Usage: "NAME --invite CODE", Help: "make an account that is your SSH key, when trajrl setup says your key has none; then trajrl setup again"},
		{Words: "whoami", Usage: "", Help: "your account's name"},
		{Words: "billing", Usage: "[usage [--range 24h] | prices | redeem CODE | topup AMOUNT]", Help: "your credit, what you spend, the prices, adding to your credit"},
		{Words: "token", Usage: "new [--label L] [--exp 720h] [--cmds ls,new,...] | ls | rm ID", Help: "tokens for the HTTP API"},
		{Words: "team", Usage: "new NAME | invite | join CODE | ls | leave | remove ACCOUNT | role ... | stop ... | rm ... | limits ...", Help: "a team: one balance its members' sandboxes are charged to"},
		{Words: "ssh-key", Usage: "list", Help: "the SSH keys that identify you (trajrl keys add/remove changes them, signed)"},
		{Words: "account delete", Usage: "--confirm ACCOUNT", Help: "delete this account, for good (rm its sandboxes first)"},
	}},
}

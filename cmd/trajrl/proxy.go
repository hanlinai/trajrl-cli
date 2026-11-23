package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// trajrl says who it is on every connection to the entry point, which
// answers no other SSH client: SSH-2.0-trajrl_VERSION, VERSION being what
// trajrl version prints.
func init() { userverify.SetVersion(version) }

// proxyCmd is "proxy HOST PORT", ssh's ProxyCommand in the lines setup
// installs ("ProxyCommand /path/to/trajrl proxy %h %p"): it logs in to
// the configured entry point, its key pinned, and carries ssh's
// connection to HOST:PORT (NAME.DOMAIN:22) through it. Its standard output
// is that connection: nothing else is ever written there. It asks no
// question; an error goes to stderr, with exit status 255 as ssh's own.
func proxyCmd(args []string) int {
	return proxy(args, os.Stdin, os.Stdout, os.Stderr)
}

func proxy(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	say := func(format string, a ...any) int {
		fmt.Fprintf(stderr, prog+" proxy: "+format+"\n", a...)
		return 255
	}
	if len(args) != 3 {
		fmt.Fprintf(stderr, "usage: %s proxy %s (ssh's ProxyCommand: %s proxy %%h %%p)\n", prog, proxyUsage, prog)
		return 2
	}
	c, err := loadConfig()
	if err != nil {
		return say("%v", err)
	}
	entry, err := dialEntry(c)
	if err != nil {
		return say("%v", err)
	}
	defer entry.Close()
	if err := userverify.Proxy(entry, args[1], args[2], stdin, stdout); err != nil {
		return say("%v", err)
	}
	return 0
}

// proxyUsage is proxy's usage, as the command table has it.
const proxyUsage = "HOST PORT"

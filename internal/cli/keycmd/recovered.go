package keycmd

// sbxkey start|unlock and a recovered disk (#111). After its host failed, a
// sandbox brought back on another host from a replica or a backup carries a
// notice in its view at the platform ("recovered on AT from replica of TIME
// (its host failed); what was written after TIME is lost; ..."). The
// platform clears that notice as soon as it hands the TD's connection to
// the owner's unlock, so it is read here first, with `show NAME --json`, and
// shown before the disk secret goes anywhere. On a terminal the owner says
// whether to go on with that copy; without one, -accept-recovered says it.
//
// The notice is the platform's word, which nothing here can check. The boot
// epoch the TD reports still refuses a disk from an earlier boot
// (-accept-older); a replica taken during the current boot has the same
// epoch, so for what was written after it the notice is all the owner has.

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/cli/clierr"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// recoveredCheck is how the owner is asked about a recovered copy.
type recoveredCheck struct {
	// accept is -accept-recovered: go on without asking.
	accept bool
	// tty: there is a terminal to ask on, with ask.
	tty  bool
	ask  func(prompt string) (string, error)
	errw io.Writer
}

// recoveredNotice is the recovered notice of a view, "" for none.
func recoveredNotice(v *sandboxView) string {
	return strings.TrimSpace(ownerkey.Printable(v.Recovered))
}

// confirmRecovered shows the notice, if there is one, and returns nil only
// if the owner goes on with that copy.
func confirmRecovered(name, notice string, c recoveredCheck) error {
	if notice == "" {
		return nil
	}
	fmt.Fprintf(c.errw, "%s is a recovered copy. The platform says:\n  %s\n", name, notice)
	switch {
	case c.accept:
		fmt.Fprintln(c.errw, "  -accept-recovered: going on with this copy.")
		return nil
	case !c.tty:
		// The owner's decision is needed: exit status 3 (clierr.NeedsOwner).
		return clierr.With(clierr.NeedsOwner, fmt.Errorf("%s is a recovered copy (above), and there is no terminal to ask on: give -accept-recovered to unlock it as it is; nothing was sent", name))
	}
	a, err := c.ask("continue with this copy? [y/N] ")
	if err != nil {
		return err
	}
	if a = strings.ToLower(a); a != "y" && a != "yes" {
		return fmt.Errorf("%s not unlocked: you did not go on with the recovered copy; nothing was sent. It waits; %s again when you are ready", name, ownerkey.Command("unlock "+name))
	}
	return nil
}

// openUnlock opens the unlock of NAME at the entry point. NAME's view is
// read first (`show NAME --json`): for a sandbox that exists already, its
// recovered notice is confirmed, since the platform clears it once the TD's
// connection is taken; and its web names are taken from it (webnames.go).
// A view that cannot be read stops the unlock before anything is sent, for
// a sandbox just made with `new` too (#118): its web names come from the
// view, and the TD requires them. Sending none would leave the sandbox's
// web server without a certificate for any name until its next unlock, and
// the tool has no other word for which names are the sandbox's. The new
// sandbox waits for its first boot; the error says how to give it.
func openUnlock(entry *ssh.Client, name string, isNew bool, c recoveredCheck, wait time.Duration) (net.Conn, string, *sandboxView, error) {
	view, err := showSandbox(entry, name)
	switch {
	case err != nil && !isNew:
		return nil, "", nil, fmt.Errorf("could not read %s's state at the platform before unlocking it: %w", name, err)
	case err != nil:
		return nil, "", nil, fmt.Errorf("%s was made at the platform but not unlocked: could not read its view there (%w), which its web names come from; nothing was sent. Its first boot is still to come: %s, with the same -image, -registry-auth, -setup-script and -env (a -prompt task cannot be given there: remove %s and make it again)",
			name, err, ownerkey.Command("unlock -first-boot "+name), name)
	case !isNew:
		if err := confirmRecovered(name, recoveredNotice(view), c); err != nil {
			return nil, "", nil, err
		}
	}
	fmt.Fprintf(c.errw, "Waiting for %s's TD (up to %v)...\n", name, wait)
	conn, id, err := ownerkey.OpenUnlock(entry, name, wait)
	return conn, id, view, err
}

package proto

import (
	"fmt"
	"regexp"
	"strings"
)

// A sandbox's web names (#113): the names its web server (the image's Caddy)
// may obtain certificates for. The owner's tool reads them from the
// platform's view of the sandbox, keeps those that are the sandbox's own
// (internal/cli/keycmd), and sends them with every release (Msg.WebNames),
// an empty list as an empty list; the guest refuses a release without them
// (RequireWebNames), writes them to KEYDIR/web-names, and the initrd to
// /var/lib/tdx-sandbox/web-names on the encrypted disk, where sandbox-share
// answers Caddy's "ask" from them: only the names listed, none if empty.

// Limits of the web names one release carries.
const (
	MaxWebNames = 64
	MaxWebName  = 253
)

// webNameRe is the Caddyfile's former "ask" rule (#33): lower-case labels of
// letters, digits and inner hyphens, at least two of them, the last one
// starting with a letter (so no IP literal).
var webNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidWebName reports whether s is a web name a release may carry: a
// lower-case DNS name of at most 253 bytes, with a dot, whose last label
// starts with a letter, and that is not localhost or under it.
func ValidWebName(s string) bool {
	return len(s) <= MaxWebName && webNameRe.MatchString(s) && !strings.HasSuffix("."+s, ".localhost")
}

// WebNamesTool is the first version of the owner's tool whose releases
// always carry the web names, empty or not (#118). A guest of the image
// revision 17 on names it when it refuses a release without them.
const WebNamesTool = "trajrl 0.2.0"

// RequireWebNames refuses a release's web names that are missing (nil: the
// field was not sent), naming the tool that sends them, and otherwise
// checks them (CheckWebNames). An empty, non-nil list passes: no names.
func RequireWebNames(names []string) error {
	if names == nil {
		return fmt.Errorf("the release carries no web names: the owner's tool is older than %s (or an sbxkey of the same age), and this sandbox's image requires them; update it and unlock again", WebNamesTool)
	}
	return CheckWebNames(names)
}

// CheckWebNames refuses a list of web names a release may not carry: more
// than MaxWebNames, or one that is not ValidWebName.
func CheckWebNames(names []string) error {
	if len(names) > MaxWebNames {
		return fmt.Errorf("%d web names; a release carries at most %d", len(names), MaxWebNames)
	}
	for _, n := range names {
		if !ValidWebName(n) {
			return fmt.Errorf("web name %.80q is not a lower-case DNS name of at most %d bytes", n, MaxWebName)
		}
	}
	return nil
}

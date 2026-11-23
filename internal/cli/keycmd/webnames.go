package keycmd

// The sandbox's web names (#113). Its web server (the image's Caddy) obtains
// a certificate for a name the first time a browser asks for it, after
// asking sandbox-share whether the name is the sandbox's. The answer comes
// from a list on the sandbox's encrypted disk, which only the owner's tool
// sets: at every unlock it reads the sandbox's view at the platform
// (`show NAME --json`), keeps the names that are the sandbox's own, prints
// them and sends them with the release (proto.Msg.WebNames), an empty list
// as an empty list: the TD refuses a release without them (#118). A rename
// (#72) or `domain add` takes effect at the next start.
//
// The view is the platform's word. What is kept is limited to
//   - the https_url's name, when it is NAME-ACCOUNT.DOMAIN or
//     NAME.ACCOUNT.DOMAIN for this sandbox's NAME: DOMAIN and ACCOUNT are
//     then "the sandbox's domain";
//   - a shared port's name, NAME-ACCOUNT-PORT.DOMAIN with the same
//     NAME-ACCOUNT and DOMAIN, PORT 3000 to 9999;
//   - a domain listed in "domains" that is not under DOMAIN (a domain of the
//     owner's own, added with `domain add`).
// Everything else is left out and named. The platform can still list a
// domain that is not the owner's, or leave a name out; the router decides
// where a name's traffic goes in any case (docs/threat-model.md, "Web
// traffic").

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// sandboxView is what sbxkey reads of `show NAME --json`.
type sandboxView struct {
	Recovered string `json:"recovered"`
	URL       string `json:"https_url"`
	Ports     []struct {
		URL string `json:"https_url"`
	} `json:"shared_ports"`
	Domains []string `json:"domains"`
}

// showSandbox reads NAME's view at the platform.
func showSandbox(entry *ssh.Client, name string) (*sandboxView, error) {
	out, err := ownerkey.RunEntry(entry, []string{"show", name, "--json"})
	if err != nil {
		return nil, err
	}
	var v sandboxView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return nil, fmt.Errorf("show %s --json: the platform's answer is not a sandbox's view: %w", name, err)
	}
	return &v, nil
}

// urlHost is the host name of an https URL with no port, user or path but
// "/"; "" if it is not one.
func urlHost(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// webNames returns the names of the view that are sandbox NAME's own, at
// most proto.MaxWebNames, and those left out (as the platform gave them).
func webNames(name string, v *sandboxView) (keep, dropped []string) {
	if v == nil {
		return nil, nil
	}
	add := func(n string) {
		switch {
		case slices.Contains(keep, n):
		case len(keep) == proto.MaxWebNames:
			dropped = append(dropped, n+" (more than "+strconv.Itoa(proto.MaxWebNames)+")")
		default:
			keep = append(keep, n)
		}
	}
	// The sandbox's domain, from its base name.
	var prefix, domain string // NAME-ACCOUNT (one-label form only) and DOMAIN
	if v.URL != "" {
		h := urlHost(v.URL)
		if rest, ok := strings.CutPrefix(h, name+"-"); ok {
			if acct, d, ok := strings.Cut(rest, "."); ok && acct != "" && !strings.Contains(acct, "-") {
				prefix, domain = name+"-"+acct, d
			}
		} else if rest, ok := strings.CutPrefix(h, name+"."); ok {
			// The two-label form, for an account with a hyphen: no
			// names per port.
			if acct, d, ok := strings.Cut(rest, "."); ok && acct != "" {
				domain = d
			}
		}
		if domain != "" && proto.ValidWebName(h) && proto.ValidWebName(domain) {
			add(h)
		} else {
			domain, prefix = "", ""
			dropped = append(dropped, v.URL)
		}
	}
	for _, p := range v.Ports {
		if p.URL == "" {
			continue
		}
		h := urlHost(p.URL)
		port, ok := strings.CutPrefix(strings.TrimSuffix(h, "."+domain), prefix+"-")
		if n, err := strconv.Atoi(port); prefix != "" && ok && strings.HasSuffix(h, "."+domain) && err == nil && strconv.Itoa(n) == port && n >= 3000 && n <= 9999 && proto.ValidWebName(h) {
			add(h)
		} else {
			dropped = append(dropped, p.URL)
		}
	}
	for _, d := range v.Domains {
		l := strings.ToLower(d)
		if proto.ValidWebName(l) && (domain == "" || (l != domain && !strings.HasSuffix(l, "."+domain))) {
			add(l)
		} else {
			dropped = append(dropped, d)
		}
	}
	return keep, dropped
}

// sayWebNames tells the owner what goes to the TD.
func sayWebNames(w io.Writer, name string, keep, dropped []string) {
	if len(keep) == 0 {
		fmt.Fprintf(w, "web names: none; an empty list sent: %s's web server gets no certificate for any name\n", name)
	} else {
		fmt.Fprintf(w, "web names sent to %s's TD, the only ones its web server gets certificates for:\n  %s\n", name, strings.Join(keep, "\n  "))
	}
	if len(dropped) > 0 {
		fmt.Fprintf(w, "  left out, not %s's own names at the platform: %s\n", name, ownerkey.Printable(strings.Join(dropped, " ")))
	}
}

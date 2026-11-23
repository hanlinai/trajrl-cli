package keycmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// viewOf decodes a view as `show NAME --json` prints it (internal/control
// View: https_url, shared_ports[].https_url, domains).
func viewOf(t *testing.T, js string) *sandboxView {
	t.Helper()
	var v sandboxView
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

// The names sbxkey sends (#113): the sandbox's own under the platform's web
// domain, and the owner's own domains; everything else is left out and
// named.
func TestWebNamesKeptAndDropped(t *testing.T) {
	v := viewOf(t, `{"name":"web","id":"sbx-0123456789abcdef","state":"waiting for its owner's key","public":true,
		"https_url":"https://web-alice.sbx.teby.ai",
		"shared_ports":[{"port":3000,"https_url":"https://web-alice-3000.sbx.teby.ai"},{"port":4000,"https_url":"https://evil.example"},
			{"port":5000,"https_url":"https://web-bob-5000.sbx.teby.ai"},{"port":6000,"https_url":"https://web-alice-6000.other.example"},
			{"port":7000,"https_url":"https://web-alice-80.sbx.teby.ai"},{"port":8000}],
		"domains":["App.Example.com","www.example.com","db-alice.sbx.teby.ai","10.0.0.1","localhost","app.example.com"]}`)
	keep, dropped := webNames("web", v)
	want := []string{"web-alice.sbx.teby.ai", "web-alice-3000.sbx.teby.ai", "app.example.com", "www.example.com"}
	if !slices.Equal(keep, want) {
		t.Fatalf("kept %q, want %q", keep, want)
	}
	for _, d := range []string{"https://evil.example", "https://web-bob-5000.sbx.teby.ai", "https://web-alice-6000.other.example",
		"https://web-alice-80.sbx.teby.ai", "db-alice.sbx.teby.ai", "10.0.0.1", "localhost"} {
		if !slices.Contains(dropped, d) {
			t.Errorf("%s was not left out: %q", d, dropped)
		}
	}
	if len(dropped) != 7 {
		t.Errorf("left out: %q", dropped)
	}

	// The two-label form (an account whose name has a hyphen).
	keep, dropped = webNames("web", viewOf(t, `{"https_url":"https://web.al-ice.sbx.teby.ai","domains":["app.example.com"]}`))
	if !slices.Equal(keep, []string{"web.al-ice.sbx.teby.ai", "app.example.com"}) || len(dropped) != 0 {
		t.Fatalf("two-label form: %q, left out %q", keep, dropped)
	}

	// A base name that is not this sandbox's: no domain is known, so no
	// shared port's name is either; the owner's own domains still go.
	for _, u := range []string{"https://db-alice.sbx.teby.ai", "https://web-alice.sbx.teby.ai:8443", "http://web-alice.sbx.teby.ai",
		"https://web-alice.sbx.teby.ai/x", "https://x@web-alice.sbx.teby.ai", "https://web-al-ice.sbx.teby.ai"} {
		keep, dropped = webNames("web", viewOf(t, fmt.Sprintf(`{"https_url":%q,"shared_ports":[{"https_url":"https://web-alice-3000.sbx.teby.ai"}],"domains":["app.example.com"]}`, u)))
		if !slices.Equal(keep, []string{"app.example.com"}) || !slices.Contains(dropped, u) {
			t.Errorf("https_url %s: kept %q, left out %q", u, keep, dropped)
		}
	}

	// No web domain at the platform: nothing to send but the owner's
	// domains; no view at all: nothing.
	if keep, dropped = webNames("web", viewOf(t, `{"name":"web"}`)); len(keep) != 0 || len(dropped) != 0 {
		t.Fatalf("no names: %q %q", keep, dropped)
	}
	if keep, dropped = webNames("web", nil); keep != nil || dropped != nil {
		t.Fatalf("no view: %q %q", keep, dropped)
	}

	// At most 64: the rest are left out, and said to be.
	var many []string
	for i := range 70 {
		many = append(many, fmt.Sprintf("d%d.example.com", i))
	}
	b, _ := json.Marshal(map[string]any{"https_url": "https://web-alice.sbx.teby.ai", "domains": many})
	keep, dropped = webNames("web", viewOf(t, string(b)))
	if len(keep) != 64 || keep[0] != "web-alice.sbx.teby.ai" || len(dropped) != 7 || !strings.Contains(dropped[0], "more than 64") {
		t.Fatalf("70 domains: %d kept, left out %q", len(keep), dropped)
	}
}

// What the owner is shown: the list sent, or that none was, and what was
// left out, with nothing of the platform's that a terminal would act on.
func TestWebNamesPrinted(t *testing.T) {
	var b bytes.Buffer
	sayWebNames(&b, "web", []string{"web-alice.sbx.teby.ai", "app.example.com"}, []string{"https://evil.example\x1b[2J"})
	got := b.String()
	if !strings.Contains(got, "web names sent to web's TD, the only ones its web server gets certificates for:\n  web-alice.sbx.teby.ai\n  app.example.com\n") ||
		!strings.Contains(got, "left out, not web's own names at the platform: https://evil.example") || strings.Contains(got, "\x1b") {
		t.Fatalf("printed:\n%s", got)
	}
	b.Reset()
	sayWebNames(&b, "web", nil, nil)
	if !strings.Contains(b.String(), "web names: none; an empty list sent: web's web server gets no certificate for any name") {
		t.Fatalf("printed:\n%s", b.String())
	}
}

// The view comes from the same show that carries the recovered notice; a new
// sandbox's is read too (no notice is asked about).
func TestWebNamesViewReadBeforeUnlock(t *testing.T) {
	for _, isNew := range []bool{false, true} {
		ev := &events{}
		entry := fakeEntry(t, "", ev)
		conn, _, view, err := openUnlock(entry, "web", isNew, recoveredCheck{errw: stderrTo{ev}}, 10*time.Second)
		if err != nil || view == nil {
			t.Fatalf("new %v: %v %+v", isNew, err, view)
		}
		conn.Close()
		all := ev.list()
		if show, unlock := index(all, "exec: show web --json"), index(all, "exec: unlock web"); show < 0 || unlock < show {
			t.Fatalf("new %v: %q", isNew, all)
		}
		if n := strings.Count(strings.Join(all, "\n"), "exec: show"); n != 1 {
			t.Fatalf("new %v: %d shows", isNew, n)
		}
	}
	// A view that cannot be read stops the unlock before the TD's
	// connection is asked for, for a sandbox just made too (#118): its web
	// names come from there, and none would be sent. The error says how to
	// give the first boot later.
	for _, isNew := range []bool{false, true} {
		ev := &events{}
		entry := fakeEntry(t, "", ev)
		conn, _, _, err := openUnlock(entry, "other", isNew, recoveredCheck{errw: stderrTo{ev}}, 10*time.Second)
		if err == nil {
			conn.Close()
			t.Fatalf("new %v: no view, and the unlock went on", isNew)
		}
		if isNew && (!strings.Contains(err.Error(), "web names") || !strings.Contains(err.Error(), "unlock -first-boot other")) {
			t.Errorf("new, no view: %v", err)
		}
		if all := ev.list(); index(all, "exec: unlock other") >= 0 {
			t.Fatalf("new %v: the unlock was asked for without a view: %q", isNew, all)
		}
	}
}

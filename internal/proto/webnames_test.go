package proto

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Which web names a release may carry (#113), and how many.
func TestWebNamesValidation(t *testing.T) {
	long := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61) // 253 bytes
	for _, ok := range []string{"web-alice.sbx.teby.ai", "web-alice-3000.sbx.teby.ai", "www.example.com", "a.b", "xn--bcher-kva.example", "1.example", long} {
		if !ValidWebName(ok) {
			t.Errorf("ValidWebName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "nodot", "10.0.0.1", "localhost", "foo.localhost", "a.b.localhost", "::1", "[::1]",
		"Web-Alice.sbx.test", "web_alice.sbx.test", "-web.sbx.test", "web-.sbx.test", "web..sbx.test", ".sbx.test", "sbx.test.",
		"*.sbx.test", "web.sbx.test:443", "web.sbx.test/x", "web.sbx.test\n", long + "b", "x." + strings.Repeat("a", 64)} {
		if ValidWebName(bad) {
			t.Errorf("ValidWebName(%q) = true", bad)
		}
	}

	var max []string
	for i := range MaxWebNames {
		max = append(max, fmt.Sprintf("n%d.example", i))
	}
	if err := CheckWebNames(max); err != nil {
		t.Fatalf("%d names: %v", MaxWebNames, err)
	}
	if err := CheckWebNames(append(max, "one-more.example")); err == nil || !strings.Contains(err.Error(), "at most 64") {
		t.Fatalf("%d names: %v", MaxWebNames+1, err)
	}
	if err := CheckWebNames(nil); err != nil {
		t.Fatalf("no names: %v", err)
	}
	if err := CheckWebNames([]string{"web-alice.sbx.test", "10.0.0.1"}); err == nil || !strings.Contains(err.Error(), "10.0.0.1") {
		t.Fatalf("an IP among them: %v", err)
	}

	// On the wire: web_names, an empty list as [], absent only when the
	// field was not set (#118), and the two read back apart.
	b, _ := json.Marshal(Msg{Type: TypeRelease, WebNames: []string{"web-alice.sbx.test"}})
	if !strings.Contains(string(b), `"web_names":["web-alice.sbx.test"]`) {
		t.Fatalf("release: %s", b)
	}
	if b, _ = json.Marshal(Msg{Type: TypeRelease, WebNames: []string{}}); !strings.Contains(string(b), `"web_names":[]`) {
		t.Fatalf("release with an empty list: %s", b)
	}
	var m Msg
	if json.Unmarshal(b, &m); m.WebNames == nil || len(m.WebNames) != 0 {
		t.Fatalf("an empty list read back as %#v", m.WebNames)
	}
	if b, _ = json.Marshal(Msg{Type: TypeRelease}); strings.Contains(string(b), "web_names") {
		t.Fatalf("release without the field: %s", b)
	}
	m = Msg{}
	if json.Unmarshal(b, &m); m.WebNames != nil {
		t.Fatalf("no field read back as %#v", m.WebNames)
	}
	// Required by the guest: missing refused, naming the tool; empty taken.
	if err := RequireWebNames(nil); err == nil || !strings.Contains(err.Error(), WebNamesTool) {
		t.Fatalf("no web names: %v", err)
	}
	if err := RequireWebNames([]string{}); err != nil {
		t.Fatalf("an empty list: %v", err)
	}
	if err := RequireWebNames([]string{"10.0.0.1"}); err == nil {
		t.Fatal("RequireWebNames took an IP")
	}
}

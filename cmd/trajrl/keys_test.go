package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/keystmt"
)

// standInSSH puts a stand-in ssh first on PATH: a shell script with body
// after "host" (the sandbox's host name) and "last" (the last argument)
// are set from ssh's arguments.
func standInSSH(t *testing.T, body string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh for the stand-in ssh")
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nhost=; last=\nfor a; do case $a in root@*) host=${a#root@};; esac; last=$a; done\n" + body
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// keys status and keys sync --all ask each running sandbox which statement
// it applied (over ssh, the verified host key), feed the newest to those
// behind, report the others as getting it at their next unlock, and fail if
// any running one did not take it. keys remove ends with the --all hint.
func TestKeysSyncAll(t *testing.T) {
	var h *home
	other := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl laptop"
	var signed []byte
	ls := `[{"name":"web","id":"sbx-0000000000000001","state":"running"},
{"name":"api","id":"sbx-0000000000000002","state":"running"},
{"name":"bad","id":"sbx-0000000000000003","state":"running"},
{"name":"nokey","id":"sbx-0000000000000004","state":"running"},
{"name":"old","id":"sbx-0000000000000005","state":"stopped"},
{"name":"wt","id":"sbx-0000000000000006","state":"waiting for its owner's key"}]`
	put := ""
	// The account's login keys at the platform: the statement's (a key
	// removed on the website would be missing here, #118 D1).
	var platformKeys []string
	e := newFakeEntry(t, func(cmd string, stdin io.Reader, out, errw io.Writer) int {
		switch cmd {
		case "ssh-key statement --json":
			json.NewEncoder(out).Encode(map[string]any{"account": "alice", "keys": platformKeys, "signed": string(signed)})
		case "ls --json":
			io.WriteString(out, ls)
		case "ssh-key statement put":
			b, _ := io.ReadAll(stdin)
			put = string(b)
		default:
			fmt.Fprintf(errw, "unexpected %q\n", cmd)
			return 2
		}
		return 0
	})
	h = newHome(t, e)
	// The statement, seq 3, signed with the home's own key, a login key in it.
	b, _ := os.ReadFile(h.keyFile)
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	mine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	platformKeys = []string{mine, strings.TrimSuffix(other, " laptop")}
	if signed, err = keystmt.Sign(&keystmt.Statement{Account: "alice", Seq: 3, Keys: []string{mine, other}}, signer); err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSuffix(other, " laptop") // any key: the stand-in ssh checks none
	pins := map[string]any{}
	for i, n := range []string{"web", "api", "bad"} {
		pins[n] = map[string]any{"name": n, "id": fmt.Sprintf("sbx-000000000000000%d", i+1), "ssh_host_key": key, "verified": time.Now()}
	}
	writeJSON(t, filepath.Join(h.dir, "xdg", "sbx", "verified.json"), map[string]any{"sandboxes": pins})
	applied := filepath.Join(h.dir, "web.applied")
	standInSSH(t, `case "$host:$last" in
web.sbx.example:--json) echo '{"sandbox_id":"sbx-0000000000000001","seq":1}';;
api.sbx.example:--json) echo '{"sandbox_id":"sbx-0000000000000002","seq":3}';;
bad.sbx.example:--json) echo '{"sandbox_id":"sbx-0000000000000003","seq":2}';;
web.sbx.example:apply) cat > `+applied+`;;
bad.sbx.example:apply) echo "REFUSED a statement fed over SSH: not signed by a key it trusts"; exit 1;;
*) echo "unexpected $*" >&2; exit 9;;
esac
`)

	out, errs, code := trajrl(t, "", "keys", "status", "--json")
	if code != 0 {
		t.Fatalf("keys status --json: %d %q", code, errs)
	}
	var rep keyStatusReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range rep.Sandboxes {
		got[s.Name] = s.Result
		if s.Applied != nil {
			got[s.Name] += fmt.Sprint(" ", *s.Applied)
		}
	}
	want := map[string]string{"web": "behind 1", "api": "current 3", "bad": "behind 2", "nokey": "not asked",
		"old": "will apply at next unlock", "wt": "will apply at next unlock"}
	if rep.LatestSeq != 3 || !rep.Signed || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("keys status: seq %d %v\n%v\nwant %v", rep.LatestSeq, rep.Signed, got, want)
	}
	if out, _, code := trajrl(t, "", "keys", "status"); code != 0 || !strings.Contains(out, "2 running sandboxes have not applied statement 3. Now: trajrl keys sync --all") {
		t.Fatalf("keys status: %d %q", code, out)
	}

	out, errs, code = trajrl(t, "", "keys", "sync", "--all")
	for _, l := range []string{
		"web: applied: statement 3 (it had 1)\n",
		"api: current: statement 3 applied already\n",
		"bad: failed: sandbox-keys apply: exit status 1: REFUSED a statement fed over SSH: not signed by a key it trusts\n",
		"nokey: failed: no host key of nokey was verified on this machine: run trajrl verify nokey first\n",
		"old: will apply at next unlock: its next start sends statement 3: trajrl start old\n",
		"wt: will apply at next unlock: its unlock sends statement 3: trajrl unlock wt\n",
	} {
		if !strings.Contains(out, l) {
			t.Errorf("keys sync --all: no line %q in\n%s", l, out)
		}
	}
	if code != 1 || !strings.Contains(errs, "statement 3 NOT applied by 2 sandboxes: bad nokey") {
		t.Fatalf("keys sync --all: %d %q", code, errs)
	}
	if b, err := os.ReadFile(applied); err != nil || string(b) != string(signed) {
		t.Fatalf("web was fed %q (%v), want the statement", b, err)
	}
	if _, errs, code := trajrl(t, "", "keys", "sync", "--all", "web"); code != 2 || !strings.Contains(errs, "usage") {
		t.Fatalf("keys sync --all web: %d %q", code, errs)
	}

	// keys remove ends by saying how to feed every sandbox.
	out, errs, code = trajrl(t, "", "keys", "remove", strings.TrimSuffix(other, " laptop"))
	if code != 0 || put == "" || !strings.Contains(out, "trajrl keys sync --all") {
		t.Fatalf("keys remove: %d %q %q", code, out, errs)
	}
}

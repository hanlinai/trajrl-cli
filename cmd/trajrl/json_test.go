package main

// The machine interface (docs/cli.md, "For programs"): --json shapes, the
// exit statuses, a passphrase never asked for without a terminal, and
// several commands typed on one line refused before they reach the entry
// point.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/sbxapi"
)

// lastLine is the last line of s.
func lastLine(s string) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return l[len(l)-1]
}

// Task 0: "trajrl ls / trajrl whoami / trajrl doctor" is refused here,
// exit 2, and nothing reaches the entry point; the same words where a
// command takes them (a comment's text, a sandbox named trajrl) go on.
func TestSeveralCommandsOnOneLine(t *testing.T) {
	e := newFakeEntry(t, func(cmd string, _ io.Reader, out, _ io.Writer) int {
		fmt.Fprintln(out, "ran: "+cmd)
		return 0
	})
	newHome(t, e)
	for _, args := range [][]string{
		{"ls", "/", "trajrl", "whoami", "/", "trajrl", "doctor"},
		{"ls", ";", "whoami"},
		{"ls", "&&", "whoami"},
		{"ls", "|", "whoami"},
		{"ls", "trajrl", "whoami"},
		{"show", "web", "/", "trajrl", "ls"},
		{"comment", "web", "a", "note", "/", "trajrl", "ls"},
		{"tag", "web", "x", ";", "trajrl", "whoami"},
	} {
		_, errs, code := trajrl(t, "", args...)
		want := fmt.Sprintf("trajrl: this looks like several commands on one line (%q); run them one per line, e.g. trajrl ls, then trajrl whoami\n", strings.Join(args, " "))
		if code != 2 || errs != want {
			t.Errorf("trajrl %q: %d %q, want 2 %q", args, code, errs, want)
		}
	}
	if execs, conns := e.seen(); conns != 0 {
		t.Fatalf("the entry point was reached: %q", execs)
	}
	// With --json, the refusal is the error object.
	if _, errs, code := trajrl(t, "", "ls", "--json", "/", "trajrl", "whoami"); code != 2 ||
		errs != `{"error":"this looks like several commands on one line (\"ls --json / trajrl whoami\"); run them one per line, e.g. trajrl ls, then trajrl whoami","code":2}`+"\n" {
		t.Errorf("--json: %d %q", code, errs)
	}
	for _, args := range [][]string{
		{"comment", "web", "build", "/", "test", "box"},
		{"comment", "web", "run", "trajrl", "ls", "daily"},
		{"tag", "web", "trajrl", "new"},
		{"show", "trajrl", "--json"},
		{"rm", "trajrl", "--yes"},
		{"rename", "web", "trajrl"},
		{"entry", "ls", "/", "x"},
	} {
		out, errs, code := trajrl(t, "", args...)
		sent := strings.Join(args, " ")
		if args[0] == "entry" {
			sent = strings.Join(args[1:], " ")
		}
		if code != 0 || out != "ran: "+sent+"\n" {
			t.Errorf("trajrl %q: %d %q %q", args, code, out, errs)
		}
	}
}

func TestVersionJSON(t *testing.T) {
	out, errs, code := trajrl(t, "", "version", "--json")
	t.Logf("trajrl version --json: %s", out)
	if code != 0 || errs != "" || out != `{"version":"`+version+`","min_entry":null}`+"\n" {
		t.Fatalf("version --json: %d %q %q", code, out, errs)
	}
	if out, _, code := trajrl(t, "", "version"); code != 0 || out != "trajrl "+version+"\n" {
		t.Fatalf("version: %d %q", code, out)
	}
}

// bootEntry is an entry point that makes web and shows it, but hands over
// no TD: unlock web fails at the platform.
func bootEntry(t *testing.T) *fakeEntry {
	return newFakeEntry(t, func(cmd string, _ io.Reader, out, errw io.Writer) int {
		switch cmd {
		case "new web --size small":
			fmt.Fprintln(out, "web: created")
		case "show web --json":
			fmt.Fprintln(out, `{"name":"web","id":"`+idA+`","state":"waiting for its owner's key"}`)
		case "unlock web":
			fmt.Fprintln(errw, "web has no TD waiting")
			return 1
		default:
			fmt.Fprintf(errw, "unexpected: %s\n", cmd)
			return 2
		}
		return 0
	})
}

// ownerKeyFile makes the owner's key file under passphrase pass.
func ownerKeyFile(t *testing.T, h *home, pass string) string {
	t.Helper()
	m, err := ownerkey.NewMaster()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Wipe()
	if err := m.WriteKeyFile(filepath.Join(h.sbxkey, "owner.key"), []byte(pass)); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(h.dir, "pass")
	if err := os.WriteFile(file, []byte(pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// No terminal and no passphrase given: exit 3, with --json the one error
// object, and nothing is read from stdin or sent to the entry point.
func TestPassphraseNoTerminal(t *testing.T) {
	e := bootEntry(t)
	h := newHome(t, e)
	t.Setenv("TRAJRL_PASSPHRASE_FILE", "")
	testPolicy(t, filepath.Join(policyDir(), "img.json"), "1")
	ownerKeyFile(t, h, "a passphrase of length")
	const msg = "the owner key needs its passphrase: give -passphrase-file or TRAJRL_PASSPHRASE_FILE"
	for _, args := range [][]string{{"unlock", "web", "--json"}, {"start", "--json", "web"}, {"new", "web", "--size", "small", "--json"}} {
		out, errs, code := trajrl(t, "a passphrase of length\n", args...)
		if code != 3 || out != "" || lastLine(errs) != `{"error":"`+msg+`","code":3}` {
			t.Errorf("trajrl %q: %d %q %q", args, code, out, errs)
		}
	}
	if _, errs, code := trajrl(t, "", "unlock", "web"); code != 3 || errs != "trajrl: "+msg+"\n" {
		t.Errorf("unlock web: %d %q", code, errs)
	}
	if execs, conns := e.seen(); conns != 0 {
		t.Fatalf("the entry point was reached: %q", execs)
	}
}

// new NAME --size small --json: --json is trajrl's, taken off the
// platform's new; the passphrase comes from TRAJRL_PASSPHRASE_FILE; an
// unlock that fails is the error object on stderr, nothing on stdout.
func TestBootJSONFlagIsTrajrls(t *testing.T) {
	e := bootEntry(t)
	h := newHome(t, e)
	testPolicy(t, filepath.Join(policyDir(), "img.json"), "1")
	t.Setenv("TRAJRL_PASSPHRASE_FILE", ownerKeyFile(t, h, "a passphrase of length"))
	out, errs, code := trajrl(t, "", "new", "web", "--size", "small", "--json")
	if code != 1 || out != "" {
		t.Fatalf("new --json: %d %q %q", code, out, errs)
	}
	var e1 struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
	}
	if err := json.Unmarshal([]byte(lastLine(errs)), &e1); err != nil || e1.Code != 1 || !strings.Contains(e1.Error, "web has no TD waiting") {
		t.Fatalf("new --json, stderr %q: %+v %v", errs, e1, err)
	}
	t.Logf("trajrl new web --size small --json, its stderr's last line: %s", lastLine(errs))
	if execs, _ := e.seen(); len(execs) < 3 || execs[0] != "new web --size small" {
		t.Fatalf("the entry point was asked %q", execs)
	}
	// The entry point not there: 255.
	gone := *h.cfg
	gone.Entry = "127.0.0.1:1"
	if err := gone.save(); err != nil {
		t.Fatal(err)
	}
	if out, errs, code := trajrl(t, "", "unlock", "web", "--json"); code != 255 || out != "" || !strings.HasPrefix(lastLine(errs), `{"error":`) || !strings.HasSuffix(lastLine(errs), `"code":255}`) {
		t.Fatalf("unlock, no entry point: %d %q %q", code, out, errs)
	}
}

// fakeAPI is a sandbox's HTTPS API (cmd/sandbox-api's /v1), with host key
// srv: exec answers in its NDJSON with what it was asked, files are kept
// in memory.
func fakeAPI(t *testing.T) (addr, pin string) {
	t.Helper()
	_, srv, _ := ed25519.GenerateKey(rand.Reader)
	cert, err := sbxapi.SelfSigned(srv, true)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"/etc/motd": []byte("hello from web\n")}
	line := func(w io.Writer, l sbxapi.Line) { json.NewEncoder(w).Encode(l) }
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/exec":
			var e sbxapi.Exec
			json.NewDecoder(r.Body).Decode(&e)
			stdin, _ := base64.StdEncoding.DecodeString(e.StdinB64)
			line(w, sbxapi.Line{Stdout: []byte(fmt.Sprintf("argv=%q cwd=%s env=%v timeout=%d\n", e.Argv, e.Cwd, e.Env, e.TimeoutS))})
			line(w, sbxapi.Line{Stdout: append([]byte("stdin="), stdin...)})
			line(w, sbxapi.Line{Stderr: []byte("a warning\n")})
			code := 7
			line(w, sbxapi.Line{ExitCode: &code})
		case r.Method == "PUT" && r.URL.Path == "/v1/files":
			b, _ := io.ReadAll(r.Body)
			p := r.URL.Query().Get("path")
			files[p] = b
			sum := sha256.Sum256(b)
			json.NewEncoder(w).Encode(sbxapi.PutResult{Path: p, Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])})
		case r.Method == "GET" && r.URL.Path == "/v1/files":
			b, ok := files[r.URL.Query().Get("path")]
			if !ok {
				w.WriteHeader(404)
				fmt.Fprintln(w, `{"error":"no such file"}`)
				return
			}
			w.Write(b)
		default:
			w.WriteHeader(404)
		}
	}))
	// No ALPN on this side (an empty list, not httptest's default): the
	// client's sandbox-api/1 is ignored and HTTP/1.1 runs, as the real
	// API's wrapped connection does (cmd/sandbox-api/server.go).
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13,
		NextProtos: []string{}}
	s.StartTLS()
	t.Cleanup(s.Close)
	sp, _ := ssh.NewPublicKey(srv.Public())
	return s.Listener.Addr().String(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

// exec --json: the API's own NDJSON lines (stdout and stderr base64), the
// last {"exit_code": N}, and trajrl's exit status the command's; -cwd,
// -env (and -e), -timeout and -stdin reach the API.
func TestExecJSON(t *testing.T) {
	h := newHome(t, nil)
	addr, pin := fakeAPI(t)
	api := []string{"-pin", pin, "-connect", addr, "-host", "web-alice.sbx.example", "-i", h.keyFile}
	args := append(append([]string{"exec"}, api...), "-cwd", "/srv", "-env", "A=1", "-e", "B=2", "-timeout", "9", "-stdin", "web", "--json", "--", "sh", "-c", "echo --json")
	out, errs, code := trajrl(t, "some input", args...)
	t.Logf("trajrl exec --json, stdout:\n%s", out)
	if code != 7 || errs != "" {
		t.Fatalf("exec --json: %d %q %q", code, out, errs)
	}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	want := `{"stdout":"` + b64(`argv=["sh" "-c" "echo --json"] cwd=/srv env=map[A:1 B:2] timeout=9`+"\n") + `"}` + "\n" +
		`{"stdout":"` + b64("stdin=some input") + `"}` + "\n" +
		`{"stderr":"` + b64("a warning\n") + `"}` + "\n" +
		`{"exit_code":7}` + "\n"
	if out != want {
		t.Fatalf("exec --json stdout:\n%s\nwant:\n%s", out, want)
	}
	// Without --json, as it was: the bytes themselves.
	out, errs, code = trajrl(t, "", append(append([]string{"exec"}, api...), "web", "--", "true")...)
	if code != 7 || !strings.HasPrefix(out, `argv=["true"] cwd= env=map[] timeout=60`) || errs != "a warning\n" {
		t.Fatalf("exec: %d %q %q", code, out, errs)
	}
}

// cp --json: {"direction", "path", "bytes"} on stdout, both ways; the
// account for people on stderr.
func TestCpJSON(t *testing.T) {
	h := newHome(t, nil)
	addr, pin := fakeAPI(t)
	api := []string{"-pin", pin, "-connect", addr, "-host", "web-alice.sbx.example", "-i", h.keyFile}
	local := filepath.Join(h.dir, "notes.txt")
	os.WriteFile(local, []byte("twelve bytes"), 0o644)
	out, errs, code := trajrl(t, "", append(append([]string{"cp"}, api...), "--json", local, "web:/root/notes.txt")...)
	t.Logf("trajrl cp --json (in): %s", out)
	if code != 0 || out != `{"direction":"in","path":"/root/notes.txt","bytes":12}`+"\n" || !strings.Contains(errs, "12 bytes") {
		t.Fatalf("cp in --json: %d %q %q", code, out, errs)
	}
	back := filepath.Join(h.dir, "motd")
	out, _, code = trajrl(t, "", append(append([]string{"cp"}, api...), "web:/etc/motd", back, "--json")...)
	t.Logf("trajrl cp --json (out): %s", out)
	if b, _ := os.ReadFile(back); code != 0 || out != `{"direction":"out","path":"/etc/motd","bytes":15}`+"\n" || string(b) != "hello from web\n" {
		t.Fatalf("cp out --json: %d %q %q", code, out, b)
	}
	// The API's refusal: 1, the error object.
	out, errs, code = trajrl(t, "", append(append([]string{"cp"}, api...), "web:/nothere", back, "--json")...)
	if code != 1 || out != "" || errs != `{"error":"404 Not Found: no such file","code":1}`+"\n" {
		t.Fatalf("cp of no file: %d %q %q", code, out, errs)
	}
	// Stdout is the result: a file to stdout is refused.
	if _, errs, code = trajrl(t, "", append(append([]string{"cp"}, api...), "--json", "web:/etc/motd", "-")...); code != 2 || !strings.Contains(errs, `"code":2`) {
		t.Fatalf("cp --json to stdout: %d %q", code, errs)
	}
}

// The API not reached while the platform shows the sandbox waiting for
// its owner's key: exit 3, and what to run.
func TestExecWaitsForKey(t *testing.T) {
	e := bootEntry(t)
	h := newHome(t, e)
	_, pin := fakeAPI(t)
	out, errs, code := trajrl(t, "", "exec", "-pin", pin, "-connect", "127.0.0.1:1", "-host", "web-alice.sbx.example", "-i", h.keyFile, "--json", "web", "--", "true")
	if code != 3 || out != "" || !strings.Contains(lastLine(errs), `web waits for its owner's key: run trajrl unlock web)","code":3}`) {
		t.Fatalf("exec of a sandbox waiting for its key: %d %q %q", code, out, errs)
	}
}

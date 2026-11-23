package keycmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

const recoveredTestID = "sbx-0123456789abcdef"

// events is what happened, in order: the fake entry's execs and what sbxkey
// wrote on stderr.
type events struct {
	mu  sync.Mutex
	all []string
}

func (e *events) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.all = append(e.all, s)
}

func (e *events) list() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.all...)
}

// stderrTo records each write as an event.
type stderrTo struct{ e *events }

func (w stderrTo) Write(p []byte) (int, error) { w.e.add("stderr: " + string(p)); return len(p), nil }

// fakeEntry is a stand-in for the platform's SSH entry point, owner-key
// mode, for one sandbox "web": `show web --json` answers its view, with the
// recovered notice given (or none), and `unlock web` writes the unlock
// preamble, then holds the session open as the platform does while it
// splices it to the TD. Every exec is recorded.
func fakeEntry(t *testing.T, recovered string, ev *events) *ssh.Client {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	exit := func(ch ssh.Channel, code uint32) {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, code)
		ch.SendRequest("exit-status", false, b)
		ch.Close()
	}
	run := func(ch ssh.Channel, cmd string) {
		ev.add("exec: " + cmd)
		switch cmd {
		case "show web --json":
			v := map[string]any{"name": "web", "id": recoveredTestID, "state": "waiting for its owner's key"}
			if recovered != "" {
				v["recovered"] = recovered
			}
			json.NewEncoder(ch).Encode(v)
			exit(ch, 0)
		case "unlock web":
			fmt.Fprintf(ch, "%s %s\n", ownerkey.PreambleTag, recoveredTestID)
			io.Copy(io.Discard, ch)
			exit(ch, 0)
		default:
			fmt.Fprintf(ch.Stderr(), "unknown command: %s\n", cmd)
			exit(ch, 2)
		}
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "session" {
						nc.Reject(ssh.Prohibited, "no")
						continue
					}
					ch, r, _ := nc.Accept()
					go func() {
						for req := range r {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							var p struct{ Cmd string }
							ssh.Unmarshal(req.Payload, &p)
							req.Reply(true, nil)
							go run(ch, p.Cmd)
						}
					}()
				}
			}()
		}
	}()
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	csigner, _ := ssh.NewSignerFromKey(cpriv)
	client, err := userverify.DialEntry(l.Addr().String(), string(ssh.MarshalAuthorizedKey(signer.PublicKey())), []ssh.AuthMethod{ssh.PublicKeys(csigner)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

const recoveredTestNotice = "recovered on 2026-11-19T03:00:00Z from replica of 2026-11-19T02:55:00Z (its host failed); " +
	"what was written after 2026-11-19T02:55:00Z is lost; it waits for you: sbxkey unlock web"

// index is the position of the first event with prefix, -1 for none.
func index(all []string, prefix string) int {
	for i, e := range all {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

func tryUnlock(t *testing.T, recovered string, c recoveredCheck, isNew bool) ([]string, error) {
	t.Helper()
	ev := &events{}
	entry := fakeEntry(t, recovered, ev)
	c.errw = stderrTo{ev}
	conn, id, _, err := openUnlock(entry, "web", isNew, c, 10*time.Second)
	if err == nil {
		if id != recoveredTestID {
			t.Errorf("sandbox ID %q", id)
		}
		conn.Close()
	}
	return ev.list(), err
}

// The notice is read with show before the unlock, printed on stderr before
// any `unlock` exec, and the unlock goes on with -accept-recovered.
func TestRecoveredNoticeBeforeUnlock(t *testing.T) {
	all, err := tryUnlock(t, recoveredTestNotice+"\x1b[2J", recoveredCheck{accept: true}, false)
	if err != nil {
		t.Fatalf("with -accept-recovered: %v\n%q", err, all)
	}
	show, notice, unlock := index(all, "exec: show web --json"), index(all, "stderr: web is a recovered copy"), index(all, "exec: unlock web")
	if show < 0 || notice < 0 || unlock < 0 || !(show < notice && notice < unlock) {
		t.Fatalf("show %d, notice %d, unlock %d, want them in that order:\n%q", show, notice, unlock, all)
	}
	if !strings.Contains(all[notice], "  "+recoveredTestNotice) {
		t.Errorf("the notice is not shown whole: %q", all[notice])
	}
	if strings.Contains(strings.Join(all, ""), "\x1b") {
		t.Error("an escape sequence from the platform reached the terminal")
	}
}

// Without a terminal and without -accept-recovered: no `unlock` exec, and an
// error (sbxkey exits 1) that names the flag.
func TestRecoveredNoTerminalRefused(t *testing.T) {
	all, err := tryUnlock(t, recoveredTestNotice, recoveredCheck{}, false)
	if err == nil || !strings.Contains(err.Error(), "-accept-recovered") {
		t.Fatalf("no terminal, no flag: %v", err)
	}
	if index(all, "exec: unlock") >= 0 {
		t.Fatalf("unlock was run: %q", all)
	}
	if index(all, "stderr: web is a recovered copy") < 0 {
		t.Errorf("the notice was not shown: %q", all)
	}
}

// On a terminal the owner is asked; only y or yes goes on.
func TestRecoveredTerminalAsks(t *testing.T) {
	for answer, goesOn := range map[string]bool{"y": true, "YES": true, "": false, "n": false, "sure": false} {
		var asked string
		ask := func(p string) (string, error) { asked = p; return answer, nil }
		all, err := tryUnlock(t, recoveredTestNotice, recoveredCheck{tty: true, ask: ask}, false)
		if asked != "continue with this copy? [y/N] " {
			t.Errorf("%q: asked %q", answer, asked)
		}
		if ran := index(all, "exec: unlock web") >= 0; ran != goesOn || (err == nil) != goesOn {
			t.Errorf("answer %q: unlock run %v, err %v", answer, ran, err)
		}
	}
	ask := func(string) (string, error) { return "", errors.New("no answer") }
	if all, err := tryUnlock(t, recoveredTestNotice, recoveredCheck{tty: true, ask: ask}, false); err == nil || index(all, "exec: unlock") >= 0 {
		t.Errorf("no answer: %v, %q", err, all)
	}
}

// No notice: nothing is asked or printed but the wait, even without a
// terminal; new reads the view (for its web names, #113) but asks nothing
// (a new sandbox was never recovered).
func TestRecoveredNoneProceeds(t *testing.T) {
	ask := func(string) (string, error) { t.Error("asked with no notice"); return "", nil }
	all, err := tryUnlock(t, "", recoveredCheck{ask: ask}, false)
	if err != nil {
		t.Fatalf("no notice: %v", err)
	}
	if index(all, "exec: show web --json") != 0 || index(all, "exec: unlock web") < 0 || index(all, "stderr: web is a recovered") >= 0 {
		t.Errorf("no notice: %q", all)
	}
	all, err = tryUnlock(t, recoveredTestNotice, recoveredCheck{}, true)
	if err != nil || index(all, "stderr: web is a recovered") >= 0 || index(all, "exec: unlock web") < 0 {
		t.Errorf("new: %v, %q", err, all)
	}
}

// A show that fails stops the unlock before it is opened.
func TestRecoveredShowFails(t *testing.T) {
	ev := &events{}
	entry := fakeEntry(t, "", ev)
	_, _, _, err := openUnlock(entry, "db", false, recoveredCheck{accept: true, errw: io.Discard}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "before unlocking it") || index(ev.list(), "exec: unlock") >= 0 {
		t.Fatalf("show failed: %v, %q", err, ev.list())
	}
}

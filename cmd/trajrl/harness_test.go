package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// In a child process started by trajrl (below), the test binary is trajrl.
func TestMain(m *testing.M) {
	if os.Getenv("TRAJRL_TEST_MAIN") == "1" {
		os.Exit(run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeEntry is a stand-in for the platform's SSH entry point, as
// internal/cli/keycmd's recovered_test.go has one: any key logs in, each
// exec is recorded and answered by handle, which gets the command's stdin
// and returns its exit status.
type fakeEntry struct {
	addr, key string
	mu        sync.Mutex
	execs     []string
	conns     int
	handle    func(cmd string, stdin io.Reader, out, errw io.Writer) int
	// versions are the SSH clients' identification strings, a login each;
	// jumps the direct-tcpip channels asked for, HOST:PORT, which forward
	// (if set) connects, or refuses with an error.
	versions []string
	jumps    []string
	forward  func(host string, port uint32) (net.Conn, error)
}

func newFakeEntry(t *testing.T, handle func(cmd string, stdin io.Reader, out, errw io.Writer) int) *fakeEntry {
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
	e := &fakeEntry{addr: l.Addr().String(), key: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), handle: handle}
	serve := func(ch ssh.Channel, cmd string) {
		e.mu.Lock()
		e.execs = append(e.execs, cmd)
		e.mu.Unlock()
		code := e.handle(cmd, ch, ch, ch.Stderr())
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(code))
		ch.SendRequest("exit-status", false, b)
		ch.Close()
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
				e.mu.Lock()
				e.conns++
				e.versions = append(e.versions, string(sc.ClientVersion()))
				e.mu.Unlock()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() == "direct-tcpip" {
						go e.jump(nc)
						continue
					}
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
							go serve(ch, p.Cmd)
						}
					}()
				}
			}()
		}
	}()
	return e
}

// jump serves a direct-tcpip channel with forward, as the entry point's
// jump does.
func (e *fakeEntry) jump(nc ssh.NewChannel) {
	var req struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	ssh.Unmarshal(nc.ExtraData(), &req)
	e.mu.Lock()
	e.jumps = append(e.jumps, net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))))
	forward := e.forward
	e.mu.Unlock()
	if forward == nil {
		nc.Reject(ssh.Prohibited, "no forwarding here")
		return
	}
	up, err := forward(req.Host, req.Port)
	if err != nil {
		nc.Reject(ssh.Prohibited, err.Error())
		return
	}
	defer up.Close()
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, ch); done <- struct{}{} }()
	go func() { io.Copy(ch, up); ch.CloseWrite(); done <- struct{}{} }()
	<-done
}

// seen is what the entry point was asked, and how many logins it had.
func (e *fakeEntry) seen() ([]string, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.execs...), e.conns
}

// home is one owner's machine: trajrl's, sbxkey's and the user's
// directories, an SSH key file, and trajrl's configuration naming entry.
type home struct {
	dir, trajrl, sbxkey, keyFile string
	cfg                          *config
}

func newHome(t *testing.T, e *fakeEntry) *home {
	t.Helper()
	d := t.TempDir()
	h := &home{dir: d, trajrl: filepath.Join(d, "trajrl"), sbxkey: filepath.Join(d, "sbxkey"), keyFile: filepath.Join(d, "id_ed25519")}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(h.sbxkey, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRAJRL_DIR", h.trajrl)
	t.Setenv("SBXKEY_DIR", h.sbxkey)
	t.Setenv("HOME", filepath.Join(d, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(d, "xdg"))
	t.Setenv("SSH_AUTH_SOCK", "")
	if e != nil {
		h.cfg = &config{Entry: e.addr, EntryKey: e.key, Identity: h.keyFile, Domain: "sbx.example"}
		if err := h.cfg.save(); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// trajrl runs trajrl as a program of its own (the test binary, see
// TestMain) in the environment the test set, with stdin, and returns what
// it printed and its exit status.
func trajrl(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	return runAs(t, os.Environ(), stdin, args...)
}

func runAs(t *testing.T, env []string, stdin string, args ...string) (string, string, int) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := &exec.Cmd{Path: self, Args: append([]string{"trajrl"}, args...), Env: append(env, "TRAJRL_TEST_MAIN=1"), Stdin: strings.NewReader(stdin)}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatal(err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

// testPolicy writes a launch policy that loads (its measurements made up).
func testPolicy(t *testing.T, path, mrtd string) string {
	t.Helper()
	p := `{"mrtd": "` + strings.Repeat(mrtd, 96) + `", "rtmr0": "` + strings.Repeat("a1", 48) + `", "rtmr1": "` + strings.Repeat("2", 96) +
		`", "rtmr2": "` + strings.Repeat("3", 96) + `", "td_attributes": "0000001000000000", "xfam": "e702000000000000", "bind_mrconfigid": true}` + "\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(p), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/sshsetup"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// standInSandbox is an SSH server standing for a sandbox's sshd: any key
// logs in, and an exec of COMMAND answers "web ran COMMAND as USER" and
// exits 0. It returns its address and its host key's known_hosts form.
func standInSandbox(t *testing.T) (addr, hostKey string) {
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
						defer ch.Close()
						for req := range r {
							if req.Type != "exec" {
								if req.WantReply {
									req.Reply(false, nil)
								}
								continue
							}
							var p struct{ Cmd string }
							ssh.Unmarshal(req.Payload, &p)
							req.Reply(true, nil)
							fmt.Fprintf(ch, "web ran %s as %s\n", p.Cmd, sc.User())
							ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 0))
							return
						}
					}()
				}
			}()
		}
	}()
	return l.Addr().String(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

// trajrl proxy, end to end with the real ssh: ProxyCommand="TRAJRL proxy
// %h %p" carries ssh's session to the sandbox through the entry point
// (here a stand-in that forwards to a stand-in sandbox), the sandbox's host
// key checked by ssh as ever. trajrl says it is trajrl, asks for
// HOST:PORT as ssh gives them, and prints nothing of its own on stdout.
func TestProxyWithOpenSSH(t *testing.T) {
	needPrograms(t, "ssh")
	sandboxAddr, sandboxKey := standInSandbox(t)
	e := newFakeEntry(t, nil)
	e.forward = func(host string, port uint32) (net.Conn, error) {
		if host != "web.sbx.example" || port != 22 {
			return nil, errors.New("only to port 22 of a running sandbox of yours, by its name")
		}
		return net.Dial("tcp", sandboxAddr)
	}
	h := newHome(t, e)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := sshsetup.ProxyProgram(self, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	known := filepath.Join(h.dir, "known_hosts")
	os.WriteFile(known, []byte("web.sbx.example "+sandboxKey+"\n"), 0o600)
	login := func(target string, command ...string) (string, string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ssh", append([]string{"-F", "/dev/null",
			"-o", "ProxyCommand=" + prog + " proxy %h %p", "-o", "UserKnownHostsFile=" + known, "-o", "StrictHostKeyChecking=yes",
			"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", h.keyFile, "root@" + target}, command...)...)
		cmd.Env = append(os.Environ(), "TRAJRL_TEST_MAIN=1")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		return out.String(), errb.String(), err
	}
	out, errs, err := login("web.sbx.example", "uname", "-a")
	if err != nil || out != "web ran uname -a as root\n" {
		t.Fatalf("ssh through trajrl proxy: %v\n%q\n%s", err, out, errs)
	}
	e.mu.Lock()
	versions, jumps := append([]string(nil), e.versions...), append([]string(nil), e.jumps...)
	e.mu.Unlock()
	if len(versions) != 1 || versions[0] != "SSH-2.0-trajrl_"+version || versions[0] != userverify.ClientVersion(version) {
		t.Errorf("trajrl said it was %q", versions)
	}
	if len(jumps) != 1 || jumps[0] != "web.sbx.example:22" {
		t.Errorf("the jumps asked for: %q", jumps)
	}
	// A name the entry point does not carry: ssh fails, with trajrl's
	// reason on stderr.
	if _, errs, err := login("nosuch.sbx.example", "true"); err == nil || !strings.Contains(errs, "trajrl proxy: the entry point did not carry nosuch.sbx.example:22: only to port 22") {
		t.Errorf("ssh to a sandbox the entry point does not carry: %v\n%s", err, errs)
	}
	// Another host key at that name: ssh refuses, as without trajrl.
	os.WriteFile(known, []byte("web.sbx.example "+e.key+"\n"), 0o600)
	if _, errs, err := login("web.sbx.example", "true"); err == nil || !strings.Contains(errs, "Host key verification failed") {
		t.Errorf("ssh with another host key on record: %v\n%s", err, errs)
	}
}

// trajrl proxy alone: its stdout is the connection and nothing else. Each
// failure is said on stderr, exit 255 (2 for its usage), stdout empty, and
// nothing is asked.
func TestProxyStdoutIsTheConnection(t *testing.T) {
	sandboxAddr, _ := standInSandbox(t)
	e := newFakeEntry(t, nil)
	e.forward = func(host string, port uint32) (net.Conn, error) {
		if host != "web.sbx.example" {
			return nil, errors.New("only to port 22 of a running sandbox of yours, by its name")
		}
		return net.Dial("tcp", sandboxAddr)
	}
	h := newHome(t, e)

	// The sandbox's SSH greeting comes back on stdout as it was sent;
	// stdin closed, trajrl ends with 0 once the sandbox has closed too.
	out, errs, code := trajrl(t, "SSH-2.0-test\r\n", "proxy", "web.sbx.example", "22")
	if code != 0 || !strings.HasPrefix(out, "SSH-2.0-Go\r\n") || errs != "" {
		t.Errorf("proxy: %d %q %q", code, out, errs)
	}
	for _, c := range []struct {
		args []string
		code int
		said string
	}{
		{[]string{"proxy"}, 2, "usage: trajrl proxy HOST PORT"},
		{[]string{"proxy", "web.sbx.example"}, 2, "usage: trajrl proxy HOST PORT"},
		{[]string{"proxy", "web.sbx.example", "ssh"}, 255, `trajrl proxy: "ssh" is not a port`},
		{[]string{"proxy", "nosuch.sbx.example", "22"}, 255, "trajrl proxy: the entry point did not carry nosuch.sbx.example:22: only to port 22 of a running sandbox of yours"},
	} {
		out, errs, code := trajrl(t, "", c.args...)
		if code != c.code || out != "" || !strings.Contains(errs, c.said) {
			t.Errorf("%q: %d %q %q", c.args, code, out, errs)
		}
	}
	// Not set up, or a key with a passphrase and no agent: said, not asked.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	locked, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	os.WriteFile(h.keyFile, pem.EncodeToMemory(locked), 0o600)
	if out, errs, code := trajrl(t, "", "proxy", "web.sbx.example", "22"); code != 255 || out != "" || !strings.Contains(errs, "passphrase") {
		t.Errorf("proxy with a locked key: %d %q %q", code, out, errs)
	}
	os.Remove(configPath())
	if out, errs, code := trajrl(t, "", "proxy", "web.sbx.example", "22"); code != 255 || out != "" || !strings.Contains(errs, "this machine is not set up") {
		t.Errorf("proxy, not set up: %d %q %q", code, out, errs)
	}
}

// The identification string trajrl sends is what trajrl version says,
// in the characters SSH allows.
func TestClientVersion(t *testing.T) {
	for v, want := range map[string]string{
		"0.2.0":      "SSH-2.0-trajrl_0.2.0",
		"0.3.0-rc.1": "SSH-2.0-trajrl_0.3.0_rc.1",
		"1.0 beta":   "SSH-2.0-trajrl_1.0_beta",
		"":           "SSH-2.0-trajrl_unknown",
		"é\r\nx":     "SSH-2.0-trajrl____x",
	} {
		if got := userverify.ClientVersion(v); got != want {
			t.Errorf("ClientVersion(%q) = %q, want %q", v, got, want)
		}
	}
	if got := userverify.ClientVersion(version); got != "SSH-2.0-trajrl_"+version {
		t.Errorf("trajrl %s says %q", version, got)
	}
	if userverify.ClientPrefix != "SSH-2.0-trajrl_" {
		t.Errorf("ClientPrefix %q", userverify.ClientPrefix)
	}
}

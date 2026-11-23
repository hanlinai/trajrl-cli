package attest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/proto"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

// A sandbox's owner checks their running sandbox themselves. These tests use
// the stand-in PKI, the only way an accepted quote exists offline; that the
// production verifier refuses everything signed under it is tested elsewhere.

func ownerKey() string {
	return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnerVerifiesThisHostKeyItself00000000000"
}

func TestVerifyRunning(t *testing.T) {
	s, pol := attest.NewStandIn(t, false)
	v := s.Verifier(pol, nil)
	ctx := context.Background()
	nonce := bytes.Repeat([]byte{7}, 32)
	rd := proto.UserReportData(nonce, ownerKey())
	after := proto.RTMR3Running(proto.RTMR3BootDone(), proto.ImageBase)
	good := s.Quote(rd, after[:])

	res, err := v.VerifyRunning(ctx, good, rd, attest.HWSandboxID, proto.ImageBase)
	if err != nil || res.PlatformTCB != "UpToDate" || res.ModuleTCBStatus != "UpToDate" {
		t.Fatalf("a booted TD's quote over the owner's nonce and its host key: %v %+v", err, res)
	}
	// The same quote gets no key: for the broker the boot stage is over.
	if _, err := v.Verify(ctx, good, rd, attest.HWSandboxID); err == nil || !strings.Contains(err.Error(), "quote policy") {
		t.Fatalf("the broker's check on an owner's quote: %v", err)
	}
	// And a boot quote is not an owner's quote: the labels differ.
	if boot := proto.ReportData(attest.HWSandboxID, nonce, []byte(ownerKey())); boot == rd {
		t.Fatal("boot evidence and owner evidence commit to the same report data")
	}

	other := proto.RTMR3BootDone()
	onlyUnlock := proto.RTMR3AfterBoot()
	refused := map[string]struct {
		quote []byte
		rd    [64]byte
		id    string
	}{
		"another nonce (a replayed quote)":            {good, proto.UserReportData(bytes.Repeat([]byte{8}, 32), ownerKey()), attest.HWSandboxID},
		"another SSH host key (something in between)": {good, proto.UserReportData(nonce, "ssh-ed25519 AAAAsomeoneelse"), attest.HWSandboxID},
		"another sandbox's identity":                  {good, rd, attest.HWOtherSandboxID},
		"a TD that has not completed its boot stage":  {s.Quote(rd, nil), rd, attest.HWSandboxID},
		"a TD whose RTMR3 was extended with more":     {s.Quote(rd, other[:]), rd, attest.HWSandboxID},
		"a TD whose RTMR3 shows no image (#112)":      {s.Quote(rd, onlyUnlock[:]), rd, attest.HWSandboxID},
		"one bit of the quote changed":                {flip(good, 700), rd, attest.HWSandboxID},
		"not a quote":                                 {[]byte("hello"), rd, attest.HWSandboxID},
	}
	for name, c := range refused {
		if _, err := v.VerifyRunning(ctx, c.quote, c.rd, c.id, proto.ImageBase); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Other measurements: another image.
	wrong := *pol
	wrong.RTMR1 = strings.Repeat("ab", 48)
	if _, err := s.Verifier(&wrong, nil).VerifyRunning(ctx, good, rd, attest.HWSandboxID, proto.ImageBase); err == nil || !strings.Contains(err.Error(), "quote policy") {
		t.Errorf("a policy for another image: %v", err)
	}
	// A platform Intel rates out of date is not verified, whatever else holds.
	rated, pol2 := attest.NewStandIn(t, true)
	if _, err := rated.Verifier(pol2, nil).VerifyRunning(ctx, rated.Quote(rd, after[:]), rd, attest.HWSandboxID, proto.ImageBase); err == nil || !strings.Contains(err.Error(), "authenticity/TCB") {
		t.Errorf("an out-of-date platform: %v", err)
	}
	// A verifier trusting Intel's root, as the production one does, has no
	// use for any of these stand-in quotes: their certificate chain ends
	// somewhere else. (The stand-in's collateral and clock are kept, so this
	// refusal is the chain's and needs no network.)
	if _, err := s.IntelRootVerifier(pol).VerifyRunning(ctx, good, rd, attest.HWSandboxID, proto.ImageBase); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("a quote signed under the stand-in PKI, to a verifier that trusts Intel's root: %v", err)
	}
}

func flip(b []byte, at int) []byte {
	c := append([]byte{}, b...)
	c[at] ^= 1
	return c
}

// sshServer is a minimal SSH server for these tests: it runs exec with a
// function, and optionally carries direct-tcpip connections.
type sshServer struct {
	addr    string
	hostKey string
	signer  ssh.Signer
}

func serveSSH(t *testing.T, exec func(cmd string) (out, errs string, code int), forward func(host string) (net.Conn, error)) *sshServer {
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
					switch {
					case nc.ChannelType() == "direct-tcpip" && forward != nil:
						var req struct {
							Host string
							Port uint32
							OH   string
							OP   uint32
						}
						ssh.Unmarshal(nc.ExtraData(), &req)
						up, err := forward(req.Host)
						if err != nil {
							nc.Reject(ssh.ConnectionFailed, err.Error())
							continue
						}
						ch, r, _ := nc.Accept()
						go ssh.DiscardRequests(r)
						go func() { io.Copy(up, ch); up.Close() }()
						go func() { io.Copy(ch, up); ch.Close() }()
					case nc.ChannelType() == "session":
						ch, r, _ := nc.Accept()
						go func() {
							defer ch.Close()
							for req := range r {
								if req.Type != "exec" {
									req.Reply(false, nil)
									continue
								}
								var p struct{ Command string }
								ssh.Unmarshal(req.Payload, &p)
								req.Reply(true, nil)
								out, errs, code := exec(p.Command)
								io.WriteString(ch, out)
								io.WriteString(ch.Stderr(), errs)
								b := make([]byte, 4)
								binary.BigEndian.PutUint32(b, uint32(code))
								ch.SendRequest("exit-status", false, b)
								return
							}
						}()
					default:
						nc.Reject(ssh.Prohibited, "no")
					}
				}
			}()
		}
	}()
	return &sshServer{addr: l.Addr().String(), signer: signer,
		hostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))}
}

// The whole check, as sbxverify does it: over SSH, against a "sandbox" that
// answers sandbox-attest with what a TD would give.
func TestOwnerVerifiesOverSSH(t *testing.T) {
	s, pol := attest.NewStandIn(t, false)
	v := s.Verifier(pol, nil)
	after := proto.RTMR3Running(proto.RTMR3BootDone(), proto.ImageBase)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	owner, _ := ssh.NewSignerFromKey(priv)
	auth := []ssh.AuthMethod{ssh.PublicKeys(owner)}
	ctx := context.Background()

	// td answers as a sandbox that is a TD: the quote is over the nonce it
	// is given and over its own host key.
	var td *sshServer
	attestCmd := func(cmd string, key string, rtmr3 []byte) (string, string, int) {
		f := strings.Fields(cmd)
		if len(f) < 2 || f[0] != "sandbox-attest" {
			return "", "unknown command", 127
		}
		nonce, _ := hex.DecodeString(f[1])
		ev, _ := json.Marshal(userverify.Evidence{Version: 1, Nonce: f[1], HostKey: key, Image: proto.ImageBase,
			Quote: base64.StdEncoding.EncodeToString(s.Quote(proto.UserReportData(nonce, key), rtmr3))})
		return string(ev) + "\n", "", 0
	}
	td = serveSSH(t, func(cmd string) (string, string, int) { return attestCmd(cmd, td.hostKey, after[:]) }, nil)

	rep, err := userverify.Check(ctx, userverify.Target{Addr: td.addr, ID: attest.HWSandboxID, Auth: auth}, v)
	if err != nil || rep.HostKey != td.hostKey || rep.Quote.PlatformTCB != "UpToDate" || len(rep.Nonce) != 64 {
		t.Fatalf("a genuine sandbox: %v %+v", err, rep)
	}
	// Two checks never use the same nonce.
	rep2, _ := userverify.Check(ctx, userverify.Target{Addr: td.addr, ID: attest.HWSandboxID, Auth: auth}, v)
	if rep2 == nil || rep2.Nonce == rep.Nonce {
		t.Fatal("the nonce was reused")
	}

	// Something in between: it answers the SSH session itself, with its own
	// host key, and passes the owner's question on to the real sandbox. The
	// quote it brings back is genuine and fresh, and names another key.
	relay := func(cmd string) (string, string, int) {
		c, err := ssh.Dial("tcp", td.addr, &ssh.ClientConfig{User: "root", Auth: auth, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		if err != nil {
			return "", err.Error(), 1
		}
		defer c.Close()
		sess, _ := c.NewSession()
		out, _ := sess.Output(cmd)
		return string(out), "", 0
	}
	mitm := serveSSH(t, relay, nil)
	_, err = userverify.Check(ctx, userverify.Target{Addr: mitm.addr, ID: attest.HWSandboxID, Auth: auth}, v)
	if err == nil || !strings.Contains(err.Error(), "answering in its place") {
		t.Fatalf("with a relay in between: %v", err)
	}

	// Other ways not to be the owner's sandbox.
	cases := map[string]func(cmd string) (string, string, int){
		"a machine that is not a TD": func(string) (string, string, int) {
			return "", "sandbox-attest: this machine is not a TDX guest; there is no quote to give", 3
		},
		"a quote made earlier, for another nonce": func(cmd string) (string, string, int) {
			return attestCmd("sandbox-attest "+strings.Repeat("11", 32), td.hostKey, after[:])
		},
		"a TD still in its boot stage": func(cmd string) (string, string, int) { return attestCmd(cmd, td.hostKey, nil) },
		"output that is not evidence":  func(string) (string, string, int) { return "hello\n", "", 0 },
		"evidence without a quote": func(cmd string) (string, string, int) {
			return `{"version":1,"quote":""}` + "\n", "", 0
		},
	}
	for name, exec := range cases {
		// Each of these servers has a host key of its own, so those that
		// return a quote for td's key fail on the key as well; the point is
		// that none of them verifies.
		srv := serveSSH(t, exec, nil)
		if _, err := userverify.Check(ctx, userverify.Target{Addr: srv.addr, ID: attest.HWSandboxID, Auth: auth}, v); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// The right sandbox, asked about under another sandbox's ID.
	if _, err := userverify.Check(ctx, userverify.Target{Addr: td.addr, ID: attest.HWOtherSandboxID, Auth: auth}, v); err == nil {
		t.Error("verified under another sandbox's ID")
	}

	// Through the service's entry point, by name: the entry point says which
	// sandbox it is and carries the connection; it is not believed about the
	// host key.
	entryExec := func(cmd string) (string, string, int) {
		if cmd == "show web --json" {
			return fmt.Sprintf(`{"name":"web","id":%q,"state":"running","host_key":"ssh-ed25519 AAAAwhattheservicesays"}`+"\n", attest.HWSandboxID), "", 0
		}
		if cmd == "show down --json" {
			return fmt.Sprintf(`{"name":"down","id":%q,"state":"stopped"}`+"\n", attest.HWSandboxID), "", 0
		}
		return "", "not found", 1
	}
	entry := serveSSH(t, entryExec, func(host string) (net.Conn, error) {
		if host != "web" {
			return nil, fmt.Errorf("no")
		}
		return net.Dial("tcp", td.addr)
	})
	rep, err = userverify.Check(ctx, userverify.Target{Entry: entry.addr, EntryKey: entry.hostKey, Name: "web", Auth: auth}, v)
	if err != nil || rep.SandboxID != attest.HWSandboxID || rep.HostKey != td.hostKey || !strings.Contains(rep.ToldHostKey, "whattheservicesays") {
		t.Fatalf("through the entry point: %v %+v", err, rep)
	}
	// The entry point's own key is pinned.
	if _, err := userverify.Check(ctx, userverify.Target{Entry: entry.addr, EntryKey: td.hostKey, Name: "web", Auth: auth}, v); err == nil {
		t.Error("an entry point with another host key was used")
	}
	for _, name := range []string{"down", "nosuch"} {
		if _, err := userverify.Check(ctx, userverify.Target{Entry: entry.addr, EntryKey: entry.hostKey, Name: name, Auth: auth}, v); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := userverify.Check(ctx, userverify.Target{Auth: auth}, v); err == nil {
		t.Error("verified without saying what")
	}
}

// The explanation an owner is shown next to a verdict: which checks hold.
func TestExplainRunning(t *testing.T) {
	ctx := context.Background()
	nonce := bytes.Repeat([]byte{7}, 32)
	rd := proto.UserReportData(nonce, ownerKey())
	after := proto.RTMR3Running(proto.RTMR3BootDone(), proto.ImageBase)
	failed := func(list []attest.Check) (names []string) {
		for _, c := range list {
			if !c.OK {
				names = append(names, c.What)
			}
		}
		return
	}

	s, pol := attest.NewStandIn(t, false)
	v := s.Verifier(pol, nil)
	good := s.Quote(rd, after[:])
	if list := v.ExplainRunning(ctx, good, rd, attest.HWSandboxID, proto.ImageBase); len(list) < 12 || len(failed(list)) != 0 {
		t.Fatalf("a quote that verifies: %d checks, failed %q", len(list), failed(list))
	}
	// An out-of-date platform: the rating fails and nothing else does, and
	// the verdict is still a refusal.
	rated, pol2 := attest.NewStandIn(t, true)
	rv := rated.Verifier(pol2, nil)
	q := rated.Quote(rd, after[:])
	if _, err := rv.VerifyRunning(ctx, q, rd, attest.HWSandboxID, proto.ImageBase); err == nil {
		t.Fatal("an out-of-date platform verified")
	}
	f := failed(rv.ExplainRunning(ctx, q, rd, attest.HWSandboxID, proto.ImageBase))
	if len(f) == 0 {
		t.Fatal("an out-of-date platform: no check failed")
	}
	for _, name := range f {
		if !strings.Contains(name, "Intel rates") {
			t.Errorf("an out-of-date platform: %q failed, which is not a rating", name)
		}
	}
	// Another image, another nonce, another sandbox: the matching line fails.
	wrong := *pol
	wrong.RTMR1 = strings.Repeat("ab", 48)
	for name, c := range map[string]struct {
		list []attest.Check
		want string
	}{
		"another image":   {s.Verifier(&wrong, nil).ExplainRunning(ctx, good, rd, attest.HWSandboxID, proto.ImageBase), "RTMR1"},
		"another nonce":   {v.ExplainRunning(ctx, good, proto.UserReportData(bytes.Repeat([]byte{8}, 32), ownerKey()), attest.HWSandboxID, proto.ImageBase), "nonce"},
		"another sandbox": {v.ExplainRunning(ctx, good, rd, attest.HWOtherSandboxID, proto.ImageBase), "MRCONFIGID"},
		"boot not closed": {v.ExplainRunning(ctx, s.Quote(rd, nil), rd, attest.HWSandboxID, proto.ImageBase), "RTMR3"},
	} {
		f := failed(c.list)
		if len(f) != 2 || !strings.Contains(f[0], c.want) || !strings.Contains(f[1], "every field") {
			t.Errorf("%s: failed checks %q, want the one about %s and the policy as a whole", name, f, c.want)
		}
	}
	if list := v.ExplainRunning(ctx, []byte("hello"), rd, attest.HWSandboxID, proto.ImageBase); len(list) != 1 || list[0].OK {
		t.Errorf("not a quote: %+v", list)
	}
	if list := v.ExplainRunning(ctx, flip(good, 700), rd, attest.HWSandboxID, proto.ImageBase); len(failed(list)) == 0 {
		t.Error("one bit changed: every check held")
	}
}

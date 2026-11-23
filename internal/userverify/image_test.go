package userverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// fakeVerifier stands in for attest.TDX: a "quote" is the RTMR3 it shows,
// and it verifies when that is the value asked for. (The quote's signature,
// TCB and measurements are attest's tests; here it is what Check does with
// the image.)
type fakeVerifier struct{ asked []string }

func (f *fakeVerifier) check(quote []byte, want [48]byte) (*attest.Result, error) {
	res := &attest.Result{RTMRs: []string{"", "", "", fmt.Sprintf("%x", quote)}}
	if !bytes.Equal(quote, want[:]) {
		return res, errors.New("quote policy: RTMR3 differs")
	}
	return res, nil
}

func (f *fakeVerifier) VerifyRunning(_ context.Context, quote []byte, _ [64]byte, _, image string) (*attest.Result, error) {
	f.asked = append(f.asked, image)
	return f.check(quote, proto.RTMR3Running(proto.RTMR3BootDone(), image))
}

func (f *fakeVerifier) VerifyRunningAs(_ context.Context, quote []byte, _ [64]byte, _ string, rtmr3 [48]byte) (*attest.Result, error) {
	return f.check(quote, rtmr3)
}

// fakeSandbox answers SSH exec requests with answer(cmd).
func fakeSandbox(t *testing.T, answer func(cmd string) (string, int)) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{NoClientAuth: true}
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
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							r.Reply(true, nil)
							cmd := string(r.Payload[4:])
							out, code := answer(cmd)
							ch.Write([]byte(out))
							st := make([]byte, 4)
							binary.BigEndian.PutUint32(st, uint32(code))
							ch.SendRequest("exit-status", false, st)
							return
						}
					}()
				}
			}()
		}
	}()
	return l.Addr().String()
}

const (
	digest1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digest2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// sandbox is a running sandbox whose RTMR3 is rtmr3 and which names says as
// its image, in sandbox-attest's output or, with inEvidence false, only in
// /run/tdx-sandbox/image (a sandbox-attest from before #112).
func sandbox(t *testing.T, rtmr3 [48]byte, says string, inEvidence bool) Target {
	addr := fakeSandbox(t, func(cmd string) (string, int) {
		switch {
		case strings.HasPrefix(cmd, "sandbox-attest "):
			ev := Evidence{Version: 1, Quote: base64.StdEncoding.EncodeToString(rtmr3[:])}
			if inEvidence {
				ev.Image = says
			}
			b, _ := json.Marshal(ev)
			return string(b) + "\n", 0
		case strings.HasPrefix(cmd, "cat /run/tdx-sandbox/image"):
			return says + "\n", 0
		}
		return "", 127
	})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	return Target{Addr: addr, ID: "sbx-00000000000000c1", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}}
}

// The image a running sandbox names is checked against RTMR3 (#112): the
// broker's sandboxes (VerifyRunning) and the owner's (OwnerRTMR3).
func TestCheckImageAgainstRTMR3(t *testing.T) {
	ctx := context.Background()
	for _, img := range []string{digest1, proto.ImageBase} {
		for _, inEv := range []bool{true, false} {
			v := &fakeVerifier{}
			rep, err := Check(ctx, sandbox(t, proto.RTMR3Running(proto.RTMR3BootDone(), img), img, inEv), v)
			if err != nil || rep.Image != img || len(v.asked) != 1 || v.asked[0] != img {
				t.Fatalf("%s (in the evidence: %v): %v %+v", img, inEv, err, rep)
			}
		}
	}
	// A sandbox that names another image than its RTMR3 shows.
	if _, err := Check(ctx, sandbox(t, proto.RTMR3Running(proto.RTMR3BootDone(), digest1), digest2, true), &fakeVerifier{}); err == nil {
		t.Fatal("a reported digest that does not match RTMR3 verified")
	}
	if _, err := Check(ctx, sandbox(t, proto.RTMR3Running(proto.RTMR3BootDone(), digest1), proto.ImageBase, false), &fakeVerifier{}); err == nil {
		t.Fatal("a sandbox running an image verified as base")
	}
	// Something that is neither base nor a digest is refused before any
	// verification.
	v := &fakeVerifier{}
	if _, err := Check(ctx, sandbox(t, proto.RTMR3AfterBoot(), "latest", true), v); err == nil || len(v.asked) != 0 {
		t.Fatalf("an image named latest: %v", err)
	}

	// With the owner's key: the owner's unlock, then the image; then the
	// record.
	unlock := proto.RTMR3BootDone()
	unlock[0] ^= 1 // any value the owner's key gives
	owner := func(t Target, record string) Target {
		t.OwnerRTMR3 = func(_, image string) ([48]byte, error) { return proto.RTMR3Running(unlock, image), nil }
		t.OwnerImage = func(_, image string) (string, error) {
			if image != record {
				return "", fmt.Errorf("REFUSED: runs %s; your record says %s", image, record)
			}
			return "as your record says", nil
		}
		return t
	}
	rep, err := Check(ctx, owner(sandbox(t, proto.RTMR3Running(unlock, digest1), digest1, true), digest1), &fakeVerifier{})
	if err != nil || !rep.UnlockedByOwner || rep.Image != digest1 || rep.ImageNote != "as your record says" {
		t.Fatalf("the owner's sandbox with its image: %v %+v", err, rep)
	}
	if _, err := Check(ctx, owner(sandbox(t, proto.RTMR3Running(unlock, digest1), digest2, true), digest2), &fakeVerifier{}); err == nil || !strings.Contains(err.Error(), "RTMR3") {
		t.Fatalf("names an image its RTMR3 does not show: %v", err)
	}
	if _, err := Check(ctx, owner(sandbox(t, proto.RTMR3Running(unlock, digest2), digest2, true), digest1), &fakeVerifier{}); err == nil || !strings.Contains(err.Error(), digest1) || !strings.Contains(err.Error(), digest2) {
		t.Fatalf("runs another image than the record's: %v", err)
	}
	if _, err := Check(ctx, owner(sandbox(t, proto.RTMR3Running(unlock, proto.ImageBase), proto.ImageBase, false), proto.ImageBase), &fakeVerifier{}); err != nil {
		t.Fatalf("the owner's base sandbox: %v", err)
	}
}

// A normal build refuses a sandbox that gives no quote, whatever image it
// names: there is no path without one.
func TestCheckImageNoQuoteIsRefused(t *testing.T) {
	if noQuoteAllowed() {
		t.Skip("a rehearsal build")
	}
	addr := fakeSandbox(t, func(cmd string) (string, int) {
		if strings.HasPrefix(cmd, "cat ") {
			return proto.ImageBase + "\n", 0
		}
		return "", 3
	})
	tg := sandbox(t, [48]byte{}, "", false)
	tg.Addr = addr
	called := false
	tg.OwnerImage = func(string, string) (string, error) { called = true; return "", nil }
	if rep, err := Check(context.Background(), tg, &fakeVerifier{}); err == nil || called || (rep != nil && rep.Rehearsal) {
		t.Fatalf("no quote: %v, image compared %v", err, called)
	}
}

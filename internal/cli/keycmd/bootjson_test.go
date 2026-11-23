package keycmd

import (
	"bytes"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/attest"
	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// The object new, start and unlock print with --json (docs/cli.md, "For
// programs"): every field always there, null where it is not known. A
// normal build cannot unlock without a real TD's quote, so the outcome
// here is the one ownerkey.Unlock returns for a verified first boot and
// for a later one.
func TestBootJSON(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBk8hWv1Hd2sWzG2Wn4nI3yJ2gW1dO4i8t5T0u0r7aXZ"
	running := "running"
	first := &ownerkey.Outcome{SandboxID: "sbx-00000000000000d1", Quote: &attest.Result{Policy: "img"}, Mode: proto.ModeTDX, Released: true,
		FirstBoot: true, HostKey: key, KnownHostsLine: "web,web.sbx.example " + key, Epoch: 1}
	later := &ownerkey.Outcome{SandboxID: "sbx-00000000000000d1", Quote: &attest.Result{Policy: "img"}, Mode: proto.ModeTDX, Released: true, Epoch: 4}
	unattested := &ownerkey.Outcome{SandboxID: "sbx-00000000000000d1", Mode: proto.ModeDev, Released: true, Epoch: 2}
	for _, c := range []struct {
		state   *string
		res     *ownerkey.Outcome
		hostKey string
		want    string
	}{
		{&running, first, key, `{"name":"web","state":"running","verified":true,"host_key_sha256":"SHA256:awtfbUNcpRM6CkkuGMJLYTvP6Xo+LoPFiFRoLCkweYk","boot":1}`},
		{nil, later, key, `{"name":"web","state":null,"verified":true,"host_key_sha256":"SHA256:awtfbUNcpRM6CkkuGMJLYTvP6Xo+LoPFiFRoLCkweYk","boot":4}`},
		{&running, later, "", `{"name":"web","state":"running","verified":true,"host_key_sha256":null,"boot":4}`},
		{&running, unattested, key, `{"name":"web","state":"running","verified":false,"host_key_sha256":"SHA256:awtfbUNcpRM6CkkuGMJLYTvP6Xo+LoPFiFRoLCkweYk","boot":2}`},
		{nil, nil, "", `{"name":"web","state":null,"verified":false,"host_key_sha256":null,"boot":null}`},
	} {
		var b bytes.Buffer
		writeBootJSON(&b, bootResultOf("web", c.state, c.res, c.hostKey))
		t.Logf("%s", b.String())
		if b.String() != c.want+"\n" {
			t.Errorf("got  %s\nwant %s", b.String(), c.want)
		}
	}
}

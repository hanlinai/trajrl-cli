package keycmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
)

// "sbxkey rename OLD NEW" (#72): the record follows the platform's rename,
// with its ID, epoch and host key; known_hosts pins the key for the new name
// and drops the old name's line; lines for other names stay. It needs no
// key file and no passphrase.
func TestRenameCommand(t *testing.T) {
	dir := t.TempDir()
	o := &opts{statePath: filepath.Join(dir, "sandboxes.json"), knownHostPath: filepath.Join(dir, "known_hosts")}
	st, err := ownerkey.OpenState(o.statePath, o.knownHostPath)
	if err != nil {
		t.Fatal(err)
	}
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBk8hWv1Hd2sWzG2Wn4nI3yJ2gW1dO4i8t5T0u0r7aXZ"
	if err := st.Put(ownerkey.Record{ID: "sbx-00000000000000a1", Name: "web", Provisioned: true, Epoch: 7, SSHHostKey: key}, true); err != nil {
		t.Fatal(err)
	}
	st.PinHostKey([]string{"web"}, key)
	st.PinHostKey([]string{"web.example.org"}, key) // a -known-host name of its own
	for _, c := range [][2]string{{"web", "a/b"}, {"nosuch", "x"}} {
		if err := rename(o, c[0], c[1]); err == nil {
			t.Errorf("rename %s %s: no error", c[0], c[1])
		}
	}
	if err := rename(o, "web", "site"); err != nil {
		t.Fatal(err)
	}
	st, _ = ownerkey.OpenState(o.statePath, o.knownHostPath)
	r := st.Get("sbx-00000000000000a1")
	if r == nil || r.Name != "site" || r.Epoch != 7 || r.SSHHostKey != key || !r.Provisioned {
		t.Fatalf("record: %+v", r)
	}
	kh, _ := os.ReadFile(o.knownHostPath)
	want := "web.example.org " + key + "\nsite " + key + "\n"
	if string(kh) != want {
		t.Fatalf("known_hosts:\n%s\nwant:\n%s", kh, want)
	}
	if err := rename(o, "site", "site"); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("rename onto itself: %v", err)
	}
}

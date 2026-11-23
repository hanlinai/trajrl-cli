package ownerkey

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/attest"
)

// The emulated rehearsal's guest, offline: the real boot code
// (internal/guest) with DevInsecure set, as the dev-insecure image runs it,
// against this package's Unlock, with a directory standing in for the disk.
// Used by the tests of both builds (evidence_test.go and
// evidence_rehearsal_test.go).

const devSandboxID = "sbx-00000000000000d1"

// devStorage keeps a disk as a directory: salt (its header), keys (what it
// was formatted with), epoch. open checks the keys as dm-integrity would.
const devStorage = `#!/bin/sh
D=__DISK__
keys() { cat "$KEYDIR/crypt.key" "$KEYDIR/integrity.key" "$KEYDIR/journal.key"; }
# The web names, as image/initrd/sandbox-storage keeps them (#113).
names() { if [ -e "$KEYDIR/web-names" ]; then cp "$KEYDIR/web-names" "$D/web-names"; else : > "$D/web-names"; fi; }
# The key statement, as image/initrd/sandbox-storage keeps it (#65).
stmt() { if [ -s "$KEYDIR/key-statement" ]; then cp "$KEYDIR/key-statement" "$D/pending-statement"; else rm -f "$D/pending-statement"; fi; }
case "$1" in
probe) [ -e "$D/salt" ] && { cat "$D/salt"; echo; exit 0; }; exit 3 ;;
format)
	[ -e "$D/salt" ] && { echo "refusing to format: the disk is not blank" >&2; exit 1; }
	keys > "$D/keys"; cp "$KEYDIR/disk-salt" "$D/salt"; names; stmt; echo format >> "$D/actions" ;;
open)
	keys | cmp -s - "$D/keys" || { echo "integrity open failed (wrong key or modified disk)" >&2; exit 1; }
	names; stmt; echo open >> "$D/actions" ;;
close) echo close >> "$D/actions" ;;
epoch-get) cat "$D/epoch" 2>/dev/null || true ;;
epoch-set) echo "$2" > "$D/epoch" ;;
*) exit 2 ;;
esac
`

// countingVerifier refuses every quote and counts the calls.
type countingVerifier struct{ calls atomic.Int32 }

func (v *countingVerifier) Verify(context.Context, []byte, [64]byte, string) (*attest.Result, error) {
	v.calls.Add(1)
	return nil, errors.New("no quote verifies here")
}

type devWorld struct {
	t    *testing.T
	disk string
	// storage is the stand-in storage script.
	storage string
}

func newDevWorld(t *testing.T) *devWorld {
	t.Helper()
	w := &devWorld{t: t, disk: filepath.Join(t.TempDir(), "disk")}
	os.MkdirAll(w.disk, 0o755)
	w.storage = filepath.Join(t.TempDir(), "storage.sh")
	os.WriteFile(w.storage, []byte(strings.ReplaceAll(devStorage, "__DISK__", w.disk)), 0o755)
	return w
}

// owner is one owner's master secret and record.
func (w *devWorld) owner() (*Master, *State) {
	w.t.Helper()
	m, err := NewMaster()
	if err != nil {
		w.t.Fatal(err)
	}
	dir := w.t.TempDir()
	st, err := OpenState(filepath.Join(dir, "sandboxes.json"), filepath.Join(dir, "known_hosts"))
	if err != nil {
		w.t.Fatal(err)
	}
	return m, st
}

func (w *devWorld) actions() string {
	b, _ := os.ReadFile(filepath.Join(w.disk, "actions"))
	return strings.TrimSpace(string(b))
}

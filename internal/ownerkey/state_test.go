package ownerkey

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// Two sbxkey runs on one state (opened at the same time, as two unlocks side
// by side are): neither loses the other's records; an epoch never goes down;
// a pinned host key is replaced only by the first boot of 'new'.
func TestConcurrentRunsKeepEachOthersRecords(t *testing.T) {
	dir := t.TempDir()
	open := func() *State {
		s, err := OpenState(filepath.Join(dir, "sandboxes.json"), filepath.Join(dir, "known_hosts"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a, b := open(), open()
	if err := a.Put(Record{ID: "sbx-00000000000000a1", Name: "one", Provisioned: true, Epoch: 1, SSHHostKey: "ssh-ed25519 AAAAone"}, true); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(Record{ID: "sbx-00000000000000a2", Name: "two", Provisioned: true, Epoch: 1}, true); err != nil {
		t.Fatal(err)
	}
	if got := open().Records(); len(got) != 2 {
		t.Fatalf("a run lost the other's record: %+v", got)
	}

	// Many at once.
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := open()
			if err := s.Put(Record{ID: fmt.Sprintf("sbx-%016x", 0x100+i), Name: fmt.Sprintf("n%d", i), Epoch: 1}, false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := open().Records(); len(got) != 18 {
		t.Fatalf("%d records after 18 puts", len(got))
	}

	// b's view of "one" is stale (epoch 1); a moves it to 5.
	if err := a.Put(Record{ID: "sbx-00000000000000a1", Name: "one", Provisioned: true, Epoch: 5}, false); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(Record{ID: "sbx-00000000000000a1", Name: "one", Provisioned: true, Epoch: 2}, false); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("an epoch was lowered: %v", err)
	}
	r := open().Get("sbx-00000000000000a1")
	if r.Epoch != 5 || r.SSHHostKey != "ssh-ed25519 AAAAone" {
		t.Fatalf("record: %+v (a put without a host key keeps the pinned one)", r)
	}
	// The pinned host key: kept unless the first boot of 'new' replaces it.
	if err := b.Put(Record{ID: "sbx-00000000000000a1", Name: "one", Provisioned: true, Epoch: 6, SSHHostKey: "ssh-ed25519 AAAAother"}, false); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("a pinned host key was replaced: %v", err)
	}
	if err := b.Put(Record{ID: "sbx-00000000000000a1", Name: "one", Provisioned: true, Epoch: 6, SSHHostKey: "ssh-ed25519 AAAAother"}, true); err != nil {
		t.Fatal(err)
	}
	if r := open().Get("sbx-00000000000000a1"); r.SSHHostKey != "ssh-ed25519 AAAAother" {
		t.Fatal("new's first boot did not pin its host key")
	}
}

// What the platform prints is shown, never interpreted by the terminal.
func TestPlatformOutputIsFiltered(t *testing.T) {
	in := "created \x1b]0;owned\x07web\x1b[2J\r\n\u009b31mok\tdone\x00\xff\x9b"
	got := Printable(in)
	if got != "created ]0;ownedweb[2J\n31mok\tdone" {
		t.Fatalf("%q", got)
	}
}

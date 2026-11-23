package ownerkey

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

const (
	imgA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imgB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func imageState(t *testing.T) (*State, func() *State) {
	t.Helper()
	dir := t.TempDir()
	open := func() *State {
		s, err := OpenState(filepath.Join(dir, "sandboxes.json"), filepath.Join(dir, "known_hosts"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	return open(), open
}

// What a first boot records (#112): the digest of a reference by digest,
// base for no image, nothing for a reference without a digest.
func TestImageDigestOf(t *testing.T) {
	for ref, want := range map[string]string{
		"":                             proto.ImageBase,
		"registry.example/app@" + imgA: imgA,
		"registry.example/app:v1":      "",
	} {
		if got := ImageDigestOf(ref); got != want {
			t.Errorf("ImageDigestOf(%q) = %q, want %q", ref, got, want)
		}
	}
}

// The comparison of the image a running TD shows with the owner's record.
func TestImageCheckAgainstTheRecord(t *testing.T) {
	st, open := imageState(t)
	put := func(id, name, image string) {
		t.Helper()
		if err := st.Put(Record{ID: id, Name: name, Provisioned: true, Epoch: 1, Image: image, ImageDigest: ImageDigestOf(image)}, true); err != nil {
			t.Fatal(err)
		}
	}
	const (
		byDigest = "sbx-00000000000000d1"
		base     = "sbx-00000000000000d2"
		tag      = "sbx-00000000000000d3"
	)
	put(byDigest, "app", "registry.example/app@"+imgA)
	put(base, "plain", "")
	put(tag, "tagged", "registry.example/app:v1")

	// By digest: that digest verifies, another is refused with both named.
	if c, err := st.CheckImage(byDigest, imgA); err != nil || c.FirstUse || c.NoRecord {
		t.Fatalf("the digest asked for: %+v %v", c, err)
	}
	_, err := st.CheckImage(byDigest, imgB)
	if err == nil || !strings.Contains(err.Error(), imgA) || !strings.Contains(err.Error(), imgB) || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("a @sha256: mismatch: %v", err)
	}
	if _, err := st.CheckImage(byDigest, proto.ImageBase); err == nil {
		t.Fatal("a sandbox asked for with an image verified as base")
	}

	// The base image: base verifies, a digest is refused.
	if _, err := st.CheckImage(base, proto.ImageBase); err != nil {
		t.Fatalf("base for a base sandbox: %v", err)
	}
	if _, err := st.CheckImage(base, imgA); err == nil {
		t.Fatal("a base sandbox showing an image verified")
	}

	// A tag: the first check records the digest (trust on first use), a
	// later one with another digest is refused.
	c, err := st.CheckImage(tag, imgA)
	if err != nil || !c.FirstUse || c.Recorded != "" {
		t.Fatalf("a tag, first check: %+v %v", c, err)
	}
	if r := open().Get(tag); r.ImageDigest != imgA {
		t.Fatalf("a tag's digest was not recorded: %+v", r)
	}
	if c, err := st.CheckImage(tag, imgA); err != nil || c.FirstUse {
		t.Fatalf("a tag, the same digest again: %+v %v", c, err)
	}
	if _, err := st.CheckImage(tag, imgB); err == nil || !strings.Contains(err.Error(), imgA) || !strings.Contains(err.Error(), imgB) {
		t.Fatalf("a tag, another digest later: %v", err)
	}

	// A new first boot with another image resets it.
	if err := open().Put(Record{ID: tag, Name: "tagged", Provisioned: true, Epoch: 1, Image: "registry.example/app@" + imgB, ImageDigest: imgB}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := open().CheckImage(tag, imgB); err != nil {
		t.Fatalf("after a new first boot with -image: %v", err)
	}
	// An unlock run that loaded its record before the digest was recorded
	// does not lose it.
	stale := Record{ID: tag, Name: "tagged", Provisioned: true, Epoch: 2}
	if err := open().Put(stale, false); err != nil {
		t.Fatal(err)
	}
	if r := open().Get(tag); r.ImageDigest != imgB || r.Image != "registry.example/app@"+imgB {
		t.Fatalf("a later boot's record lost the image: %+v", r)
	}

	// No record: nothing compared, nothing recorded; not well formed: refused.
	if c, err := st.CheckImage("sbx-00000000000000ff", imgA); err != nil || !c.NoRecord {
		t.Fatalf("no record: %+v %v", c, err)
	}
	if open().Get("sbx-00000000000000ff") != nil {
		t.Fatal("a check made a record")
	}
	for _, bad := range []string{"", "latest", "registry.example/app@" + imgA} {
		if _, err := st.CheckImage(byDigest, bad); err == nil {
			t.Errorf("CheckImage(%q) accepted", bad)
		}
	}
}

// ExpectedRTMR3 is the owner's unlock, then the image.
func TestExpectedRTMR3HasTheImage(t *testing.T) {
	m, err := NewMaster()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Wipe()
	const id = "sbx-00000000000000d1"
	secret, _ := m.DiskSecret(id)
	unlock, _ := proto.RTMR3OwnerUnlock(secret)
	for _, img := range []string{imgA, proto.ImageBase} {
		got, err := ExpectedRTMR3(m, id, img)
		if err != nil || got != proto.RTMR3Running(unlock, img) {
			t.Fatalf("ExpectedRTMR3(%s): %v", img, err)
		}
	}
	a, _ := ExpectedRTMR3(m, id, imgA)
	b, _ := ExpectedRTMR3(m, id, imgB)
	if a == b {
		t.Fatal("two images, one RTMR3")
	}
}

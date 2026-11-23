package verifycmd

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/proto"
	"github.com/hanlinai/trajrl-cli/internal/userverify"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// What -owner-key says about the image (#112), for each case of the
// owner's record, and what -json carries.
func TestImageNoteAndVerdict(t *testing.T) {
	dir := t.TempDir()
	st, err := ownerkey.OpenState(filepath.Join(dir, "sandboxes.json"), filepath.Join(dir, "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	put := func(id, name, image, digest string) {
		if err := st.Put(ownerkey.Record{ID: id, Name: name, Provisioned: true, Epoch: 1, Image: image, ImageDigest: digest}, true); err != nil {
			t.Fatal(err)
		}
	}
	put("sbx-00000000000000e1", "app", "registry.example/app@"+digestA, digestA)
	put("sbx-00000000000000e2", "plain", "", proto.ImageBase)
	put("sbx-00000000000000e3", "old", "", "")

	check := func(id, image string) (string, error) {
		c, err := st.CheckImage(id, image)
		if err != nil {
			return "", err
		}
		return imageNote("x", c, image), nil
	}
	for _, c := range []struct {
		id, image, want string
	}{
		{"sbx-00000000000000e1", digestA, "the image you created it with (registry.example/app@" + digestA},
		{"sbx-00000000000000e2", proto.ImageBase, "runs the base image, as your record says"},
		{"sbx-00000000000000e3", digestB, "now recorded (trust on first use)"},
		{"sbx-00000000000000e3", digestB, "runs " + digestB + ", as your record says"},
		{"sbx-00000000000000ff", digestA, "compared with nothing"},
	} {
		note, err := check(c.id, c.image)
		if err != nil || !strings.Contains(note, c.want) {
			t.Errorf("%s with %s: %q %v, want %q", c.id, c.image, note, err, c.want)
		}
	}
	// Refusals name both digests.
	for id, image := range map[string]string{"sbx-00000000000000e1": digestB, "sbx-00000000000000e2": digestA, "sbx-00000000000000e3": digestA} {
		_, err := check(id, image)
		if err == nil || !strings.Contains(err.Error(), image) || !strings.Contains(err.Error(), "your record says") {
			t.Errorf("%s with %s: %v", id, image, err)
		}
	}

	at := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	if v := verdictOf(&userverify.Report{SandboxID: "sbx-00000000000000e1", Image: digestA}, nil, "", at); v.Verdict != "VERIFIED" || v.Image != digestA {
		t.Fatalf("-json of a verified sandbox: %+v", v)
	}
	if v := verdictOf(&userverify.Report{Image: digestB}, errors.New("REFUSED: x runs the image"), "sbx-1", at); v.Verdict != "NOT VERIFIED" || v.Image != digestB {
		t.Fatalf("-json of a refusal: %+v", v)
	}
	// A rehearsal's report (no quote) is never VERIFIED.
	if v := verdictOf(&userverify.Report{SandboxID: "sbx-1", Image: proto.ImageBase, Rehearsal: true}, nil, "", at); v.Verdict != "NOT VERIFIED" || !strings.Contains(v.Reason, "rehearsal") {
		t.Fatalf("-json of a rehearsal: %+v", v)
	}
}

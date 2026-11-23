package proto

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

// The values tests/rtmr-from-artifacts.py --self-test and
// tests/ccel-replay.py --self-test compute too: the Go and Python sides
// agree on the image event and on RTMR3 of a running sandbox (#112).
var rtmr3Vectors = []struct{ image, event, running string }{
	{"base",
		"3d1e8b91ff8aef24efc9346e74933deeb58ff3dd45be84a4d365e7100caa1043e04a3dd021811fbbc630df672ce451af",
		"d0448b783b1eae87bd8fd532ec4e18672d62c00131ff212785020ce0f4908d0542ca38ab711e131f2af48e9040424ba1"},
	{"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"994e0698fcdad5a40ceaf00f4cf5d938dc4a1dad0c4178c7302f0f27ee7e1536f79c988a25e0e28380d6fab429e9d332",
		"3657e06bfd452b76f098ba700079583733ef3efb7c1baa65097e1108fcf25efc7330dac7ef463927a9ff8d701c12f1cd"},
}

func TestRTMR3ImageVectors(t *testing.T) {
	for _, v := range rtmr3Vectors {
		e := RTMR3Image(v.image)
		if got := hex.EncodeToString(e[:]); got != v.event {
			t.Errorf("RTMR3Image(%s) = %s, want %s", v.image, got, v.event)
		}
		r := RTMR3Running(RTMR3BootDone(), v.image)
		if got := hex.EncodeToString(r[:]); got != v.running {
			t.Errorf("RTMR3Running(BootDone, %s) = %s, want %s", v.image, got, v.running)
		}
	}
}

// RTMR3Running is two extensions from zero: the unlock's, then the image's.
func TestRTMR3RunningIsTwoExtensions(t *testing.T) {
	unlock := sha512.Sum384([]byte("some unlock value"))
	img := "sha256:ab0123456789abcd0123456789abcdef0123456789abcdef0123456789abcdef"
	want := RTMR3Extend(RTMR3Extend([48]byte{}, unlock), RTMR3Image(img))
	if RTMR3Running(unlock, img) != want {
		t.Fatal("RTMR3Running is not After(After(0, unlock), Image(digest))")
	}
	if RTMR3After(unlock) != RTMR3Extend([48]byte{}, unlock) {
		t.Fatal("RTMR3After is not one extension from zero")
	}
	// The image changes the value; so does the unlock; base is an image of
	// its own.
	if RTMR3Running(unlock, img) == RTMR3Running(unlock, ImageBase) ||
		RTMR3Running(unlock, img) == RTMR3Running(RTMR3BootDone(), img) ||
		RTMR3Running(unlock, ImageBase) == RTMR3After(unlock) {
		t.Fatal("RTMR3Running does not depend on both of its inputs")
	}
}

func TestValidImageMeasure(t *testing.T) {
	for s, ok := range map[string]bool{
		"base": true,
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": true,
		"":      false,
		"BASE":  false,
		"base ": false,
		"sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef":       false,
		"sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":       false,
		"reg/x@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": false,
	} {
		if ValidImageMeasure(s) != ok {
			t.Errorf("ValidImageMeasure(%q) = %v", s, !ok)
		}
	}
}

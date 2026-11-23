package keycmd

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestOCIImageTakenFromTheEntryArguments(t *testing.T) {
	ref := "localhost:5000/test@" + testDigest
	for _, c := range []struct {
		args       []string
		ref        string
		rest       []string
		wantErrStr string
	}{
		{[]string{"--image", ref, "--size", "small"}, ref, []string{"--size", "small"}, ""},
		{[]string{"--image=" + ref}, ref, nil, ""},
		{[]string{"-image", ref, "--wait"}, ref, []string{"--wait"}, ""},
		// The platform's own images stay with the entry point.
		{[]string{"--image", "next", "--wait"}, "", []string{"--image", "next", "--wait"}, ""},
		{[]string{"--image=next"}, "", []string{"--image=next"}, ""},
		{[]string{"--image"}, "", []string{"--image"}, ""},
		{[]string{"--image", ref, "--image", ref}, "", nil, "twice"},
	} {
		got, rest, err := imageFromEntryArgs(c.args)
		if c.wantErrStr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErrStr) {
				t.Errorf("%q: %v", c.args, err)
			}
			continue
		}
		if err != nil || got != c.ref || !reflect.DeepEqual(rest, c.rest) {
			t.Errorf("%q: %q %q %v", c.args, got, rest, err)
		}
	}
}

func TestOCIImageChecksAndCredentialFile(t *testing.T) {
	if _, err := checkImage("localhost:5000/test:latest", ""); !errors.Is(err, proto.ErrImageTag) {
		t.Fatalf("a tag: %v", err)
	}
	if _, err := checkImage("", "somefile"); err == nil {
		t.Fatal("-registry-auth without an image")
	}
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "good"), filepath.Join(dir, "bad")
	os.WriteFile(good, []byte("alice:s3cret\n"), 0o600)
	os.WriteFile(bad, []byte("no-colon-s3cret\n"), 0o600)
	ref := "ghcr.io/me/app@" + testDigest
	if a, err := checkImage(ref, good); err != nil || a != "alice:s3cret" {
		t.Fatalf("credential file: %q %v", a, err)
	}
	if _, err := checkImage(ref, bad); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("a malformed credential file: %v (the message must not quote it)", err)
	}
}

// What a first boot says about the image it recorded (#112).
func TestImageRecordedLine(t *testing.T) {
	const d = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for ref, want := range map[string]string{
		"":                          "the base image, recorded",
		"registry.example/app@" + d: d + " recorded (registry.example/app@" + d + ")",
		"registry.example/app:v1":   "names no digest; the first sbxverify -owner-key records",
	} {
		if got := imageRecorded("web", ref); !strings.Contains(got, want) || !strings.Contains(got, "RTMR3") {
			t.Errorf("imageRecorded(%q) = %q, want %q", ref, got, want)
		}
	}
}

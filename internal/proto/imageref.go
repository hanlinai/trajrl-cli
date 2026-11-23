package proto

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// A sandbox's image (#38) is named by digest only: REGISTRY/REPO@sha256:HEX.
// A tag names whatever the registry says it names at the moment it is asked,
// so the owner's own client resolves it, and what reaches the TD is the
// digest the owner chose; the guest checks every byte it pulls against it.

// MaxImageRef bounds an image reference; MaxRegistryAuth a credential.
const (
	MaxImageRef     = 512
	MaxRegistryAuth = 4 << 10
)

// ImageRef is a parsed image reference.
type ImageRef struct {
	// Registry is the registry's host[:port], as it is dialled
	// (registry-1.docker.io for Docker Hub).
	Registry string
	// Repository is the repository's path at that registry
	// (library/ubuntu for Docker Hub's "ubuntu").
	Repository string
	// Digest is "sha256:" and 64 lower-case hex digits.
	Digest string
}

// String is the reference in its full form.
func (r ImageRef) String() string { return r.Registry + "/" + r.Repository + "@" + r.Digest }

var (
	digestRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	pathCompRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	hostRe     = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]{1,5})?$`)
)

// ValidDigest reports whether d is "sha256:" and 64 lower-case hex digits.
func ValidDigest(d string) bool { return digestRe.MatchString(d) }

// ErrImageTag is the refusal of a reference that names a tag.
var ErrImageTag = errors.New("an image is named by digest only (REF@sha256:...), not by tag: resolve the tag on your side, e.g. with 'docker buildx imagetools inspect REF' or 'crane digest REF', and give REF@sha256:<digest>")

// ParseImageRef parses REGISTRY/REPO@sha256:HEX. A reference without a
// registry (one whose first part has no dot or port and is not localhost)
// is Docker Hub's, as docker reads it. A tag is refused, with or without a
// digest beside it.
func ParseImageRef(s string) (ImageRef, error) {
	var r ImageRef
	if len(s) > MaxImageRef {
		return r, fmt.Errorf("an image reference is at most %d bytes", MaxImageRef)
	}
	name, digest, ok := strings.Cut(s, "@")
	last := name[strings.LastIndex(name, "/")+1:]
	if strings.Contains(last, ":") {
		return r, ErrImageTag
	}
	if !ok {
		return r, ErrImageTag
	}
	if !ValidDigest(digest) {
		return r, fmt.Errorf("image reference %.80q: the digest must be sha256: and 64 lower-case hex digits", s)
	}
	r.Digest = digest
	host, rest, hasSlash := strings.Cut(name, "/")
	if hasSlash && (strings.ContainsAny(host, ".:") || host == "localhost") {
		if !hostRe.MatchString(host) {
			return r, fmt.Errorf("image reference %.80q: %q is not a registry host[:port]", s, host)
		}
		r.Registry, r.Repository = host, rest
		if host == "docker.io" || host == "index.docker.io" {
			r.Registry = "registry-1.docker.io"
		}
	} else {
		r.Registry, r.Repository = "registry-1.docker.io", name
	}
	if r.Registry == "registry-1.docker.io" && !strings.Contains(r.Repository, "/") {
		r.Repository = "library/" + r.Repository
	}
	if r.Repository == "" {
		return r, fmt.Errorf("image reference %.80q names no repository", s)
	}
	for _, c := range strings.Split(r.Repository, "/") {
		if !pathCompRe.MatchString(c) {
			return r, fmt.Errorf("image reference %.80q: %q is not a valid repository path component (lower-case letters, digits, separators)", s, c)
		}
	}
	return r, nil
}

// CheckRegistryAuth checks a registry credential's form: USER:PASSWORD, on
// one line.
func CheckRegistryAuth(a string) error {
	if a == "" {
		return nil
	}
	if len(a) > MaxRegistryAuth {
		return fmt.Errorf("a registry credential is at most %d bytes", MaxRegistryAuth)
	}
	user, _, ok := strings.Cut(a, ":")
	if !ok || user == "" || strings.ContainsAny(a, "\r\n\x00") {
		return errors.New("a registry credential is USER:PASSWORD on one line")
	}
	return nil
}

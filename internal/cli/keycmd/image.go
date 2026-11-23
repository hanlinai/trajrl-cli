package keycmd

// sbxkey new NAME --image REGISTRY/REPO@sha256:... (#38). The sandbox's
// root is that image over the platform's base: its TD pulls it at the first
// boot, checks it against the digest and unpacks it onto its encrypted disk.
// The reference and the registry credential travel as the setup script
// does: in the release of the first boot, inside the attested session, never
// through the platform. A tag is refused here, before anything is created:
// what the TD is given is the digest the owner chose.

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hanlinai/trajrl-cli/internal/ownerkey"
	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// isImageRef tells an image reference from the name of one of the
// platform's own images, which the entry point's new also takes as
// --image: a reference has a '/' or an '@', a platform image name neither.
func isImageRef(v string) bool { return strings.ContainsAny(v, "/@") }

// imageFromEntryArgs takes --image REF (or -image, or --image=REF) out of
// the arguments for the entry point's new when REF is an image reference,
// and returns it with the rest. A platform image name stays where it is.
func imageFromEntryArgs(args []string) (string, []string, error) {
	var ref string
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		flag, val, hasVal := strings.Cut(a, "=")
		if flag != "--image" && flag != "-image" {
			rest = append(rest, a)
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				rest = append(rest, a)
				continue
			}
			val = args[i+1]
		}
		if !isImageRef(val) {
			rest = append(rest, a)
			if !hasVal {
				rest = append(rest, val)
				i++
			}
			continue
		}
		if !hasVal {
			i++
		}
		if ref != "" {
			return "", nil, errors.New("--image given twice")
		}
		ref = val
	}
	return ref, rest, nil
}

// checkImage checks an image reference and reads the registry credential
// file: USER:PASSWORD on its first line.
func checkImage(ref, authFile string) (string, error) {
	if ref == "" {
		if authFile != "" {
			return "", errors.New("-registry-auth without an image (--image REGISTRY/REPO@sha256:...)")
		}
		return "", nil
	}
	if _, err := proto.ParseImageRef(ref); err != nil {
		return "", err
	}
	if authFile == "" {
		return "", nil
	}
	b, err := os.ReadFile(authFile)
	if err != nil {
		return "", err
	}
	auth, _, _ := strings.Cut(string(b), "\n")
	auth = strings.TrimSuffix(auth, "\r")
	if err := proto.CheckRegistryAuth(auth); err != nil || auth == "" {
		// The file's content is a secret: not quoted.
		return "", fmt.Errorf("%s: a registry credential is USER:PASSWORD on the first line", authFile)
	}
	return auth, nil
}

// imageRecorded is what a first boot tells the owner about the image it
// recorded (#112): the running TD's RTMR3 must show it, which
// sbxverify -owner-key checks against this record.
func imageRecorded(name, ref string) string {
	verify := ownerkey.VerifyOwnerCommand(name)
	switch d := ownerkey.ImageDigestOf(ref); {
	case ref == "":
		return "  image: the base image, recorded; " + verify + " checks that the running TD's RTMR3 shows it"
	case d != "":
		return fmt.Sprintf("  image: %s recorded (%s); %s checks that the running TD's RTMR3 shows it", d, ref, verify)
	default:
		return fmt.Sprintf("  image: %s names no digest; the first %s records the one the running TD's RTMR3 shows", ref, verify)
	}
}

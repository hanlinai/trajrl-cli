//go:build rehearsal

package userverify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hanlinai/trajrl-cli/internal/proto"
)

// REHEARSAL BUILD: a sandbox that is not a TD gives no quote; the image it
// names is compared with the owner's record, and the report says that
// nothing was attested.
func TestRehearsalImageWithoutQuote(t *testing.T) {
	AllowUnattestedRehearsal()
	defer unattestedRehearsal.Store(false)
	addr := fakeSandbox(t, func(cmd string) (string, int) {
		if strings.HasPrefix(cmd, "cat ") {
			return digest1 + "\n", 0
		}
		return "", 3
	})
	for record, ok := range map[string]bool{digest1: true, digest2: false} {
		tg := sandbox(t, [48]byte{}, "", false)
		tg.Addr = addr
		tg.OwnerImage = func(_, image string) (string, error) {
			if image != record {
				return "", errors.New("REFUSED: your record says " + record)
			}
			return "as your record says", nil
		}
		rep, err := Check(context.Background(), tg, &fakeVerifier{})
		if (err == nil) != ok || rep == nil || !rep.Rehearsal || rep.Quote != nil || rep.Image != digest1 {
			t.Fatalf("record %s: %v %+v", record, err, rep)
		}
	}
	// Something that is neither base nor a digest is refused here too.
	bad := fakeSandbox(t, func(cmd string) (string, int) {
		if strings.HasPrefix(cmd, "cat ") {
			return "latest\n", 0
		}
		return "", 3
	})
	tg := sandbox(t, [48]byte{}, "", false)
	tg.Addr = bad
	if _, err := Check(context.Background(), tg, &fakeVerifier{}); err == nil || !strings.Contains(err.Error(), proto.ImageBase) {
		t.Fatalf("an image named latest: %v", err)
	}
}

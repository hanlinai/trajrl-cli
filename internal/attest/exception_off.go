//go:build !tcbexception

package attest

import (
	"errors"
	"time"

	"github.com/google/go-tdx-guest/pcs"
)

// This build has no TCB exception (#82). The validation build of kbs, for
// hardware bring-up only, is made with -tags tcbexception and has
// exception_on.go instead: the exception file, its loader and the verdict
// that records it. Here there is nothing to load an exception with, and
// TCBException is an empty type that keeps TDX.Exception compiling: a
// verifier somebody hands one refuses every quote, and nothing ever covers an
// out-of-date TDX module.
type TCBException struct{}

var errNoTCBException = errors.New("this build has no TCB exception")

func (*TCBException) check() error { return errNoTCBException }

func (*TCBException) covers(string, []byte, pcs.TcbLevel, string, time.Time) (string, error) {
	return "", errNoTCBException
}

//go:build !linux

package ownerkey

// boot skips the test: the guest's boot code (internal/guest) is Linux only,
// so on Windows and macOS no test boots one (rehearsal_world_boot_test.go).
func (w *devWorld) boot(u *Unlock, devInsecure bool) (guestErr error, out *Outcome, err error) {
	w.t.Helper()
	w.t.Skip("the guest's boot code (internal/guest) is Linux only")
	return nil, nil, nil
}

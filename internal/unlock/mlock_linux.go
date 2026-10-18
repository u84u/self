//go:build linux

package unlock

import "golang.org/x/sys/unix"

// mlockBestEffort locks payload bytes into RAM where possible. Failures
// are ignored: this is a hardening hint, not a correctness requirement.
func mlockBestEffort(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Mlock(b)
}

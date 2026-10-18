//go:build unix && !linux

package unlock

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Launch runs the payload as a child process, unlinking the decrypted
// temporary file as soon as the child has it mapped.
func Launch(image io.Reader, argv, envv []string) (int, error) {
	return launchSpawn(image, argv, envv)
}

// Crash terminates the process with SIGSEGV. Unlike Linux the Go runtime
// owns the signal disposition here, so the crash may carry a runtime
// report on stderr; the process still dies by SIGSEGV as observed from
// the outside.
func Crash() {
	_ = unix.Kill(unix.Getpid(), unix.SIGSEGV)
	os.Exit(139)
}

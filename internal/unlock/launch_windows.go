//go:build windows

package unlock

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// Launch runs the payload as a child process. The decrypted temporary
// file is deleted when the child exits; Windows keeps the running image
// locked, so it exists on disk for the duration of the run.
func Launch(image io.Reader, argv, envv []string) (int, error) {
	return launchSpawn(image, argv, envv)
}

// Crash terminates with STATUS_ACCESS_VIOLATION, the Windows analogue of
// a segfault.
func Crash() {
	_ = windows.TerminateProcess(windows.CurrentProcess(), 0xC0000005)
	os.Exit(1)
}

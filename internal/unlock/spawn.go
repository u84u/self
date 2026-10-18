//go:build windows || (unix && !linux)

package unlock

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// launchSpawn writes the payload to a private temporary file and runs it
// as a child process, forwarding its exit status.
//
// The file is unlinked as soon as the child has it mapped wherever the
// platform allows that (all POSIX systems); on Windows the running image
// stays locked and is removed once the child exits, so the plaintext
// exists on disk for the duration of the run. That difference is
// inherent: there is no exec-from-memory on Windows or macOS without
// loader tricks that antivirus products rightly flag.
func launchSpawn(image io.Reader, argv, envv []string) (int, error) {
	f, err := os.CreateTemp("", "self-*")
	if err != nil {
		return 0, fmt.Errorf("unlock: temp file: %w", err)
	}
	path := f.Name()
	cleanup := func() { f.Close(); secureRemove(path) }

	if err := f.Chmod(0o700); err != nil {
		cleanup()
		return 0, fmt.Errorf("unlock: temp file: %w", err)
	}
	if _, err := io.Copy(f, image); err != nil {
		cleanup()
		return 0, fmt.Errorf("unlock: write payload: %w", err)
	}
	if err := f.Close(); err != nil {
		secureRemove(path)
		return 0, fmt.Errorf("unlock: write payload: %w", err)
	}

	if len(argv) == 0 {
		argv = []string{path}
	}
	cmd := exec.Command(path)
	cmd.Args = argv // keep the original argv[0], not the temp path
	cmd.Env = envv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		secureRemove(path)
		return 0, fmt.Errorf("unlock: start payload: %w", err)
	}
	// Start waits for exec on POSIX, so unlinking now cannot race it.
	removed := secureRemove(path)

	err = cmd.Wait()
	if !removed {
		_ = secureRemove(path)
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return 0, fmt.Errorf("unlock: run payload: %w", err)
	}

	state := cmd.ProcessState
	if state == nil {
		return 0, fmt.Errorf("unlock: run payload: missing process state")
	}
	code := state.ExitCode()
	if code < 0 && runtime.GOOS != "windows" {
		// Killed by a signal: mirror it through the conventional
		// 128+n encoding rather than re-raising, which would drag the
		// Go runtime's crash reporter into the output.
		if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			code = 128 + int(ws.Signal())
		} else {
			code = 1
		}
	}
	return code, nil
}

// secureRemove overwrites a file with zeros before deleting it, where
// the path still exists. Best-effort: failures are ignored.
func secureRemove(path string) bool {
	removed := false
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		info, _ := f.Stat()
		if info != nil {
			buf := make([]byte, 64*1024)
			var written int64
			for written < info.Size() {
				n := int64(len(buf))
				if remaining := info.Size() - written; remaining < n {
					n = remaining
				}
				if _, err := f.Write(buf[:n]); err != nil {
					break
				}
				written += n
			}
		}
		f.Close()
	}
	removed = (os.Remove(path) == nil)
	return removed
}

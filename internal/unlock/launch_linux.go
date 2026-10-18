//go:build linux

package unlock

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Launch decrypts into an anonymous in-memory file and execs it,
// replacing the current process. Nothing ever touches the filesystem and
// the kernel does the real loading, so PIE, dynamic, and Go payloads all
// work unmodified.
func Launch(image io.Reader, argv, envv []string) (int, error) {
	hardenProcess()
	// Try a secret memfd first (Linux >= 5.14): pages are removed from
	// the kernel's page tables so other processes cannot read them.
	if fd, err := unix.MemfdSecret(0); err == nil {
		// Buffer the image so we can retry on the regular path.
		data, rerr := io.ReadAll(image)
		if rerr == nil {
			if _, werr := fdWriter(fd).Write(data); werr == nil {
				// Best-effort seal.
				_, _ = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS,
					unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE)
				if eerr := execveat(fd, "", argv, envv); eerr == nil {
					return 0, nil
				}
			}
		}
		unix.Close(fd)
		// Reset image is impossible (already consumed); callers pass a
		// reader. To keep it simple, fall through only if we buffered.
		// If we consumed image but failed, we cannot retry; return error.
		if rerr != nil {
			return 0, fmt.Errorf("unlock: read payload: %w", rerr)
		}
		// We consumed data but secret path failed; use a bytes reader.
		image = bytes.NewReader(data)
	}

	fd, err := unix.MemfdCreate("self", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return 0, fmt.Errorf("unlock: memfd: %w", err)
	}
	defer unix.Close(fd)

	if _, err := io.Copy(fdWriter(fd), image); err != nil {
		return 0, fmt.Errorf("unlock: write payload: %w", err)
	}
	// Best-effort sealing: prevent truncation/growth of the plaintext.
	_, _ = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS,
		unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE)

	// Primary launch path.
	if err := execveat(fd, "", argv, envv); err != nil {
		// Fallback for kernels/configs that reject execveat on a
		// memfd: exec the fd via its /proc entry.
		path := fmt.Sprintf("/proc/self/fd/%d", fd)
		// execve needs a real path; try it before giving up.
		if err2 := execProc(fd, path, argv, envv); err2 != nil {
			return 0, err2
		}
	}
	return 0, nil // unreachable on success
}

// execProc is the fallback launcher using /proc/self/fd/N.
func execProc(fd int, path string, argv, envv []string) error {
	pathp, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	argp, err := cSlice(argv)
	if err != nil {
		return err
	}
	envp, err := cSlice(envv)
	if err != nil {
		return err
	}
	_, _, errno := unix.RawSyscall6(unix.SYS_EXECVE, uintptr(unsafe.Pointer(pathp)),
		uintptr(unsafe.Pointer(&argp[0])), uintptr(unsafe.Pointer(&envp[0])), 0, 0, 0)
	runtime.KeepAlive(pathp)
	runtime.KeepAlive(argp)
	runtime.KeepAlive(envp)
	if errno != 0 {
		return fmt.Errorf("unlock: execve: %w", errno)
	}
	return nil
}

// execveat replaces the current process with the file behind dirfd.
// x/sys/unix exposes no wrapper, so the syscall is made directly; see
// execveat(2) for the AT_EMPTY_PATH dance.
func execveat(dirfd int, path string, argv, envv []string) error {
	pathp, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	argp, err := cSlice(argv)
	if err != nil {
		return err
	}
	envp, err := cSlice(envv)
	if err != nil {
		return err
	}
	_, _, errno := unix.RawSyscall6(unix.SYS_EXECVEAT, uintptr(dirfd),
		uintptr(unsafe.Pointer(pathp)), uintptr(unsafe.Pointer(&argp[0])),
		uintptr(unsafe.Pointer(&envp[0])), uintptr(unix.AT_EMPTY_PATH), 0)
	runtime.KeepAlive(pathp)
	runtime.KeepAlive(argp)
	runtime.KeepAlive(envp)
	if errno != 0 {
		return fmt.Errorf("unlock: execveat: %w", errno)
	}
	return nil // unreachable on success
}

// cSlice encodes strs as a NULL-terminated array of C strings.
func cSlice(strs []string) ([]*byte, error) {
	ptrs := make([]*byte, 0, len(strs)+1)
	for _, s := range strs {
		p, err := unix.BytePtrFromString(s)
		if err != nil {
			return nil, err
		}
		ptrs = append(ptrs, p)
	}
	return append(ptrs, nil), nil
}

type fdWriter int

func (fd fdWriter) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := unix.Write(int(fd), p[total:])
		total += n
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// kernelSigaction is struct sigaction as the kernel lays it out on
// Linux/asm-generic: handler, flags, restorer, mask.
type kernelSigaction struct {
	Handler  uintptr
	Flags    uint64
	Restorer uintptr
	Mask     uint64
}

// hardenProcess applies best-effort runtime hardening before exec.
func hardenProcess() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	if os.Getenv("SELF_ANTI_SANDBOX") == "1" {
		if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			low := strings.ToLower(string(data))
			if strings.Contains(low, "docker") || strings.Contains(low, "lxc") || strings.Contains(low, "kubepods") {
				unix.Exit(3)
			}
		}
		if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
			low := strings.ToLower(string(data))
			for _, bad := range []string{"virtualbox", "vmware", "qemu", "kvm"} {
				if strings.Contains(low, bad) {
					unix.Exit(3)
				}
			}
		}
	}
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 && fields[1] != "0" {
					unix.Exit(3)
				}
			}
		}
	}
	// Best-effort seccomp filter blocking ptrace and process_vm_*.
	_ = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: uint32(unix.SYS_PTRACE)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | 1}, // EPERM
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: uint32(unix.SYS_PROCESS_VM_READV)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | 1},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: uint32(unix.SYS_PROCESS_VM_WRITEV)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, _ = unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog)))
}

// Crash terminates the process with SIGSEGV and no diagnostics. It does
// not return.
func Crash() {
	// Hand SIGSEGV back to the kernel before faulting: the Go runtime's
	// handler would otherwise print a full crash report to stderr. The
	// zero value is SIG_DFL with no flags and an empty mask.
	act := kernelSigaction{}
	// The kernel's sigset_t is _NSIG/8 bytes: 8 on all asm-generic
	// architectures.
	const kernelSigsetSize = 8
	if _, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(unix.SIGSEGV),
		uintptr(unsafe.Pointer(&act)), 0, kernelSigsetSize, 0, 0); errno != 0 {
		unix.Exit(3) // fail closed even if the disposition cannot be reset
	}
	// Do not litter the machine with core files.
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})

	runtime.LockOSThread()
	var mask unix.Sigset_t
	mask.Val[0] = 1 << (unix.SIGSEGV - 1)
	_ = unix.PthreadSigmask(unix.SIG_UNBLOCK, &mask, nil)

	for {
		if err := unix.Tgkill(unix.Getpid(), unix.Gettid(), unix.SIGSEGV); err != nil {
			unix.Exit(3) // fail closed even if the signal is unavailable
		}
		unix.Pause()
	}
}

//go:build linux && !amd64 && !arm64

package unlock

// seccompArch is zero on architectures this build has no audit value
// for. A zero value makes blockDebugSyscalls skip installing the filter
// rather than compare syscall numbers against the wrong table.
const seccompArch = 0

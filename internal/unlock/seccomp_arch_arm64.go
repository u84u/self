//go:build linux && arm64

package unlock

// seccompArch is AUDIT_ARCH_AARCH64 from linux/audit.h.
const seccompArch = 0xc00000b7

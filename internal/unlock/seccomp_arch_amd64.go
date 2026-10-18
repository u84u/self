//go:build linux && amd64

package unlock

// seccompArch is AUDIT_ARCH_X86_64 from linux/audit.h.
const seccompArch = 0xc000003e

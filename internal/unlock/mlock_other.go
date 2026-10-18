//go:build !linux

package unlock

// mlockBestEffort is a no-op on platforms without a usable mlock.
func mlockBestEffort(b []byte) {}

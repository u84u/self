package stubs

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLookup(t *testing.T) {
	want := []byte("stub bytes")
	fsys := fstest.MapFS{
		"assets/stub-windows-386.gz": {Data: gzipped(t, want)},
	}
	got, err := lookup(fsys, "windows/386")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("lookup returned %q, want %q", got, want)
	}
}

func TestLookupUnsupportedPlatform(t *testing.T) {
	_, err := lookup(fstest.MapFS{}, "plan9/amd64")
	if err == nil {
		t.Fatal("lookup of an unsupported platform succeeded, want error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error %q should mention the unsupported platform", err)
	}
}

func TestLookupWithoutAssets(t *testing.T) {
	_, err := lookup(fstest.MapFS{}, "linux/amd64")
	if err == nil {
		t.Fatal("lookup without built assets succeeded, want error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %q should wrap fs.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), "make stubs") {
		t.Errorf("error %q should tell the reader to run make stubs", err)
	}
}

// TestEmbeddedStubs checks the real assets when the build populated
// them; a fresh clone skips.
func TestEmbeddedStubs(t *testing.T) {
	magic := map[string][]byte{
		"linux/amd64":   []byte{0x7f, 0x45, 0x4c, 0x46}, // ELF magic
		"linux/arm64":   []byte{0x7f, 0x45, 0x4c, 0x46},
		"darwin/amd64":  {0xcf, 0xfa, 0xed, 0xfe}, // 64-bit Mach-O, little-endian
		"darwin/arm64":  {0xcf, 0xfa, 0xed, 0xfe},
		"windows/amd64": []byte{0x4d, 0x5a}, // MZ
		"windows/386":   []byte{0x4d, 0x5a},
	}
	for _, platform := range Supported {
		data, err := Lookup(platform)
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("stub assets not built: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(data, magic[platform]) {
			t.Errorf("%s stub does not start with %q", platform, magic[platform])
		}
	}
}

func TestLookupPlatformNotInSupportedList(t *testing.T) {
	_, err := lookup(fstest.MapFS{}, "freebsd/amd64")
	if err == nil {
		t.Fatal("lookup of unsupported platform succeeded, want error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error %q should mention unsupported platform", err)
	}
}

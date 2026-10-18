package format

import (
	"bytes"
	"strings"
	"testing"
)

func TestFooterRoundTrip(t *testing.T) {
	want := Footer{Version: Version, BlobSize: 1 << 40}
	got, err := Decode(Encode(want))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Version != want.Version || got.Flags != want.Flags || got.BlobSize != want.BlobSize {
		t.Errorf("Decode = %+v, want %+v", got, want)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	valid := Encode(Footer{Version: Version, BlobSize: 42})

	badTail := bytes.Clone(valid)
	badTail[Size-1] ^= 0xff

	badVersion := bytes.Clone(valid)
	badVersion[8] = 99

	for name, b := range map[string][]byte{
		"short":       bytes.Repeat([]byte{0}, Size-1),
		"zeroed":      bytes.Repeat([]byte{0}, Size),
		"bad tail":    badTail,
		"bad version": badVersion,
	} {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: Decode succeeded, want error", name)
		}
	}
}

func TestOpenLocatesBlob(t *testing.T) {
	blob := bytes.Repeat([]byte("ciphertext"), 100)
	artifact := append([]byte("stub-elf"), blob...)
	artifact = append(artifact, Encode(Footer{Version: Version, BlobSize: uint64(len(blob))})...)

	r, _, err := Open(bytes.NewReader(artifact), int64(len(artifact)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := make([]byte, len(blob))
	if _, err := r.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Error("blob mismatch")
	}
}

func TestOpenRejectsUnpackedBinary(t *testing.T) {
	if _, _, err := Open(strings.NewReader(strings.Repeat("x", 4096)), 4096); err == nil {
		t.Error("Open succeeded on an unpacked binary, want error")
	}
}

func TestOpenRejectsTooSmall(t *testing.T) {
	if _, _, err := Open(bytes.NewReader(make([]byte, 31)), 31); err == nil {
		t.Error("Open on 31-byte artifact succeeded, want error")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(Encode(Footer{Version: Version, BlobSize: 42}))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Decode(b)
	})
}

func FuzzOpen(f *testing.F) {
	artifact := append([]byte("stub-elf"), bytes.Repeat([]byte("ciphertext"), 10)...)
	artifact = append(artifact, Encode(Footer{Version: Version, BlobSize: 100})...)
	f.Add(artifact)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Open(bytes.NewReader(data), int64(len(data)))
	})
}

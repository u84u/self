// Package format defines the on-disk layout of a packed artifact:
//
//	[stub ELF][age blob][footer]
//
// The stub ELF is an ordinary executable; everything after its last
// PT_LOAD segment is invisible to the kernel loader. The age blob is a
// standard age file (anonymous per-recipient stanzas) whose plaintext is
// the target executable. The fixed-size footer lets the stub find the
// blob by reading the tail of its own executable.
package format

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// Magic marks the start of a footer.
	Magic = "SELF"
	// MagicTail closes the footer so a truncated artifact is detected
	// rather than misparsed.
	MagicTail = "FLES"
	// Version1 is the original format revision.
	Version1 = uint32(1)
	// Version2 adds Flags and a CRC and length-prefixed payloads.
	Version2 = uint32(2)
	// Version is the format revision written by this build.
	Version = Version2
	// Size is the footer size in bytes.
	Size = 32

	// FlagPadded indicates the age plaintext is length-prefixed +
	// payload + random padding, to be trimmed by the stub.
	FlagPadded = uint32(1 << 0)
	// FlagExpiry indicates the length-prefixed header also carries
	// not-before / not-after unix timestamps.
	FlagExpiry = uint32(1 << 1)
	// FlagEnv indicates the header carries an environment block.
	FlagEnv = uint32(1 << 2)
	// FlagCapability indicates an issuer-signed capability token is
	// appended to the encrypted payload.
	FlagCapability = uint32(1 << 3)

	// CapabilityMarker separates a capability token from the payload
	// bytes. The stub only looks for it when FlagCapability is set.
	CapabilityMarker = "SELF-CAP"
)

// Footer is the trailer of a packed artifact.
type Footer struct {
	Version  uint32
	Flags    uint32
	CRC      uint32
	BlobSize uint64
}

// Encode serializes f into its 32-byte on-disk form.
func Encode(f Footer) []byte {
	b := make([]byte, Size)
	copy(b, Magic)
	binary.LittleEndian.PutUint32(b[4:], f.Flags)
	binary.LittleEndian.PutUint32(b[8:], f.Version)
	// CRC field left zero while computing.
	binary.LittleEndian.PutUint64(b[16:], f.BlobSize)
	copy(b[Size-4:], MagicTail)
	crc := crc32.ChecksumIEEE(b)
	binary.LittleEndian.PutUint32(b[12:], crc)
	return b
}

// Decode parses a footer, validating both magics and the version.
func Decode(b []byte) (Footer, error) {
	var f Footer
	if len(b) != Size {
		return f, fmt.Errorf("format: footer is %d bytes, want %d", len(b), Size)
	}
	if string(b[:len(Magic)]) != Magic || string(b[Size-len(MagicTail):]) != MagicTail {
		return f, errors.New("format: not a packed artifact")
	}
	f.Flags = binary.LittleEndian.Uint32(b[4:])
	f.Version = binary.LittleEndian.Uint32(b[8:])
	if f.Version != Version1 && f.Version != Version2 {
		return f, fmt.Errorf("format: unsupported version %d", f.Version)
	}
	f.CRC = binary.LittleEndian.Uint32(b[12:])
	f.BlobSize = binary.LittleEndian.Uint64(b[16:])
	// Validate CRC for v2; v1 reserved field is zero.
	if f.Version == Version2 {
		tmp := make([]byte, Size)
		copy(tmp, b)
		binary.LittleEndian.PutUint32(tmp[12:], 0)
		if crc32.ChecksumIEEE(tmp) != f.CRC {
			return f, errors.New("format: footer CRC mismatch")
		}
	}
	return f, nil
}

// Open locates the sealed blob at the tail of an artifact of the given
// size and returns a reader over it together with the decoded footer.
func Open(r io.ReaderAt, size int64) (*io.SectionReader, Footer, error) {
	var f Footer
	if size < Size {
		return nil, f, errors.New("format: artifact too short")
	}
	footer := make([]byte, Size)
	if _, err := r.ReadAt(footer, size-Size); err != nil {
		return nil, f, fmt.Errorf("format: read footer: %w", err)
	}
	dec, err := Decode(footer)
	if err != nil {
		return nil, f, err
	}
	start := size - Size - int64(dec.BlobSize)
	if start < 0 {
		return nil, dec, errors.New("format: blob size exceeds artifact")
	}
	return io.NewSectionReader(r, start, int64(dec.BlobSize)), dec, nil
}

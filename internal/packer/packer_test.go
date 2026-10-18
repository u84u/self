package packer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

type fakeRecipient struct{}

func (fakeRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "X25519", Args: []string{"x"}, Body: []byte("y")}}, nil
}

func TestPackRequiresRecipients(t *testing.T) {
	err := Pack(Options{Stub: "a", Target: "b", Out: "c"})
	if err == nil {
		t.Fatal("Pack without recipients succeeded, want error")
	}
}

func TestPackRejectsBadRecipientToken(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub")
	target := filepath.Join(dir, "target")

	// Write a stub with invalid token format (wrong length prefix)
	if err := os.WriteFile(stub, []byte{0x01, 0x02, 0x03}, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write a valid ELF target
	if err := os.WriteFile(target, []byte{0x7f, 0x01}, 0o755); err != nil {
		t.Fatal(err)
	}

	err := Pack(Options{
		Stub:       stub,
		Target:     target,
		Out:        filepath.Join(dir, "out"),
		Recipients: []age.Recipient{fakeRecipient{}},
	})
	if err == nil {
		t.Fatal("Pack accepted bad token, want error")
	}
	if !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("error %q should mention unexpected EOF", err)
	}
}

func TestPackRejectsNilRecipients(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub")
	target := filepath.Join(dir, "target")

	if err := os.WriteFile(stub, []byte{0x7f, 0x01}, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte{0x7f, 0x01}, 0o755); err != nil {
		t.Fatal(err)
	}

	err := Pack(Options{
		Stub:       stub,
		Target:     target,
		Out:        filepath.Join(dir, "out"),
		Recipients: nil,
	})
	if err == nil {
		t.Fatal("Pack with nil recipients succeeded, want error")
	}
}

func TestPackRequiresValidStubFormat(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub")
	// Write a file that's not a recognized format
	if err := os.WriteFile(stub, []byte("just some text"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte{0x7f, 0x01}, 0o755); err != nil {
		t.Fatal(err)
	}

	err := Pack(Options{
		Stub:       stub,
		Target:     target,
		Out:        filepath.Join(dir, "out"),
		Recipients: []age.Recipient{fakeRecipient{}},
	})
	if err == nil {
		t.Fatal("Pack accepted invalid stub format, want error")
	}
	if !strings.Contains(err.Error(), "unrecognised") {
		t.Errorf("error %q should mention unrecognised format", err)
	}
}

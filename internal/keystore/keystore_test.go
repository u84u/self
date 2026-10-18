package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir, "alice"); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	recipients, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(recipients) != 1 {
		t.Fatalf("Load returned %d recipients, want 1", len(recipients))
	}

	info, err := os.Stat(filepath.Join(dir, "alice.id"))
	if err != nil {
		t.Fatalf("Stat identity: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("identity permissions = %o, want 600", perm)
	}
}

func TestLoadRejectsNonEd25519(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rsa.pub"), ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = Load(dir)
	if err == nil {
		t.Fatal("Load accepted an RSA key, want error")
	}
	if !strings.Contains(err.Error(), "ssh-ed25519") {
		t.Errorf("error %q should name the supported key type", err)
	}
}

func TestLoadRequiresKeys(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("Load of an empty directory succeeded, want error")
	}
}

func TestGenerateRejectsBadName(t *testing.T) {
	for _, name := range []string{"", "../evil", "a/b"} {
		if err := Generate(t.TempDir(), name); err == nil {
			t.Errorf("Generate(%q) succeeded, want error", name)
		}
	}
}

func TestDecoys(t *testing.T) {
	recipients, err := Decoys(3)
	if err != nil {
		t.Fatalf("Decoys: %v", err)
	}
	if len(recipients) != 3 {
		t.Fatalf("Decoys returned %d recipients, want 3", len(recipients))
	}
	if _, err := Decoys(-1); err == nil {
		t.Fatal("Decoys(-1) succeeded, want error")
	}
}

func TestGenerateLoadZeroRecipientError(t *testing.T) {
	dir := t.TempDir()
	recipients, err := Load(dir)
	if err == nil {
		t.Fatal("Load with zero recipients succeeded, want error")
	}
	if len(recipients) != 0 {
		t.Fatalf("Load returned %d recipients, want 0", len(recipients))
	}
}
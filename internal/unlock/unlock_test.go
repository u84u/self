package unlock

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writeKey marshals key into OpenSSH format and writes it to dir/name.
func writeKey(t *testing.T, dir, name string, key any, passphrase []byte) {
	t.Helper()
	var (
		block *pem.Block
		err   error
	)
	if passphrase == nil {
		block, err = ssh.MarshalPrivateKey(key, name)
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, name, passphrase)
	}
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIdentities(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeKey(t, dir, "id_ed25519", priv, nil)
	writeKey(t, dir, "id_encrypted", priv, []byte("secret"))
	// Junk files alongside the keys must be skipped, not fatal.
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("Host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	identities, err := Identities(dir)
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("Identities returned %d identities, want 1 (encrypted key needs the passphrase)", len(identities))
	}

	t.Setenv(PassphraseEnv, "secret")
	identities, err = Identities(dir)
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(identities) != 2 {
		t.Fatalf("Identities returned %d identities, want 2 (encrypted key with passphrase)", len(identities))
	}
}

func TestIdentitiesMissingDir(t *testing.T) {
	identities, err := Identities(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(identities) != 0 {
		t.Fatalf("Identities returned %d identities, want 0", len(identities))
	}
}

func TestIdentityRejectsECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity(pem.EncodeToMemory(block), nil); err == nil {
		t.Fatal("identity accepted an ECDSA key, want error")
	}
}

func TestIdentitiesSkipsJunkFiles(t *testing.T) {
	dir := t.TempDir()
	// Write junk file alongside a note that it should be skipped
	if err := os.WriteFile(filepath.Join(dir, "junk"), []byte("\x00\x01\x02\x03"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No valid key files should result in 0 identities
	identities, err := Identities(dir)
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(identities) != 0 {
		t.Fatalf("Identities returned %d identities from junk only, want 0", len(identities))
	}
}

func TestIdentitiesWithEncryptedKeyRequiresPassphrase(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeKey(t, dir, "enc", priv, []byte("secret"))

	// Without passphrase should skip the encrypted key (return 0 identities)
	identities, err := Identities(dir)
	if err != nil {
		t.Fatalf("Identities: %v", err)
	}
	if len(identities) != 0 {
		t.Fatalf("Identities returned %d identities without passphrase, want 0", len(identities))
	}

	// With correct passphrase should succeed
	t.Setenv(PassphraseEnv, "secret")
	identities, err = Identities(dir)
	if err != nil {
		t.Fatalf("Identities with passphrase: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("Identities returned %d identities, want 1 with passphrase", len(identities))
	}
}
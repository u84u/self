// Package keystore manages the customer public keys that payloads are
// sealed to. Keys are plain OpenSSH public keys, one per *.pub file.
package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// validName reports whether name is a safe single path component for use as
// a key file stem.
func validName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return false
	}
	return true
}

// Load reads every *.pub file in dir and returns one recipient per key.
//
// Only ssh-ed25519 keys are accepted. A uniform key type keeps the sealed
// header homogeneous: decoy entries and real entries are indistinguishable,
// so an analyst cannot count customers by stanza type.
func Load(dir string) ([]age.Recipient, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, fmt.Errorf("keystore: list keys: %w", err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("keystore: no *.pub keys in %s", dir)
	}

	recipients := make([]age.Recipient, 0, len(paths))
	for _, path := range paths {
		if strings.HasSuffix(filepath.Base(path), ".sign.pub") {
			continue
		}
		pub, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("keystore: read %s: %w", path, err)
		}
		key, _, _, rest, err := ssh.ParseAuthorizedKey(pub)
		if err != nil {
			return nil, fmt.Errorf("keystore: parse %s: %w", filepath.Base(path), err)
		}
		if len(bytes.TrimSpace(rest)) > 0 {
			return nil, fmt.Errorf("keystore: parse %s: unexpected trailing data", filepath.Base(path))
		}
		if key.Type() != ssh.KeyAlgoED25519 {
			return nil, fmt.Errorf("keystore: %s: key type %q not supported, want %q",
				filepath.Base(path), key.Type(), ssh.KeyAlgoED25519)
		}
		r, err := agessh.NewEd25519Recipient(key)
		if err != nil {
			return nil, fmt.Errorf("keystore: %s: %w", filepath.Base(path), err)
		}
		recipients = append(recipients, r)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("keystore: no customer keys in %s", dir)
	}
	return recipients, nil
}

// Generate creates an ssh-ed25519 key pair named name in dir, writing
// name.pub (the customer's half) and name.id (a PEM private key, used to
// test packed artifacts; discard it once the customer's real key is on
// file).
func Generate(dir, name string) error {
	if !validName(name) {
		return fmt.Errorf("keystore: invalid key name %q", name)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keystore: generate key: %w", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".pub"), ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		return fmt.Errorf("keystore: write public key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "self "+name)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	idPath := filepath.Join(dir, name+".id")
	if err := os.WriteFile(idPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return fmt.Errorf("keystore: write identity: %w", err)
	}
	return nil
}

// GenerateSigningKey creates an Ed25519 signing key pair named name in dir,
// writing name.sign (hex seed) and name.sign.pub (hex public key).
func GenerateSigningKey(dir, name string) error {
	if !validName(name) {
		return fmt.Errorf("keystore: invalid key name %q", name)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keystore: generate signing key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".sign"), []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return fmt.Errorf("keystore: write signing key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".sign.pub"), []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return fmt.Errorf("keystore: write signing public key: %w", err)
	}
	return nil
}

// Decoys returns n recipients whose private halves are discarded. Padded
// into the sealed header they hide how many real customers exist: nobody,
// including the issuer, can tell a decoy stanza from a real one.
func Decoys(n int) ([]age.Recipient, error) {
	if n < 0 {
		return nil, errors.New("keystore: negative decoy count")
	}
	recipients := make([]age.Recipient, 0, n)
	for i := 0; i < n; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("keystore: decoy: %w", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("keystore: decoy: %w", err)
		}
		r, err := agessh.NewEd25519Recipient(sshPub)
		if err != nil {
			return nil, fmt.Errorf("keystore: decoy: %w", err)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}

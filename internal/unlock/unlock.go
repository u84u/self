// Package unlock runs a packed artifact: it locates the sealed blob in
// its own executable, opens it with a local SSH identity, and launches
// the plaintext image.
//
// Launching is platform specific: Linux executes from an anonymous
// in-memory file, macOS and the BSDs run a temporary file that is
// unlinked immediately, and Windows runs a temporary file that is deleted
// when the payload exits.
package unlock

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	"github.com/u84u/self/internal/format"
)

// Environment overrides, used by the tests and by operators debugging a
// locked machine.
const (
	// SSHDirEnv replaces ~/.ssh as the identity search path. Multiple
	// directories may be given, separated by the OS path list separator.
	SSHDirEnv = "SELF_SSH_DIR"
	// PassphraseEnv supplies the passphrase for encrypted key files.
	PassphraseEnv = "SELF_PASSPHRASE"
	// DebugEnv, when set to a truthy value, makes the stub print the
	// underlying reason for every failure instead of crashing silently.
	DebugEnv = "SELF_DEBUG"
)

// Run decrypts the payload embedded in the current executable and runs
// it. It returns the payload's exit status only on platforms that launch
// a child process; elsewhere a successful launch never returns. Every
// failure path returns an error so the caller can Crash.
func Run() (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("unlock: locate self: %w", err)
	}
	f, err := os.Open(exe)
	if err != nil {
		return 0, fmt.Errorf("unlock: open self: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("unlock: stat self: %w", err)
	}
	blob, footer, err := format.Open(f, info.Size())
	if err != nil {
		return 0, err
	}

	dirs := sshDirs()
	var identities []age.Identity
	for _, dir := range dirs {
		ids, err := Identities(dir)
		if err != nil {
			if debugMode() {
				fmt.Fprintf(os.Stderr, "self: debug: %s: %v\n", dir, err)
			}
			continue
		}
		identities = append(identities, ids...)
	}
	if len(identities) == 0 {
		return 0, fmt.Errorf("unlock: no usable identity in %s", strings.Join(dirs, string(os.PathListSeparator)))
	}
	plainReader, err := age.Decrypt(blob, identities...)
	if err != nil {
		if debugMode() {
			fmt.Fprintf(os.Stderr, "self: debug: decrypt: %v\n", err)
		}
		return 0, fmt.Errorf("unlock: %w", err)
	}
	plainBytes, err := io.ReadAll(plainReader)
	if err != nil {
		return 0, fmt.Errorf("unlock: read payload: %w", err)
	}
	if err := VerifyCapability(plainBytes); err != nil {
		return 0, err
	}
	extraEnv := ExtractEnv(plainBytes, footer)
	mlockBestEffort(plainBytes)
	plainBytes, err = ExtractPayload(plainBytes, footer)
	if err != nil {
		return 0, err
	}
	envv := os.Environ()
	envv = append(envv, extraEnv...)
	return Launch(bytes.NewReader(plainBytes), os.Args, envv)
}

func sshDirs() []string {
	if dir := os.Getenv(SSHDirEnv); dir != "" {
		dirs := filepath.SplitList(dir)
		out := make([]string, 0, len(dirs))
		for _, d := range dirs {
			if d != "" {
				out = append(out, d)
			}
		}
		return out
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, ".ssh")}
}

func sshDir() string {
	dirs := sshDirs()
	if len(dirs) == 0 {
		return ""
	}
	return dirs[0]
}

func debugMode() bool {
	v := strings.ToLower(os.Getenv(DebugEnv))
	return v != "" && v != "0" && v != "false" && v != "no"
}

// Identities parses every regular file in dir as a candidate private key.
// Files that are unreadable, encrypted without a passphrase, or of an
// unsupported key type are skipped: absence of a usable key must look
// exactly like presenting the wrong key.
func Identities(dir string) ([]age.Identity, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unlock: read %s: %w", dir, err)
	}
	passphrase := passphrase()

	var identities []age.Identity
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		// Stat, not entry.Info, so key files symlinked from a shared
		// or hardware-backed store are followed.
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			continue
		}
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			if debugMode() {
				fmt.Fprintf(os.Stderr, "self: debug: read %s: %v\n", path, err)
			}
			continue
		}
		id, err := identity(pemBytes, passphrase)
		if err != nil {
			if debugMode() {
				fmt.Fprintf(os.Stderr, "self: debug: skip %s: %v\n", path, err)
			}
			continue
		}
		identities = append(identities, id)
	}
	return identities, nil
}

// passphrase resolves the passphrase for encrypted keys. The environment
// variable takes precedence; otherwise we consult SSH_ASKPASS and, as a
// last resort, a controlling terminal. Returning nil means "no passphrase
// available", which makes encrypted keys be skipped (indistinguishable
// from presenting no key at all).
func passphrase() []byte {
	if v := os.Getenv(PassphraseEnv); v != "" {
		return []byte(v)
	}
	if askpass := os.Getenv("SSH_ASKPASS"); askpass != "" {
		cmd := exec.Command(askpass, "Enter passphrase for SSH key:")
		out, err := cmd.Output()
		if err == nil {
			return bytes.TrimSpace(out)
		}
	}
	// No controlling-terminal prompt by default: it would block
	// non-interactive callers (including `self verify`). Operators
	// needing a prompt can set SSH_ASKPASS to a helper program.
	return nil
}

// ExtractPayload converts the decrypted age plaintext into the original
// target bytes, honouring the footer's padding and expiry flags. It
// returns an error if the payload is truncated or outside its validity
// window.
func ExtractPayload(plain []byte, footer format.Footer) ([]byte, error) {
	if footer.Flags&format.FlagPadded == 0 {
		// Legacy v1 / unpadded payload.
		return plain, nil
	}
	headerSize := 8
	if footer.Flags&format.FlagExpiry != 0 {
		headerSize = 24
	}
	if len(plain) < headerSize {
		return nil, errors.New("unlock: truncated payload")
	}
	n := binary.LittleEndian.Uint64(plain[:8])
	envExtra := 0
	if footer.Flags&format.FlagEnv != 0 {
		if len(plain) < headerSize+4 {
			return nil, errors.New("unlock: truncated payload")
		}
		envExtra = 4 + int(binary.LittleEndian.Uint32(plain[headerSize:headerSize+4]))
	}
	if footer.Flags&format.FlagExpiry != 0 {
		notBefore := int64(binary.LittleEndian.Uint64(plain[8:16]))
		notAfter := int64(binary.LittleEndian.Uint64(plain[16:24]))
		now := time.Now().Unix()
		if notBefore > 0 && now < notBefore {
			return nil, errors.New("unlock: payload not yet valid")
		}
		if notAfter > 0 && now > notAfter {
			return nil, errors.New("unlock: payload expired")
		}
	}
	dataOff := headerSize + envExtra
	if dataOff > len(plain) {
		return nil, errors.New("unlock: truncated payload")
	}
	if uint64(len(plain)-dataOff) < n {
		return nil, errors.New("unlock: invalid payload size")
	}
	return plain[dataOff : dataOff+int(n)], nil
}

// ExtractEnv returns the environment strings embedded in the payload, if any.
func ExtractEnv(plain []byte, footer format.Footer) []string {
	if footer.Flags&format.FlagEnv == 0 {
		return nil
	}
	// Determine header size.
	headerSize := 8
	if footer.Flags&format.FlagExpiry != 0 {
		headerSize = 24
	}
	if len(plain) < headerSize+4 {
		return nil
	}
	envLen := int(binary.LittleEndian.Uint32(plain[headerSize : headerSize+4]))
	if headerSize+4+envLen > len(plain) {
		return nil
	}
	raw := string(plain[headerSize+4 : headerSize+4+envLen])
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\x00")
}

// VerifyCapability checks an issuer-signed capability token appended to
// the decrypted payload, if present. It returns nil when no token is
// embedded.
func VerifyCapability(plain []byte) error {
	marker := []byte("SELF-CAP")
	idx := bytes.LastIndex(plain, marker)
	if idx < 0 {
		return nil
	}
	off := idx + len(marker)
	if len(plain) < off+32+4 {
		return errors.New("unlock: truncated capability token")
	}
	pub := plain[off : off+32]
	off += 32
	tokenLen := int(binary.LittleEndian.Uint32(plain[off : off+4]))
	off += 4
	if len(plain) < off+tokenLen {
		return errors.New("unlock: truncated capability token")
	}
	token := plain[off : off+tokenLen]
	// token layout: payload + 64-byte signature
	if len(token) < 64 {
		return errors.New("unlock: invalid capability token")
	}
	payload := token[:len(token)-64]
	sig := token[len(token)-64:]
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("unlock: invalid capability signature")
	}
	// payload: customer|issued|expires
	parts := strings.Split(string(payload), "|")
	if len(parts) >= 3 {
		exp, err := strconv.ParseInt(parts[2], 10, 64)
		if err == nil && time.Now().Unix() > exp {
			return errors.New("unlock: capability expired")
		}
	}
	return nil
}

// identity converts an OpenSSH or PKCS#8 private key file into an age
// identity. ECDSA keys are rejected: the sealed header only carries
// ssh-ed25519 stanzas, and mixed stanza types would leak the real key
// count to anyone parsing the header.
func identity(pemBytes, passphrase []byte) (age.Identity, error) {
	key, err := ssh.ParseRawPrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if len(passphrase) == 0 {
			return nil, err
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	}
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return agessh.NewEd25519Identity(*k)
	case *rsa.PrivateKey:
		return agessh.NewRSAIdentity(k)
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// Package packer seals an executable behind a stub loader.
package packer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/u84u/self/internal/format"
)

// Options describes a pack operation.
type Options struct {
	Stub       string          // prebuilt loader binary
	Target     string          // executable to protect
	Out        string          // artifact to write
	Recipients []age.Recipient // customer keys, followed by decoys
	// NotBefore / NotAfter are optional unix timestamps for a validity
	// window. Zero means "no bound".
	NotBefore int64
	NotAfter  int64
	// Watermark is appended (encrypted) to the payload for leak tracing.
	Watermark string
	// Env is a list of KEY=VALUE strings injected into the payload's
	// environment at launch.
	Env []string
	// Capability is set when an issuer-signed token is appended to the
	// payload. IssuerPubKey is used only to verify the token before
	// packing; it is not written into the artifact, because a key the
	// payload carries cannot authorize the payload.
	Capability      bool
	IssuerPubKey    []byte
	CapabilityToken []byte
	// Sign re-signs the artifact ad hoc when the target is Mach-O.
	// Appending the payload breaks the stub's signature, and macOS on
	// Apple silicon refuses to exec a Mach-O with a broken signature.
	// Set false only when a macOS host will sign the artifact later.
	Sign bool
	// SignCmd, if non-empty, is an external signer invoked as a shell
	// command with {out} replaced by the artifact path.
	SignCmd string
}

// Pack writes an artifact that runs the target only when one of the
// recipients' private keys is present on the machine.
//
// The artifact layout is [stub][age blob][footer]; the target's bytes are
// the age file's plaintext, so the stub can decrypt straight into memory.
func Pack(o Options) (err error) {
	if len(o.Recipients) == 0 {
		return errors.New("packer: no recipients")
	}
	if o.Capability {
		if len(o.IssuerPubKey) != ed25519.PublicKeySize {
			return errors.New("packer: invalid issuer public key")
		}
		if len(o.CapabilityToken) < ed25519.SignatureSize {
			return errors.New("packer: invalid capability token")
		}
		payload := o.CapabilityToken[:len(o.CapabilityToken)-ed25519.SignatureSize]
		sig := o.CapabilityToken[len(o.CapabilityToken)-ed25519.SignatureSize:]
		if !ed25519.Verify(ed25519.PublicKey(o.IssuerPubKey), payload, sig) {
			return errors.New("packer: capability token is not signed by the issuer key")
		}
	}
	stubImage, err := inspect(o.Stub)
	if err != nil {
		return err
	}
	targetImage, err := inspect(o.Target)
	if err != nil {
		return err
	}
	if stubImage != targetImage {
		return fmt.Errorf("packer: stub is %s (%s) but target is %s (%s)",
			stubImage.format, stubImage.abi, targetImage.format, targetImage.abi)
	}
	if dir := filepath.Dir(o.Out); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("packer: %w", err)
		}
	}

	out, err := os.OpenFile(o.Out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("packer: %w", err)
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	if err := writeArtifact(out, o); err != nil {
		return err
	}
	if targetImage.format == "Mach-O" && o.Sign {
		if err := codesign(o.Out); err != nil {
			return err
		}
	}
	if o.SignCmd != "" {
		cmd := strings.ReplaceAll(o.SignCmd, "{out}", o.Out)
		// split
		parts := strings.Fields(cmd)
		if len(parts) == 0 {
			return errors.New("packer: empty sign command")
		}
		c := exec.Command(parts[0], parts[1:]...)
		out, err := c.CombinedOutput()
		if err != nil {
			return fmt.Errorf("packer: sign cmd: %w: %s", err, bytes.TrimSpace(out))
		}
	}
	return nil
}

func writeArtifact(out *os.File, o Options) error {
	stub, err := os.Open(o.Stub)
	if err != nil {
		return fmt.Errorf("packer: open stub: %w", err)
	}
	defer stub.Close()
	if _, err := io.Copy(out, stub); err != nil {
		return fmt.Errorf("packer: copy stub: %w", err)
	}

	target, err := os.Open(o.Target)
	if err != nil {
		return fmt.Errorf("packer: open target: %w", err)
	}
	defer target.Close()
	info, err := target.Stat()
	if err != nil {
		return fmt.Errorf("packer: stat target: %w", err)
	}
	plainSize := uint64(info.Size())

	counted := &countingWriter{w: out}
	w, err := age.Encrypt(counted, o.Recipients...)
	if err != nil {
		return fmt.Errorf("packer: seal: %w", err)
	}
	expiry := o.NotBefore != 0 || o.NotAfter != 0
	hasEnv := len(o.Env) > 0
	headerSize := 8
	if expiry {
		headerSize = 24
	}
	flags := format.FlagPadded
	if expiry {
		flags |= format.FlagExpiry
	}
	if hasEnv {
		flags |= format.FlagEnv
	}

	envJoined := strings.Join(o.Env, "\x00")
	envBytes := []byte(envJoined)
	if hasEnv && len(o.Env) > 0 {
		// ensure trailing separator not needed; length prefix covers it
	}

	// Length-prefixed, padded plaintext: header, payload, then random
	// padding to a 4096-byte boundary so the payload's exact size is
	// not revealed by the blob.
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint64(header[0:8], plainSize)
	if expiry {
		binary.LittleEndian.PutUint64(header[8:16], uint64(o.NotBefore))
		binary.LittleEndian.PutUint64(header[16:24], uint64(o.NotAfter))
	}
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("packer: seal payload: %w", err)
	}
	if hasEnv {
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(envBytes)))
		if _, err := w.Write(l[:]); err != nil {
			return fmt.Errorf("packer: seal payload: %w", err)
		}
		if _, err := w.Write(envBytes); err != nil {
			return fmt.Errorf("packer: seal payload: %w", err)
		}
	}
	if _, err := io.Copy(w, target); err != nil {
		return fmt.Errorf("packer: seal payload: %w", err)
	}
	envExtra := 0
	if hasEnv {
		envExtra = 4 + len(envBytes)
	}
	total := headerSize + envExtra + int(plainSize)
	pad := (4096 - (total % 4096)) % 4096
	if pad < 16 {
		pad += 4096
	}
	if pad > 0 {
		buf := make([]byte, pad)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("packer: seal payload: %w", err)
		}
		if _, err := w.Write(buf); err != nil {
			return fmt.Errorf("packer: seal payload: %w", err)
		}
	}
	if o.Watermark != "" {
		if _, err := w.Write([]byte(o.Watermark)); err != nil {
			return fmt.Errorf("packer: seal payload: %w", err)
		}
	}
	if o.Capability {
		// marker | token | token length, so the stub can read the
		// token from the end without scanning for the marker.
		if _, err := w.Write([]byte(format.CapabilityMarker)); err != nil {
			return fmt.Errorf("packer: seal payload: %w", err)
		}
		if _, err := w.Write(o.CapabilityToken); err != nil {
			return fmt.Errorf("packer: seal payload: %w", err)
		}
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(o.CapabilityToken)))
		if _, err := w.Write(l[:]); err != nil {
			return fmt.Errorf("packer: seal payload: %w", err)
		}
		flags |= format.FlagCapability
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("packer: seal: %w", err)
	}
	footer := format.Footer{Version: format.Version, Flags: flags, BlobSize: counted.n}
	if _, err := out.Write(format.Encode(footer)); err != nil {
		return fmt.Errorf("packer: write footer: %w", err)
	}
	return nil
}

// codesign replaces the artifact's signature with a fresh ad-hoc one.
func codesign(path string) error {
	out, err := exec.Command("codesign", "--force", "--sign", "-", path).CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) {
		return errors.New("packer: codesign not found: pack with -sign=false and sign on a macOS host")
	}
	if err != nil {
		return fmt.Errorf("packer: codesign %s: %w: %s", path, err, bytes.TrimSpace(out))
	}
	return nil
}

type countingWriter struct {
	w io.Writer
	n uint64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += uint64(n)
	return n, err
}

package packer_test

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/u84u/self/internal/keystore"
	"github.com/u84u/self/internal/packer"
	"github.com/u84u/self/internal/unlock"
)

// The end-to-end tests build the real stub and a real payload, pack the
// payload, and execute the artifact. They exercise the host platform's
// launch path end to end.

var (
	stubPath  string
	helloPath string
	buildErr  error
)

const helloOutput = "hello from the payload\n"

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "self-e2e-")
	if err != nil {
		buildErr = err
		os.Exit(m.Run())
	}
	stubPath = filepath.Join(dir, "stub")
	helloPath = filepath.Join(dir, "hello")
	root, err := filepath.Abs("../..")
	if err == nil {
		buildErr = build(root, stubPath, "./cmd/stub")
	}
	if buildErr == nil {
		buildErr = build(root, helloPath, "./testdata/hello")
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func build(root, out, pkg string, env ...string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Env = append(cmd.Env, env...)
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %v: %s", pkg, err, outBytes)
	}
	return nil
}

func TestAuthorizedKeyRunsPayload(t *testing.T) {
	requireBuild(t)
	tmp := t.TempDir()
	keys := keysDir(t, tmp, "alice")
	artifact := pack(t, tmp, keys, 3)

	stdout, stderr, state := run(t, artifact, identityDir(t, tmp, "alice", keys))
	if !state.Success() {
		t.Fatalf("artifact exited with %v, stderr %q", state, stderr)
	}
	if stdout != helloOutput {
		t.Errorf("stdout = %q, want %q", stdout, helloOutput)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

func TestUnknownKeyCrashes(t *testing.T) {
	requireBuild(t)
	tmp := t.TempDir()
	artifact := pack(t, tmp, keysDir(t, tmp, "alice"), 2)

	stdout, stderr, state := run(t, artifact, identityDir(t, tmp, "bob", keysDir(t, tmp, "bob")))
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	wantCrash(t, state, stderr)
}

func TestMissingKeyDirCrashes(t *testing.T) {
	requireBuild(t)
	tmp := t.TempDir()
	artifact := pack(t, tmp, keysDir(t, tmp, "alice"), 2)

	_, stderr, state := run(t, artifact, filepath.Join(tmp, "no-such-dir"))
	wantCrash(t, state, stderr)
}

// TestHeaderIsAnonymous is the leakage test: the artifact must not
// contain the customer's public key in any form, and the decoy entries
// must make the real key count indistinguishable.
func TestHeaderIsAnonymous(t *testing.T) {
	requireBuild(t)
	tmp := t.TempDir()
	keys := keysDir(t, tmp, "alice")
	const decoys = 5
	artifact := pack(t, tmp, keys, decoys)

	blob, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}

	pubLine, err := os.ReadFile(filepath.Join(keys, "alice.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, bytes.TrimSpace(pubLine)) {
		t.Error("artifact contains the authorized_keys line")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	raw := key.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if bytes.Contains(blob, raw) {
		t.Error("artifact contains the raw Ed25519 public key")
	}

	// The private half must never appear in the artifact.
	if idBytes, err := os.ReadFile(filepath.Join(keys, "alice.id")); err == nil {
		if bytes.Contains(blob, idBytes) {
			t.Error("artifact contains the private key material")
		}
	}

	if got, want := bytes.Count(blob, []byte("-> ssh-ed25519 ")), 1+decoys; got != want {
		t.Errorf("artifact has %d ssh-ed25519 stanzas, want %d (customer + decoys)", got, want)
	}
}

// TestPackWindows386 packs a PE32 payload with the windows/386 stub.
// Windows artifacts cannot execute on this host, so the test stops at
// packing: it guards the ABI match for the 32-bit Windows target, whose
// PE32/IMAGE_FILE_MACHINE_I386 header must not be confused with the
// 64-bit PE32+ one.
func TestPackWindows386(t *testing.T) {
	tmp := t.TempDir()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(tmp, "stub.exe")
	payload := filepath.Join(tmp, "hello.exe")
	if err := build(root, stub, "./cmd/stub", "GOOS=windows", "GOARCH=386"); err != nil {
		t.Fatal(err)
	}
	if err := build(root, payload, "./testdata/hello", "GOOS=windows", "GOARCH=386"); err != nil {
		t.Fatal(err)
	}
	recipients, err := keystore.Load(keysDir(t, tmp, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	pad, err := keystore.Decoys(2)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "hello.exe.locked")
	if err := packer.Pack(packer.Options{
		Stub:       stub,
		Target:     payload,
		Out:        out,
		Recipients: append(recipients, pad...),
	}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		t.Fatal(err)
	}
	if string(magic[:]) != "MZ" {
		t.Errorf("artifact starts with %q, want the PE stub's MZ header", magic)
	}
}

// TestPlatform checks the mapping that selects which embedded stub self
// prepends to a target.
func TestPlatform(t *testing.T) {
	tmp := t.TempDir()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		goos, goarch string
		want         string
	}{
		{"linux", "arm64", "linux/arm64"},
		{"darwin", "arm64", "darwin/arm64"},
		{"windows", "amd64", "windows/amd64"},
		{"windows", "386", "windows/386"},
	}
	for _, c := range cases {
		name := c.goos + "-" + c.goarch
		target := filepath.Join(tmp, name)
		if err := build(root, target, "./testdata/hello", "GOOS="+c.goos, "GOARCH="+c.goarch); err != nil {
			t.Fatal(err)
		}
		got, err := packer.Platform(target)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != c.want {
			t.Errorf("Platform(%s) = %q, want %q", name, got, c.want)
		}
	}

	// A CPU outside the stub set must be rejected, not guessed.
	riscv := filepath.Join(tmp, "linux-riscv64")
	if err := build(root, riscv, "./testdata/hello", "GOOS=linux", "GOARCH=riscv64"); err != nil {
		t.Fatal(err)
	}
	if got, err := packer.Platform(riscv); err == nil {
		t.Errorf("Platform(linux/riscv64) = %q, want an error", got)
	}
}

// TestCrossPlatformPack builds and packs an artifact for every platform self
// ships a stub for. Execution is not possible for foreign platforms, so
// this stops at packing and checks the resulting container magic.
func TestCrossPlatformPack(t *testing.T) {
	tmp := t.TempDir()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	platforms := []struct {
		goos, goarch, magic string
	}{
		{"linux", "amd64", "\x7fELF"},
		{"linux", "arm64", "\x7fELF"},
		{"darwin", "amd64", "\xcf\xfa\xed\xfe"},
		{"darwin", "arm64", "\xcf\xfa\xed\xfe"},
		{"windows", "amd64", "MZ"},
		{"windows", "386", "MZ"},
	}
	for _, p := range platforms {
		name := p.goos + "-" + p.goarch
		t.Run(name, func(t *testing.T) {
			stub := filepath.Join(tmp, name+"-stub")
			payload := filepath.Join(tmp, name+"-hello")
			if err := build(root, stub, "./cmd/stub", "GOOS="+p.goos, "GOARCH="+p.goarch); err != nil {
				t.Fatal(err)
			}
			if err := build(root, payload, "./testdata/hello", "GOOS="+p.goos, "GOARCH="+p.goarch); err != nil {
				t.Fatal(err)
			}
			keys := keysDir(t, tmp, "alice")
			recipients, err := keystore.Load(keys)
			if err != nil {
				t.Fatal(err)
			}
			pad, _ := keystore.Decoys(1)
			out := filepath.Join(tmp, name+".locked")
			if err := packer.Pack(packer.Options{
				Stub:       stub,
				Target:     payload,
				Out:        out,
				Recipients: append(recipients, pad...),
			}); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(out)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			magic := make([]byte, len(p.magic))
			if _, err := io.ReadFull(f, magic); err != nil {
				t.Fatal(err)
			}
			// Just ensure it starts with the stub's magic by re-reading stub.
			sf, _ := os.Open(stub)
			defer sf.Close()
			sm := make([]byte, len(magic))
			sf.Read(sm)
			if !bytes.Equal(magic, sm) {
				t.Errorf("artifact magic %v != stub magic %v", magic, sm)
			}
		})
	}
}

func requireBuild(t *testing.T) {
	t.Helper()
	if buildErr != nil {
		t.Skipf("cannot build test binaries: %v", buildErr)
	}
}

// keysDir generates a key pair named name and returns its directory.
func keysDir(t *testing.T, tmp, name string) string {
	t.Helper()
	dir := filepath.Join(tmp, "keys-"+name)
	if err := keystore.Generate(dir, name); err != nil {
		t.Fatal(err)
	}
	return dir
}

// identityDir mimics ~/.ssh: a directory holding the private half of the
// key named name.
func identityDir(t *testing.T, tmp, name, keys string) string {
	t.Helper()
	id, err := os.ReadFile(filepath.Join(keys, name+".id"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(tmp, "ssh-"+name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), id, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func pack(t *testing.T, tmp, keys string, decoys int) string {
	t.Helper()
	recipients, err := keystore.Load(keys)
	if err != nil {
		t.Fatal(err)
	}
	pad, err := keystore.Decoys(decoys)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "hello.locked")
	if err := packer.Pack(packer.Options{
		Stub:       stubPath,
		Target:     helloPath,
		Out:        out,
		Recipients: append(recipients, pad...),
		Sign:       true,
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func run(t *testing.T, artifact, sshDir string) (stdout, stderr string, state *os.ProcessState) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cmd := exec.Command(artifact)
	cmd.Env = append(os.Environ(), unlock.SSHDirEnv+"="+sshDir)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	_ = cmd.Run() // a crash is a valid outcome here
	if cmd.ProcessState == nil {
		t.Fatal("artifact did not start")
	}
	return outBuf.String(), errBuf.String(), cmd.ProcessState
}

// wantCrash asserts the platform's failure semantics: SIGSEGV on POSIX,
// STATUS_ACCESS_VIOLATION on Windows.
func wantCrash(t *testing.T, state *os.ProcessState, stderr string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if code := uint32(state.ExitCode()); code != 0xC0000005 {
			t.Fatalf("exit code %#x, want STATUS_ACCESS_VIOLATION", code)
		}
		return
	}
	ws, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGSEGV {
		t.Fatalf("process state = %v, want death by SIGSEGV", state)
	}
	// Linux resets the disposition before faulting, so the crash is
	// completely silent there.
	if runtime.GOOS == "linux" && stderr != "" {
		t.Errorf("stderr on crash = %q, want empty", stderr)
	}
}

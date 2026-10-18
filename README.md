# self

Seal an executable behind a set of SSH public keys. The packed artifact
runs only on a machine that holds a matching private key, and the sealed
header reveals nothing about which keys are authorized: no key ids, no
fingerprints, no way to count the real customers apart from the decoys.

## How it works

An artifact is `[stub][age blob][footer]`. The stub is an ordinary
executable; the blob is a standard [`age`](https://age-encryption.org)
file whose plaintext is the target and whose recipients are the
customers' `ssh-ed25519` keys plus decoy entries. On launch the stub
finds the blob through the fixed-size footer, tries every private key in
`~/.ssh` against it, and runs the plaintext. A wrong or absent key ends
in a bare crash.

Decoys make the header homogeneous: a decoy stanza is byte-for-byte the
same shape as a real one, so nobody can count the customers or tell
which stanzas are real. The customer-to-stanza mapping exists only in
the issuer's `keys/` directory and never ships.

## Build

    make          # build/self, with a loader stub for every platform embedded
    make test

`make stubs` alone rebuilds the gzipped loaders (linux/amd64+arm64,
darwin/amd64+arm64, windows/amd64+386) that `make` embeds into `self`.

## Use

    build/self keygen -keys keys -name alice        # test pair; the customer sends you their alice.pub
    build/self pack -target ./myapp -keys keys -out dist/myapp.locked

Every command's flags are listed by `self <command> -h`; `self -h` lists
the commands. `pack` reads the target's format and prepends the embedded
stub for its platform; `-stub` overrides that with a custom loader.
Packing is validation only; the same `build/self` runs on any platform
and keeps the `*.id` private halves out of the artifact.

## Platforms

| Platform | Launch | Notes |
| --- | --- | --- |
| Linux | `memfd_create` + `execveat`: replaces the process, never touches disk | silent real SIGSEGV on failure |
| macOS, BSDs | temp file unlinked right after start | crash may carry a Go runtime report; run `codesign` on the artifact if you skip `-sign` |
| Windows | temp file deleted when the payload exits | locked on disk while running; `STATUS_ACCESS_VIOLATION` on failure |

Mach-O artifacts are re-signed ad hoc by the packer (`-sign=false` to
skip, then sign on a macOS host). Appending a payload invalidates
Authenticode signatures on PE files the same way; re-sign after packing
if you ship signed binaries.

## Limits

This is licensing enforcement, not DRM. It stops casual sharing — each
machine needs a real authorized key — but anyone holding a licensed key
can decrypt the payload from a debugger, and anyone who patches the
auth check skips it entirely. The memfd launch on Linux is also a
pattern that EDR products watch closely; expect allowlisting
conversations with customers that run endpoint security.

## Additional limitations

- SSH agents cannot be used for decryption: age needs the private key
  material (the Ed25519 seed), which agents never expose. Keys must be
  files on disk (or supplied via `SELF_SSH_DIR`).
- Revocation is not supported without repacking: removing a customer
  means re-issuing the artifact without their key. The anonymous header
  makes per-customer revocation lists impossible without leaking identity.
- Optional time windows rely on the machine clock and are trivially
  bypassed; treat them as licensing hints, not enforcement.
- `SELF_DEBUG=1` prints underlying failure reasons to stderr; leave it
  unset in production to keep the crash silent.

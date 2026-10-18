The gzipped loader stubs consumed by package stubs are build outputs:
"make stubs" writes stub-<goos>-<goarch>.gz here from ./cmd/stub, and
self embeds whatever is present when it is built. This placeholder keeps
the directory (and the go:embed pattern) valid in a fresh clone.

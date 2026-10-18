// Package stubs embeds the prebuilt loader binaries that self prepends
// to artifacts, one per supported platform, and resolves them by
// platform name.
//
// The assets are build outputs: "make stubs" builds cmd/stub for every
// platform and writes gzipped copies into assets/, and a self built
// after that embeds them. A fresh clone embeds only the placeholder, so
// lookups fail with build instructions rather than misbehaving.
package stubs

import (
	"compress/gzip"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
)

// Supported lists the platforms a full build embeds a stub for.
var Supported = []string{
	"linux/amd64",
	"linux/arm64",
	"darwin/amd64",
	"darwin/arm64",
	"windows/amd64",
	"windows/386",
}

//go:embed assets/*
var embedded embed.FS

// Lookup returns the stub binary for platform, named like "windows/386".
func Lookup(platform string) ([]byte, error) {
	return lookup(embedded, platform)
}

func lookup(fsys fs.FS, platform string) ([]byte, error) {
	if !slices.Contains(Supported, platform) {
		return nil, fmt.Errorf("stubs: unsupported platform %s; stubs ship for %s",
			platform, strings.Join(Supported, ", "))
	}
	name := "assets/stub-" + strings.ReplaceAll(platform, "/", "-") + ".gz"
	f, err := fsys.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("stubs: %w; run \"make stubs\" and rebuild self to embed the %s stub",
			err, platform)
	}
	if err != nil {
		return nil, fmt.Errorf("stubs: %w", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("stubs: %s: %w", name, err)
	}
	defer zr.Close()
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("stubs: %s: %w", name, err)
	}
	return data, nil
}

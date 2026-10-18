package packer

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
)

// image describes an executable's container format and ABI. Two images
// are compatible, and only then can one stub launch the other, when
// their format and ABI strings match.
type image struct {
	format string // "ELF", "PE", or "Mach-O"
	abi    string // details such as class and machine
	// goos and goarch name the platform self ships a stub for, for
	// choosing which one to prepend; empty for unsupported targets.
	goos, goarch string
}

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// inspect reads just enough of path to identify its format and ABI.
func inspect(path string) (image, error) {
	f, err := os.Open(path)
	if err != nil {
		return image{}, fmt.Errorf("packer: %w", err)
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return image{}, fmt.Errorf("packer: %s: %w", path, err)
	}

	if bytes.Equal(magic[:], elfMagic) {
		ef, err := elf.Open(path)
		if err != nil {
			return image{}, fmt.Errorf("packer: %s: %w", path, err)
		}
		defer ef.Close()
		img := image{format: "ELF", abi: fmt.Sprintf("%v/%v/%v/%v", ef.Class, ef.Data, ef.OSABI, ef.Machine)}
		switch ef.Machine {
		case elf.EM_X86_64:
			// An ELF header says nothing about the OS; Linux is the
			// only one self ships a stub for.
			img.goos, img.goarch = "linux", "amd64"
		case elf.EM_AARCH64:
			img.goos, img.goarch = "linux", "arm64"
		case elf.EM_386:
			// No stub ships for 32-bit Linux, but naming the platform
			// lets the error say so.
			img.goos, img.goarch = "linux", "386"
		}
		return img, nil
	}

	if magic[0] == 'M' && magic[1] == 'Z' {
		pf, err := pe.Open(path)
		if err != nil {
			return image{}, fmt.Errorf("packer: %s: %w", path, err)
		}
		defer pf.Close()
		// PE32 vs PE32+ decides whether the stub and the payload
		// interpret pointers the same way, so it belongs in the ABI.
		bits := "PE32"
		if _, ok := pf.OptionalHeader.(*pe.OptionalHeader64); ok {
			bits = "PE32+"
		}
		img := image{format: "PE", abi: fmt.Sprintf("%s/%v", bits, pf.Machine)}
		switch {
		case bits == "PE32+" && pf.Machine == pe.IMAGE_FILE_MACHINE_AMD64:
			img.goos, img.goarch = "windows", "amd64"
		case bits == "PE32" && pf.Machine == pe.IMAGE_FILE_MACHINE_I386:
			img.goos, img.goarch = "windows", "386"
		}
		return img, nil
	}

	if isMachOMagic(magic) {
		if isFatMachOMagic(magic) {
			return image{}, fmt.Errorf("packer: %s: universal Mach-O binary, thin it with lipo -thin first", path)
		}
		mf, err := macho.Open(path)
		if err != nil {
			return image{}, fmt.Errorf("packer: %s: %w", path, err)
		}
		defer mf.Close()
		img := image{format: "Mach-O", abi: fmt.Sprintf("%#x/%v/%#x", mf.Magic, mf.Cpu, mf.SubCpu)}
		switch mf.Cpu {
		case macho.CpuAmd64:
			img.goos, img.goarch = "darwin", "amd64"
		case macho.CpuArm64:
			img.goos, img.goarch = "darwin", "arm64"
		}
		return img, nil
	}

	return image{}, fmt.Errorf("packer: %s: unrecognised executable format", path)
}

// Platform names the GOOS/GOARCH pair a target runs on, such as
// "windows/386", for selecting the stub to prepend to it.
func Platform(path string) (string, error) {
	img, err := inspect(path)
	if err != nil {
		return "", err
	}
	if img.goos == "" {
		return "", fmt.Errorf("packer: %s: no stub platform for %s (%s); pass -stub to prepend a custom loader",
			path, img.format, img.abi)
	}
	return img.goos + "/" + img.goarch, nil
}

// isMachOMagic matches the four thin and four fat Mach-O magics in both
// byte orders.
func isMachOMagic(m [4]byte) bool {
	switch m {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xce, 0xfa, 0xed, 0xfe}, // 32-bit
		[4]byte{0xfe, 0xed, 0xfa, 0xcf}, [4]byte{0xcf, 0xfa, 0xed, 0xfe}, // 64-bit
		[4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca}, // fat
		[4]byte{0xca, 0xfe, 0xba, 0xbf}, [4]byte{0xbf, 0xba, 0xfe, 0xca}: // fat 64
		return true
	}
	return false
}

func isFatMachOMagic(m [4]byte) bool {
	switch m {
	case [4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca},
		[4]byte{0xca, 0xfe, 0xba, 0xbf}, [4]byte{0xbf, 0xba, 0xfe, 0xca}:
		return true
	}
	return false
}

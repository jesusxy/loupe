// Package inspect is Loupe's static PE inspection boundary. It never executes input.
package inspect

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
)

const (
	optionalHeaderMagicPE32     uint16 = 0x10b
	optionalHeaderMagicPE32Plus uint16 = 0x20b
	MaxFileSize                        = 16 << 20
	MaxSections                        = 96
)

type ImageInfo struct {
	Arch                uint16 // machine arch
	Magic               uint16
	ImageBase           uint64
	ImportDataDirectory pe.DataDirectory
	EntryPointRVA       uint32
	EntryPointVA        uint64
	SizeOfImage         uint32
	SizeOfHeaders       uint32
	SectionAlignment    uint32
	Sections            []*pe.Section
}

// Parse extracts the same image model used by Loupe's native loader.
// Preflight bounds every debug/pe allocation path before calling that package.
func Parse(raw []byte) (info *ImageInfo, err error) {
	defer func() {
		if recover() != nil {
			info = nil
			err = fmt.Errorf("malformed PE structure")
		}
	}()
	if err := validate(raw); err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid PE: %w", err)
	}
	defer f.Close()
	imageInfo := ImageInfo{}

	imageInfo.Arch = f.FileHeader.Machine
	imageInfo.Sections = f.Sections

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageInfo.ImageBase = uint64(oh.ImageBase)
		imageInfo.EntryPointRVA = oh.AddressOfEntryPoint
		imageInfo.Magic = oh.Magic
		imageInfo.ImportDataDirectory = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		imageInfo.SizeOfImage = oh.SizeOfImage
		imageInfo.SizeOfHeaders = oh.SizeOfHeaders
		imageInfo.SectionAlignment = oh.SectionAlignment
	case *pe.OptionalHeader64:
		imageInfo.ImageBase = uint64(oh.ImageBase)
		imageInfo.EntryPointRVA = oh.AddressOfEntryPoint
		imageInfo.Magic = oh.Magic
		imageInfo.ImportDataDirectory = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		imageInfo.SizeOfImage = oh.SizeOfImage
		imageInfo.SizeOfHeaders = oh.SizeOfHeaders
		imageInfo.SectionAlignment = oh.SectionAlignment
	default:
		return nil, fmt.Errorf("unsupported optional header type %T", f.OptionalHeader)
	}

	valid32 := imageInfo.Arch == pe.IMAGE_FILE_MACHINE_I386 &&
		imageInfo.Magic == optionalHeaderMagicPE32
	valid64 := imageInfo.Arch == pe.IMAGE_FILE_MACHINE_AMD64 &&
		imageInfo.Magic == optionalHeaderMagicPE32Plus

	if !valid32 && !valid64 {
		return nil, fmt.Errorf(
			"unsupported or inconsistent PE architecture: machine 0x%x magic=0x%x",
			imageInfo.Arch,
			imageInfo.Magic,
		)
	}

	for _, section := range imageInfo.Sections {
		if len(section.Name) > 256 {
			return nil, fmt.Errorf("section name exceeds 256 bytes")
		}
	}
	if imageInfo.ImageBase > ^uint64(0)-uint64(imageInfo.EntryPointRVA) {
		return nil, fmt.Errorf("entry point address overflows")
	}
	imageInfo.EntryPointVA = imageInfo.ImageBase + uint64(imageInfo.EntryPointRVA)

	return &imageInfo, nil
}
func span(raw []byte, offset, size uint64) bool {
	return offset <= uint64(len(raw)) && size <= uint64(len(raw))-offset
}

func validate(b []byte) error {
	if len(b) > MaxFileSize {
		return fmt.Errorf("file exceeds 16 MiB limit")
	}
	if len(b) < 96 || string(b[:2]) != "MZ" {
		return fmt.Errorf("expected a Windows PE file with an MZ header")
	}
	u16 := func(o uint64) uint64 { return uint64(binary.LittleEndian.Uint16(b[o : o+2])) }
	u32 := func(o uint64) uint64 { return uint64(binary.LittleEndian.Uint32(b[o : o+4])) }
	peoff := u32(0x3c)
	if peoff < 64 || !span(b, peoff, 24) || string(b[peoff:peoff+4]) != "PE\x00\x00" {
		return fmt.Errorf("invalid PE signature or header offset")
	}
	coff := peoff + 4
	sections, optSize := u16(coff+2), u16(coff+16)
	if sections == 0 || sections > MaxSections {
		return fmt.Errorf("supported section count is 1–96")
	}
	opt := coff + 20
	if !span(b, opt, optSize) || optSize < 96 {
		return fmt.Errorf("truncated optional header")
	}
	machine, magic := u16(coff), u16(opt)
	var directoryStart uint64
	switch {
	case machine == 0x14c && magic == 0x10b:
		directoryStart = 96
	case machine == 0x8664 && magic == 0x20b:
		directoryStart = 112
	default:
		return fmt.Errorf("supported formats are x86 PE32 and x86-64 PE32+")
	}
	if optSize < directoryStart {
		return fmt.Errorf("truncated optional header")
	}
	dirs := u32(opt + directoryStart - 4)
	if dirs > 16 || optSize != directoryStart+8*dirs {
		return fmt.Errorf("invalid data-directory count or optional-header size")
	}
	table := opt + optSize
	if !span(b, table, sections*40) {
		return fmt.Errorf("truncated section table")
	}
	headers := u32(opt + 60)
	if headers < table+sections*40 || headers > uint64(len(b)) {
		return fmt.Errorf("invalid SizeOfHeaders")
	}
	// debug/pe eagerly reads COFF symbols, string tables and relocations.
	// Bound all three, including records not used in the public inspector.
	symbols, count := u32(coff+8), u32(coff+12)
	if count > 65536 {
		return fmt.Errorf("COFF symbol limit exceeded")
	}
	if symbols != 0 {
		if !span(b, symbols, count*18+4) {
			return fmt.Errorf("invalid COFF symbol range")
		}
		strings := symbols + count*18
		length := u32(strings)
		if length < 4 || length > 1<<20 || !span(b, strings, length) {
			return fmt.Errorf("invalid COFF string table")
		}
	}
	for i := uint64(0); i < sections; i++ {
		s := table + i*40
		size, offset := u32(s+16), u32(s+20)
		if size != 0 && offset != 0 && !span(b, offset, size) {
			return fmt.Errorf("section %d extends beyond the file", i+1)
		}
		if u32(s+12)+u32(s+8) > 1<<32 {
			return fmt.Errorf("section virtual range overflows")
		}
		reloc, nreloc := u32(s+24), u16(s+32)
		if nreloc > 4096 || (nreloc != 0 && !span(b, reloc, nreloc*10)) {
			return fmt.Errorf("invalid or excessive relocation records")
		}
	}
	return nil
}

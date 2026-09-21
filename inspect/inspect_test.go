package inspect

import (
	"encoding/binary"
	"testing"
)

// Synthetic PE fixtures are for parser tests only. They are not published as research artifacts.
func fixture(wide bool) []byte {
	b := make([]byte, 1024)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	put16 := func(o int, v uint16) { binary.LittleEndian.PutUint16(b[o:], v) }
	put32 := func(o int, v uint32) { binary.LittleEndian.PutUint32(b[o:], v) }
	machine, magic, optsize := uint16(0x14c), uint16(0x10b), uint16(224)
	if wide {
		machine, magic, optsize = 0x8664, 0x20b, 240
	}
	put16(0x84, machine)
	put16(0x86, 1)
	put16(0x94, optsize)
	opt := 0x98
	put16(opt, magic)
	put32(opt+16, 0x1000)
	if wide {
		binary.LittleEndian.PutUint64(b[opt+24:], 0x140000000)
		put32(opt+108, 16)
	} else {
		put32(opt+28, 0x400000)
		put32(opt+92, 16)
	}
	put32(opt+32, 0x1000)
	put32(opt+36, 512)
	put32(opt+56, 0x2000)
	put32(opt+60, 512)
	s := opt + int(optsize)
	copy(b[s:], ".text")
	put32(s+8, 8)
	put32(s+12, 0x1000)
	put32(s+16, 512)
	put32(s+20, 512)
	put32(s+36, 0x60000020)
	return b
}
func TestSupportedImages(t *testing.T) {
	for _, wide := range []bool{false, true} {
		info, err := Parse(fixture(wide))
		if err != nil {
			t.Fatal(err)
		}
		base := uint64(0x400000)
		if wide {
			base = 0x140000000
		}
		if info.ImageBase != base || info.EntryPointVA != base+0x1000 || len(info.Sections) != 1 || info.Sections[0].Name != ".text" {
			t.Fatalf("unexpected image: %+v", info)
		}
	}
}
func TestMalformed(t *testing.T) {
	cases := map[string]func([]byte){
		"signature":    func(b []byte) { b[0] = 0 },
		"offset":       func(b []byte) { binary.LittleEndian.PutUint32(b[0x3c:], 0xffffffff) },
		"sections":     func(b []byte) { binary.LittleEndian.PutUint16(b[0x86:], 65535) },
		"architecture": func(b []byte) { binary.LittleEndian.PutUint16(b[0x84:], 0xaa64) },
		"optional":     func(b []byte) { binary.LittleEndian.PutUint16(b[0x94:], 1) },
		"directories":  func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+108:], 0xffffffff) },
		"headers":      func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+60:], 0xffffffff) },
		"raw range":    func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+240+20:], 0xffffffff) },
		"symbols":      func(b []byte) { binary.LittleEndian.PutUint32(b[0x90:], 0xffffffff) },
		"zero count string table": func(b []byte) {
			binary.LittleEndian.PutUint32(b[0x8c:], 1000)
			binary.LittleEndian.PutUint32(b[1000:], 0xffffffff)
		},
		"relocations":      func(b []byte) { binary.LittleEndian.PutUint16(b[0x98+240+32:], 65535) },
		"virtual overflow": func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+240+12:], 0xffffffff) },
		"entry overflow":   func(b []byte) { binary.LittleEndian.PutUint64(b[0x98+24:], 0xffffffffffffffff) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := fixture(true)
			mutate(b)
			if _, err := Parse(b); err == nil {
				t.Fatal("accepted malformed file")
			}
		})
	}
	for n := 0; n < 512; n++ {
		if _, err := Parse(fixture(true)[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
}
func TestFileSizeIsCallerPolicy(t *testing.T) {
	// A trailing overlay must not make the core apply the browser's 16 MiB budget.
	b := make([]byte, (17<<20)+1)
	copy(b, fixture(true))
	info, err := Parse(b)
	if err != nil || info == nil || info.EntryPointVA != 0x140001000 {
		t.Fatalf("larger image: info=%+v, err=%v", info, err)
	}
	// Larger inputs still go through structural validation.
	b[0] = 0
	if _, err := Parse(b); err == nil {
		t.Fatal("accepted malformed larger image")
	}
}
func FuzzParse(f *testing.F) {
	f.Add(fixture(false))
	f.Add(fixture(true))
	f.Add([]byte("MZ"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := Parse(b)
		if err == nil && (info == nil || len(info.Sections) > MaxSections) {
			t.Fatal("invalid success")
		}
	})
}

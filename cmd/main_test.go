package main

import (
	"bytes"
	"debug/pe"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOptions(t *testing.T) {
	defaults, err := parseOptions(nil, io.Discard)
	if err != nil || defaults.path != "testdata/test.exe" || defaults.maxFileSize != 256<<20 {
		t.Fatalf("defaults: %+v, %v", defaults, err)
	}
	custom, err := parseOptions([]string{"-max-file-size-mib", "512", "sample.exe"}, io.Discard)
	if err != nil || custom.path != "sample.exe" || custom.maxFileSize != 512<<20 {
		t.Fatalf("custom options: %+v, %v", custom, err)
	}
	for _, args := range [][]string{
		{"-max-file-size-mib", "0"},
		{"-max-file-size-mib", "-1"},
		{"-max-file-size-mib", "9223372036854775807"},
		{"-max-file-size-mib", "invalid"},
		{"one.exe", "two.exe"},
	} {
		if _, err := parseOptions(args, io.Discard); err == nil {
			t.Fatalf("accepted invalid options %q", args)
		}
	}
	if _, err := parseOptions([]string{"-h"}, io.Discard); err != flag.ErrHelp {
		t.Fatalf("help: %v", err)
	}
}

func TestLargerFileAndCLIBudget(t *testing.T) {
	// Statically parse the existing fixture with a padded overlay. Never emulate it.
	fixture, err := os.ReadFile("../testdata/test.exe")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "padded.exe")
	if err := os.WriteFile(path, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	const size = 17 << 20
	if err := os.Truncate(path, size); err != nil {
		t.Fatal(err)
	}
	image, raw, err := parsePE(path, size)
	if err != nil || image == nil || len(raw) != size {
		t.Fatalf("file at configured limit: image=%v, bytes=%d, err=%v", image != nil, len(raw), err)
	}
	if _, _, err := parsePE(path, size-1); err == nil || !strings.Contains(err.Error(), "-max-file-size-mib") {
		t.Fatalf("file above limit should explain the override: %v", err)
	}
	if _, _, err := parsePE(path, 0); err == nil {
		t.Fatal("accepted an invalid size limit")
	}
	if _, _, err := parsePE(t.TempDir(), size); err == nil {
		t.Fatal("accepted a directory")
	}
}

func TestPEProgressOutput(t *testing.T) {
	image := &ImageInfo{
		ImageBase: 0x140000000, EntryPointRVA: 0x1000,
		Sections: []*pe.Section{{SectionHeader: pe.SectionHeader{Name: ".text", VirtualAddress: 0x1000}}},
	}
	var output bytes.Buffer
	printPEInfo(&output, image)
	for _, expected := range []string{
		"[pe] Number of Sections in file 1\n",
		"[pe] Image Base: 0x140000000\n",
		"[pe] Entry point of PE: 0x1000\n",
		"[pe] Section name:.text    - va:0x1000\n",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing diagnostic %q in %q", expected, output.String())
		}
	}
}

package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type MemRegion struct {
	Base  uint64
	Size  uint64
	Perms uint32
	Label string // "code", "stack", "heap" - useful for TUI display later
}

type ImportStub struct {
	Name    string
	Address uint64
}

type ImportTable struct {
	ByAddress map[uint64]string
	ByName    map[string]uint64
}

func main() {
	fmt.Println("Initializing the emulator...")

	uc, err := unicorn.NewUnicorn(unicorn.ARCH_X86, unicorn.MODE_64)
	if err != nil {
		log.Fatalf("Failed to initialize the emulator %v", err)
	}
	defer uc.Close()

	fmt.Println("Successfully initialized X86-64 emulator")

	// map memory
	regions, err := setupMem(uc)
	if err != nil {
		log.Fatalf("Failed to map memory regions: %v", err)
	}

	for _, r := range regions {
		fmt.Printf("[%s] base=0x%x size=0x%x perms=%d\n", r.Label, r.Base, r.Size, r.Perms)
	}

	f, err := parsePE("testdata/test.exe")
	if err != nil {
		log.Fatalf("Failed to parse PE file: %v", err)
	}
	defer f.Close()

	err = loadPESections(uc, f.Sections, 0x400000)
	if err != nil {
		log.Fatalf("Failed to load PE Sections: %v", err)
	}

	plaintext := []byte{0x41, 0x42, 0x43, 0x44}
	shellcode := []byte{0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x04, 0xFF, 0xD0, 0xF4}

	codeRegion := regions[0]
	stackRegion := regions[1]
	dataRegion := regions[2]
	importRegion := regions[3]

	importTable := buildImportTable(uc, importRegion.Base)

	for addr, api := range importTable.ByAddress {
		fmt.Printf("[import] addr=0x%x api=%s\n", addr, api)
	}

	encrypted := xorEncrypt(plaintext, 0xAA)
	if err = uc.MemWrite(dataRegion.Base, encrypted); err != nil {
		log.Fatalf("Failed to write encrypted payload: %v", err)
	}

	err = addInstrHook(uc, codeRegion)
	if err != nil {
		log.Fatalf("Failed to add Instruction Hook: %v", err)
	}

	err = addMemHook(uc)
	if err != nil {
		log.Fatalf("Failed to add Mem Hook: %v", err)
	}

	err = addInvalidMemHook(uc)
	if err != nil {
		log.Fatalf("Failed to add Invalid Memory Hook: %v", err)
	}

	err = addAPIHook(uc, importTable, importRegion)
	if err != nil {
		log.Fatalf("Failed to add API Hook: %v", err)
	}

	err = loadCode(uc, codeRegion, shellcode)
	if err != nil {
		log.Fatalf("Failed to load code into memory: %v", err)
	}

	err = executeCode(uc, codeRegion, stackRegion, len(shellcode))
	if err != nil {
		log.Fatalf("Failed to execute code: %v", err)
	}

	data, err := dumpMemory(uc, dataRegion.Base, uint64(len(plaintext)))
	if err != nil {
		log.Fatalf("Failed to decrypt payload from data region: %v", err)
	}

	// print data
	fmt.Printf("encrypted input: 	%x\n", encrypted)
	fmt.Printf("dumped output: 		%x\n", data)
	fmt.Printf("as string:			%s\n", data)

}

func setupMem(uc unicorn.Unicorn) ([]MemRegion, error) {
	memRegions := []MemRegion{
		{Base: 0x1000000, Size: 0x1000, Perms: unicorn.PROT_READ | unicorn.PROT_EXEC, Label: "code"},
		{Base: 0x2000000, Size: 0x1000, Perms: unicorn.PROT_READ | unicorn.PROT_WRITE, Label: "stack"},
		{Base: 0x3000000, Size: 0x1000, Perms: unicorn.PROT_READ | unicorn.PROT_WRITE, Label: "data"},
		{Base: 0x4000000, Size: 0x1000, Perms: unicorn.PROT_READ | unicorn.PROT_EXEC, Label: "imports"},
	}

	for _, r := range memRegions {
		if err := uc.MemMapProt(r.Base, r.Size, int(r.Perms)); err != nil {
			return nil, fmt.Errorf("failed to map %s region: %w", r.Label, err)
		}
	}

	fmt.Println("Successfully mapped memory regions")
	return memRegions, nil
}

func loadCode(uc unicorn.Unicorn, codeRegion MemRegion, shellcode []byte) error {
	if uint64(len(shellcode)) > codeRegion.Size {
		return fmt.Errorf("shellcode size %d exceeds region size %d", len(shellcode), codeRegion.Size)
	}

	// write bytes into code region
	err := uc.MemWrite(codeRegion.Base, shellcode)
	if err != nil {
		return fmt.Errorf("failed to write shellcode: %w", err)
	}

	fmt.Println("Successfully wrote shellcode to memory region")
	return nil
}

func executeCode(uc unicorn.Unicorn, code MemRegion, stack MemRegion, shellcodeLen int) error {
	if err := uc.RegWrite(unicorn.X86_REG_RSP, stack.Base+stack.Size); err != nil {
		return fmt.Errorf("failed to set RSP: %w", err)
	}

	if err := uc.Start(code.Base, code.Base+uint64(shellcodeLen)); err != nil {
		return err
	}

	return nil
}

func xorEncrypt(data []byte, key byte) []byte {
	out := make([]byte, len(data))

	for i, b := range data {
		out[i] = b ^ key
	}

	return out
}

func dumpMemory(uc unicorn.Unicorn, addr uint64, size uint64) ([]byte, error) {
	return uc.MemRead(addr, size)
}

func findRegion(regions []MemRegion, label string) (MemRegion, bool) {
	for _, r := range regions {
		if r.Label == label {
			return r, true
		}
	}

	return MemRegion{}, false
}

func buildImportTable(uc unicorn.Unicorn, base uint64) ImportTable {
	// LoadLibraryW, URLDownloadToFileW ?
	apiNames := []string{"VirtualAlloc", "VirtualProtect", "LoadLibraryA", "GetProcAddress"}
	importTable := ImportTable{
		ByAddress: make(map[uint64]string),
		ByName:    make(map[string]uint64),
	}

	for i, api := range apiNames {
		addr := base + (uint64(i) * 8)
		err := uc.MemWrite(addr, []byte{0xC3})
		if err != nil {
			fmt.Printf("Failed to write RET stub to addr: 0x%x - %v\n", addr, err)
		}

		importTable.ByAddress[addr] = api
		importTable.ByName[api] = addr

	}

	return importTable
}

// ------------ HOOKS ----------------- //

func addInstrHook(uc unicorn.Unicorn, codeRegion MemRegion) error {
	_, err := uc.HookAdd(unicorn.HOOK_CODE, func(uc unicorn.Unicorn, addr uint64, size uint32) {
		fmt.Printf("[trace] 0x%x (%d bytes)\n", addr, size)
	}, codeRegion.Base, codeRegion.Base+codeRegion.Size)

	return err
}

func addMemHook(uc unicorn.Unicorn) error {
	_, err := uc.HookAdd(unicorn.HOOK_MEM_READ|unicorn.HOOK_MEM_WRITE, func(uc unicorn.Unicorn, access int, addr uint64, size int, value int64) {
		if access == unicorn.MEM_WRITE {
			fmt.Printf("[mem write] 0x%x (%d bytes) val=0x%x\n", addr, size, value)
		} else {
			fmt.Printf("[mem read] 0x%x (%d bytes)\n", addr, size)
		}
	}, 1, 0)

	return err
}

func addInvalidMemHook(uc unicorn.Unicorn) error {
	_, err := uc.HookAdd(unicorn.HOOK_MEM_UNMAPPED, func(uc unicorn.Unicorn, access int, addr uint64, size int, value int64) {
		accessType := "unknown"
		switch access {
		case unicorn.MEM_READ_UNMAPPED:
			accessType = "read"
		case unicorn.MEM_WRITE_UNMAPPED:
			accessType = "write"
		case unicorn.MEM_FETCH_UNMAPPED:
			accessType = "fetch"
		}
		rax, _ := uc.RegRead(unicorn.X86_REG_RAX)
		rsp, _ := uc.RegRead(unicorn.X86_REG_RSP)
		rip, _ := uc.RegRead(unicorn.X86_REG_RIP)
		fmt.Printf("[mem invalid] type=%s addr=0x%x size=%d\n", accessType, addr, size)
		fmt.Printf("[registers] RAX=0x%x RSP=0x%x RIP=0x%x", rax, rsp, rip)
	}, 1, 0)

	return err
}

func addAPIHook(uc unicorn.Unicorn, importTable ImportTable, importRegion MemRegion) error {
	_, err := uc.HookAdd(unicorn.HOOK_CODE, func(uc unicorn.Unicorn, addr uint64, size uint32) {
		api, ok := importTable.ByAddress[addr]
		if !ok {
			return
		}

		// write a fake return val to RAX
		if err := uc.RegWrite(unicorn.X86_REG_RAX, 0x1); err != nil {
			fmt.Printf("failed to write fake return val to RAX register: %v", err)
		}

		// simulate RET manually
		rsp, _ := uc.RegRead(unicorn.X86_REG_RSP) // rsp holds an address not data
		b, err := uc.MemRead(rsp, 8)              // read the memory at the address returned from rsp, this is our return addr
		if err != nil {
			fmt.Printf("Failed to read from RSP register: %v", err)
		}

		retAddr := binary.LittleEndian.Uint64(b)
		err = uc.RegWrite(unicorn.X86_REG_RIP, retAddr) // resume execution at this addr after CALL
		if err != nil {
			fmt.Printf("failed to write return addr to RIP register")
		}

		fmt.Printf("[api] Intercepted api: %s addr=0x%x ret=0x%x RAX=0x1\n", api, addr, retAddr)

		err = uc.RegWrite(unicorn.X86_REG_RSP, rsp+8) // increment SP
		if err != nil {
			fmt.Printf("failed to advance RSP: %v", err)
		}

	}, importRegion.Base, importRegion.Base+importRegion.Size)

	return err
}

// ------------- PE File ---------------- //
func parsePE(path string) (*pe.File, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open PE file: %w\n", err)
	}

	fmt.Printf("[pe] Number of Sections in file %d\n", f.FileHeader.NumberOfSections)
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, fmt.Errorf("not a 64-bit PE")
	}

	fmt.Printf("[pe] Image Base: 0x%x\n", oh.ImageBase)
	fmt.Printf("[pe] Entry point of PE: 0x%x\n", oh.AddressOfEntryPoint)

	for _, section := range f.Sections {
		fmt.Printf("[pe] Section name:%-8s - va:0x%x\n", section.Name, section.VirtualAddress)
	}

	return f, nil
}

func loadPESections(uc unicorn.Unicorn, sections []*pe.Section, imageBase uint64) error {
	permsBySection := map[string]int{
		".text":  unicorn.PROT_READ | unicorn.PROT_EXEC,
		".data":  unicorn.PROT_READ | unicorn.PROT_WRITE,
		".rdata": unicorn.PROT_READ,
		".idata": unicorn.PROT_READ | unicorn.PROT_WRITE,
	}

	for _, section := range sections {
		perms, ok := permsBySection[section.Name]
		if !ok {
			fmt.Printf("[pe] Skipping section %-8s\n", section.Name)
			continue // skip sections we dont care about
		}

		alignedSize := (uint64(section.VirtualSize) + 0xFFF) & ^uint64(0xFFF)
		mapMemAddr := imageBase + uint64(section.VirtualAddress)

		if err := uc.MemMapProt(mapMemAddr, alignedSize, perms); err != nil {
			return fmt.Errorf("failed to map section %s at 0x%x: %w", section.Name, mapMemAddr, err)
		}

		data, err := section.Data()
		if err != nil {
			return fmt.Errorf("failed to read section %s data: %w", section.Name, err)
		}

		if err := uc.MemWrite(mapMemAddr, data); err != nil {
			return fmt.Errorf("failed to write section %s to memory: %w", section.Name, err)
		}

		fmt.Printf("[pe] Loaded %-8s addr=0x%x size=0x%x (aligned=0x%x) perms=0x%x\n", section.Name, mapMemAddr, section.VirtualSize, alignedSize, perms)
	}

	return nil
}

func patchIAT(uc unicorn.Unicorn, f *pe.File, imageBase uint64, importTable ImportTable) error {
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return fmt.Errorf("not a 64-bit PE")
	}

	var dll struct {
		OriginalFirstThunk uint32 // ptr to the INT
		TimeDataStamp      uint32
		ForwarderChain     uint32
		Name               uint32
		FirstThunk         uint32 // ptr to IAT
	}

	importDirectory := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	importsAddr := uint64(importDirectory.VirtualAddress) + imageBase // this is the rva where all the imports are in the PE file

	for {
		dllBytes, err := uc.MemRead(uint64(importsAddr), 20)
		if err != nil {
			return fmt.Errorf("failed to read import dll: %w", err)
		}

		binary.Read(bytes.NewReader(dllBytes), binary.LittleEndian, &dll)

		if dll.OriginalFirstThunk == 0 && dll.FirstThunk == 0 {
			break
		}

		nameBuf, _ := uc.MemRead(imageBase+uint64(dll.Name), 64)
		if nullIdx := bytes.IndexByte(nameBuf, 0); nullIdx != -1 {
			fmt.Printf("DLL Name: %s", string(nameBuf[:nullIdx]))
		}

		// inner loop goes here
		for {
			break
		}

		importsAddr += 20

	}

	return nil
}

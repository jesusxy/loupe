package main

import (
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

	plaintext := []byte{0x41, 0x42, 0x43, 0x44}
	shellcode := []byte{0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x03, 0x48, 0xC7, 0xC1, 0x04, 0x00, 0x00, 0x00, 0x80, 0x36, 0xAA, 0x48, 0xFF, 0xC6, 0xE2, 0xF8, 0xF4}

	codeRegion := regions[0]
	stackRegion := regions[1]
	dataRegion := regions[2]

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
	var memRegions []MemRegion

	// code { baseAddr: 0x1000000, size: 0x1000, perms: READ+EXEC}
	// map code region
	codeRegion := &MemRegion{
		Base:  0x1000000,
		Size:  0x1000,
		Perms: unicorn.PROT_READ | unicorn.PROT_EXEC,
		Label: "code",
	}
	err := uc.MemMapProt(codeRegion.Base, codeRegion.Size, int(codeRegion.Perms))
	if err != nil {
		return nil, fmt.Errorf("failed to map code region: %w", err)
	}

	memRegions = append(memRegions, *codeRegion)

	stackRegion := &MemRegion{
		Base:  0x2000000,
		Size:  0x1000,
		Perms: unicorn.PROT_READ | unicorn.PROT_WRITE,
		Label: "stack",
	}

	// stack { baseAddr: 0x2000000, size: 0x1000, perms: READ+WRITE}
	// map stack
	err = uc.MemMapProt(stackRegion.Base, stackRegion.Size, int(stackRegion.Perms))
	if err != nil {
		return nil, fmt.Errorf("failed to map code region: %w", err)
	}

	memRegions = append(memRegions, *stackRegion)

	dataRegion := &MemRegion{
		Base:  0x3000000,
		Size:  0x1000,
		Perms: unicorn.PROT_READ | unicorn.PROT_WRITE,
		Label: "data",
	}

	err = uc.MemMapProt(dataRegion.Base, dataRegion.Size, int(dataRegion.Perms))
	if err != nil {
		return nil, fmt.Errorf("failed to map code region: %w", err)
	}

	memRegions = append(memRegions, *dataRegion)

	// call the import table func
	importTableRegion := &MemRegion{
		Base:  0x4000000,
		Size:  0x1000,
		Perms: unicorn.PROT_READ | unicorn.PROT_EXEC,
		Label: "importTable",
	}

	err = uc.MemMapProt(importTableRegion.Base, importTableRegion.Size, int(importTableRegion.Perms))
	if err != nil {
		return nil, fmt.Errorf("failed to map import table region: %w", err)
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

func buildImportTable(base uint64) ImportTable {
	apiNames := []string{"VirtualAlloc", "VirtualProtect", "LoadLibraryA", "GetProcAddress"}
	importTable := ImportTable{
		ByAddress: make(map[uint64]string),
		ByName:    make(map[string]uint64),
	}

	for i, api := range apiNames {
		addr := base + (uint64(i) * 8)
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
		fmt.Printf("[mem invalid] type=%s addr=0x%x size=%d\n", accessType, addr, size)
	}, 1, 0)

	return err
}

package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const (
	optionalHeaderMagicPE32     uint16 = 0x10b
	optionalHeaderMagicPE32Plus uint16 = 0x20b
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

func main() {
	fmt.Println("Initializing the emulator...")

	// parse PE BEFORE creating unicorn
	imageInfo, raw, err := parsePE("testdata/test.exe")
	if err != nil {
		log.Fatalf("Failed to parse PE file: %v", err)
	}

	var mode int

	switch imageInfo.Arch {
	case pe.IMAGE_FILE_MACHINE_I386:
		mode = unicorn.MODE_32
	case pe.IMAGE_FILE_MACHINE_AMD64:
		mode = unicorn.MODE_64
	default:
		log.Fatalf("Unsupported PE machine: 0x%x", imageInfo.Arch)
	}

	uc, err := unicorn.NewUnicorn(unicorn.ARCH_X86, mode)
	if err != nil {
		log.Fatalf("Failed to initialize the emulator %v", err)
	}
	defer uc.Close()

	fmt.Println("Successfully initialized emulator")

	// map memory
	regions, err := setupMem(uc)
	if err != nil {
		log.Fatalf("Failed to map memory regions: %v", err)
	}

	for _, r := range regions {
		fmt.Printf("[%s] base=0x%x size=0x%x perms=%d\n", r.Label, r.Base, r.Size, r.Perms)
	}

	err = loadPESections(uc, raw, imageInfo)
	if err != nil {
		log.Fatalf("Failed to load PE Sections: %v", err)
	}

	stackRegion := regions[1]
	importRegion := regions[3]

	importTable, err := patchIAT(uc, imageInfo)
	if err != nil {
		log.Fatalf("Failed to patchIAT: %v", err)
	}

	for addr, api := range importTable.ByAddress {
		fmt.Printf("[import] addr=0x%x api=%s\n", addr, api)
	}

	err = setupTEB(uc, imageInfo)
	if err != nil {
		log.Fatalf("Failed to setup TEB: %v", err)
	}

	err = addInstrHook(uc)
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

	err = executeCode(uc, stackRegion, imageInfo)
	if err != nil {
		log.Fatalf("Failed to execute code: %v", err)
	}
}

func setupMem(uc unicorn.Unicorn) ([]MemRegion, error) {
	memRegions := []MemRegion{
		{Base: 0x1000000, Size: 0x1000, Perms: unicorn.PROT_READ | unicorn.PROT_EXEC, Label: "code"},
		{Base: 0x2000000, Size: 0x100000, Perms: unicorn.PROT_READ | unicorn.PROT_WRITE, Label: "stack"},
		{Base: 0x3000000, Size: 0x1000, Perms: unicorn.PROT_READ | unicorn.PROT_WRITE, Label: "data"},
		{Base: 0x4000000, Size: 0x1000, Perms: unicorn.PROT_READ | unicorn.PROT_EXEC, Label: "imports"},
		{Base: 0x7000000, Size: 0x1000, Perms: unicorn.PROT_READ | unicorn.PROT_WRITE, Label: "scratch"},
	}

	for _, r := range memRegions {
		if err := uc.MemMapProt(r.Base, r.Size, int(r.Perms)); err != nil {
			return nil, fmt.Errorf("failed to map %s region: %w", r.Label, err)
		}
	}

	argcData := make([]byte, 4)
	binary.LittleEndian.PutUint32(argcData, 1)
	if err := uc.MemWrite(0x7000040, argcData); err != nil {
		return nil, fmt.Errorf("failed to write argc data: %w", err)
	}

	argvPtr := make([]byte, 8)
	binary.LittleEndian.PutUint64(argvPtr, 0x7000060)
	if err := uc.MemWrite(0x7000050, argvPtr); err != nil {
		return nil, fmt.Errorf("failed to write argv data: %w", err)
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

func executeCode(uc unicorn.Unicorn, stack MemRegion, imageInfo *ImageInfo) error {
	var sentinel uint64
	var sentinelBytes []byte
	var stackRegister int
	var stackPointer uint64

	switch imageInfo.Arch {
	case pe.IMAGE_FILE_MACHINE_I386:
		sentinel = 0xDEAD0000
		stackPointer = stack.Base + stack.Size - 4
		sentinelBytes = make([]byte, 4)
		binary.LittleEndian.PutUint32(sentinelBytes, uint32(sentinel))
		stackRegister = unicorn.X86_REG_ESP
	case pe.IMAGE_FILE_MACHINE_AMD64:
		sentinel = 0xDEAD000000000000
		stackPointer = stack.Base + stack.Size - 8
		sentinelBytes = make([]byte, 8)
		binary.LittleEndian.PutUint64(sentinelBytes, sentinel)
		stackRegister = unicorn.X86_REG_RSP
	default:
		return fmt.Errorf("unsupported architecture")
	}

	if err := uc.MemWrite(stackPointer, sentinelBytes); err != nil {
		return fmt.Errorf("failed to write sentinel return address: %w", err)
	}

	if err := uc.RegWrite(stackRegister, stackPointer); err != nil {
		return fmt.Errorf("failed to set stack pointer: %w", err)
	}
	entrypoint := imageInfo.EntryPointVA
	if err := uc.Start(entrypoint, sentinel); err != nil {
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

func makeStubAllocator(base uint64) func() uint64 {
	next := base

	return func() uint64 {
		addr := next
		next += 8
		return addr
	}
}

// ------------ HOOKS ----------------- //

func addInstrHook(uc unicorn.Unicorn) error {
	_, err := uc.HookAdd(unicorn.HOOK_CODE, func(uc unicorn.Unicorn, addr uint64, size uint32) {
		fmt.Printf("[trace] 0x%x (%d bytes)\n", addr, size)
	}, 0, ^uint64(0))

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
	_, err := uc.HookAdd(unicorn.HOOK_MEM_UNMAPPED, func(uc unicorn.Unicorn, access int, addr uint64, size int, value int64) bool {
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
		fmt.Printf("[registers] RAX=0x%x RSP=0x%x RIP=0x%x\n", rax, rsp, rip)

		return false
	}, 1, 0)

	return err
}

func addAPIHook(uc unicorn.Unicorn, importTable ImportTable, importRegion MemRegion) error {
	returnVals := map[string]uint64{
		"__p__fmode":      0x7000000,
		"__p__commode":    0x7000008,
		"__p__environ":    0x7000010,
		"__acrt_iob_func": 0x7000018,
		"VirtualAlloc":    0x7000020,
		"malloc":          0x7000028,
		"calloc":          0x7000030,
		"__p___argc":      0x7000040,
		"__p___argv":      0x7000050,
	}

	_, err := uc.HookAdd(unicorn.HOOK_CODE, func(uc unicorn.Unicorn, addr uint64, size uint32) {
		api, ok := importTable.ByAddress[addr]
		if !ok {
			return
		}

		retVal, ok := returnVals[api]
		if !ok {
			retVal = 0x0
		}
		// write a fake return val to RAX
		if err := uc.RegWrite(unicorn.X86_REG_RAX, retVal); err != nil {
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

		fmt.Printf("[api] Intercepted api: %s addr=0x%x ret=0x%x RAX=0x%x\n", api, addr, retAddr, retVal)

		if api == "exit" || api == "abort" || api == "_exit" {
			fmt.Println("[unicorn] Program called exit. Stopping simulation...")
			uc.Stop()
			return
		}

		err = uc.RegWrite(unicorn.X86_REG_RSP, rsp+8) // increment SP
		if err != nil {
			fmt.Printf("failed to advance RSP: %v", err)
		}

	}, importRegion.Base, importRegion.Base+importRegion.Size)

	return err
}

// ------------- PE File ---------------- //
func parsePE(path string) (*ImageInfo, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read PE file: %w", err)
	}

	f, err := pe.NewFile(bytes.NewReader(raw))

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse PE file: %w\n", err)
	}

	imageInfo := ImageInfo{}

	fmt.Printf("[pe] Number of Sections in file %d\n", f.FileHeader.NumberOfSections)

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
		fmt.Printf("[pe] Image Base: 0x%x\n", imageInfo.ImageBase)
		fmt.Printf("[pe] Entry point of PE: 0x%x\n", imageInfo.EntryPointRVA)
	case *pe.OptionalHeader64:
		imageInfo.ImageBase = uint64(oh.ImageBase)
		imageInfo.EntryPointRVA = oh.AddressOfEntryPoint
		imageInfo.Magic = oh.Magic
		imageInfo.ImportDataDirectory = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		imageInfo.SizeOfImage = oh.SizeOfImage
		imageInfo.SizeOfHeaders = oh.SizeOfHeaders
		imageInfo.SectionAlignment = oh.SectionAlignment
		fmt.Printf("[pe] Image Base: 0x%x\n", imageInfo.ImageBase)
		fmt.Printf("[pe] Entry point of PE: 0x%x\n", imageInfo.EntryPointRVA)
	default:
		return nil, nil, fmt.Errorf("unsupported optional header type %T", f.OptionalHeader)
	}

	valid32 := imageInfo.Arch == pe.IMAGE_FILE_MACHINE_I386 &&
		imageInfo.Magic == optionalHeaderMagicPE32
	valid64 := imageInfo.Arch == pe.IMAGE_FILE_MACHINE_AMD64 &&
		imageInfo.Magic == optionalHeaderMagicPE32Plus

	if !valid32 && !valid64 {
		return nil, nil, fmt.Errorf(
			"unsupported or inconsistent PE architecture: machine 0x%x magic=0x%x",
			imageInfo.Arch,
			imageInfo.Magic,
		)
	}

	imageInfo.EntryPointVA = imageInfo.ImageBase + uint64(imageInfo.EntryPointRVA)

	for _, section := range imageInfo.Sections {
		fmt.Printf("[pe] Section name:%-8s - va:0x%x\n", section.Name, section.VirtualAddress)
	}

	return &imageInfo, raw, nil
}

func loadPESections(uc unicorn.Unicorn, raw []byte, imageInfo *ImageInfo) error {
	if uint64(imageInfo.SizeOfHeaders) > uint64(len(raw)) {
		return fmt.Errorf(
			"PE header size 0x%x exceeds file size 0x%x",
			imageInfo.SizeOfHeaders,
			len(raw),
		)
	}

	headerBuf := raw[:imageInfo.SizeOfHeaders]
	pageSize := uint64(0x1000)
	size := uint64(imageInfo.SizeOfHeaders)
	alignedSize := (size + pageSize - 1) & ^(pageSize - 1)

	if err := uc.MemMapProt(imageInfo.ImageBase, alignedSize, unicorn.PROT_READ); err != nil {
		return fmt.Errorf("failed to mape PE header region: %w", err)
	}

	if err := uc.MemWrite(imageInfo.ImageBase, headerBuf); err != nil {
		return fmt.Errorf("failed to write PE headers to memory: %w", err)
	}

	fmt.Printf("[pe] Loaded headers addr=0x%x size=0x%x\n", imageInfo.ImageBase, alignedSize)

	permsBySection := map[string]int{
		".text":  unicorn.PROT_READ | unicorn.PROT_EXEC,
		".data":  unicorn.PROT_READ | unicorn.PROT_WRITE,
		".rdata": unicorn.PROT_READ,
		".idata": unicorn.PROT_READ | unicorn.PROT_WRITE,
		".bss":   unicorn.PROT_READ | unicorn.PROT_WRITE,
	}

	for _, section := range imageInfo.Sections {
		perms, ok := permsBySection[section.Name]
		if !ok {
			fmt.Printf("[pe] Skipping section %-8s\n", section.Name)
			continue // skip sections we dont care about
		}

		alignedSize := (uint64(section.VirtualSize) + 0xFFF) & ^uint64(0xFFF)
		mapMemAddr := imageInfo.ImageBase + uint64(section.VirtualAddress)

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

func patchIAT(uc unicorn.Unicorn, imageInfo *ImageInfo) (ImportTable, error) {
	importTable := ImportTable{
		ByAddress: make(map[uint64]string),
		ByName:    make(map[string]uint64),
	}

	importDirectory := imageInfo.ImportDataDirectory
	if importDirectory.VirtualAddress == 0 {
		return importTable, nil
	}

	var importEntrySize uint64
	var ordinalMask uint64
	var decodeImportEntry func([]byte) uint64
	var encodeImportAddress func(uint64) ([]byte, error)

	switch imageInfo.Arch {
	case pe.IMAGE_FILE_MACHINE_I386:
		importEntrySize = 4
		ordinalMask = 0x80000000
		decodeImportEntry = func(data []byte) uint64 {
			return uint64(binary.LittleEndian.Uint32(data))
		}
		encodeImportAddress = func(address uint64) ([]byte, error) {
			if address > uint64(^uint32(0)) {
				return nil, fmt.Errorf("import stub address 0x%x exceeds 32-bit address space", address)
			}

			data := make([]byte, importEntrySize)
			binary.LittleEndian.PutUint32(data, uint32(address))
			return data, nil
		}
	case pe.IMAGE_FILE_MACHINE_AMD64:
		importEntrySize = 8
		ordinalMask = 0x8000000000000000
		decodeImportEntry = func(data []byte) uint64 {
			return binary.LittleEndian.Uint64(data)
		}
		encodeImportAddress = func(address uint64) ([]byte, error) {
			data := make([]byte, importEntrySize)
			binary.LittleEndian.PutUint64(data, address)
			return data, nil
		}
	default:
		return ImportTable{}, fmt.Errorf("unsupported architecture for IAT patching: 0x%x", imageInfo.Arch)
	}

	alloc := makeStubAllocator(0x4000000)

	var dllDescriptor struct {
		OriginalFirstThunk uint32
		TimeDateStamp      uint32
		ForwarderChain     uint32
		NameRVA            uint32
		FirstThunk         uint32
	}

	const importDescriptorSize uint64 = 20
	dllDescriptorAddress := imageInfo.ImageBase + uint64(importDirectory.VirtualAddress)

	for {
		dllDescriptorBytes, err := uc.MemRead(dllDescriptorAddress, importDescriptorSize)
		if err != nil {
			return ImportTable{}, fmt.Errorf("failed to read DLL import descriptor at 0x%x: %w", dllDescriptorAddress, err)
		}

		err = binary.Read(bytes.NewReader(dllDescriptorBytes), binary.LittleEndian, &dllDescriptor)
		if err != nil {
			return ImportTable{}, fmt.Errorf("failed to decode DLL import descriptor at 0x%x: %w", dllDescriptorAddress, err)
		}

		if dllDescriptor.OriginalFirstThunk == 0 && dllDescriptor.FirstThunk == 0 {
			break
		}

		nameBuf, err := uc.MemRead(imageInfo.ImageBase+uint64(dllDescriptor.NameRVA), 64)
		if err != nil {
			return ImportTable{}, fmt.Errorf("[pe:dll] failed to read DLL name at RVA 0x%x: %w", dllDescriptor.NameRVA, err)
		}

		if nullIdx := bytes.IndexByte(nameBuf, 0); nullIdx != -1 {
			fmt.Printf("[pe:dll] %s\n", string(nameBuf[:nullIdx]))
		}

		lookupTableRVA := dllDescriptor.OriginalFirstThunk
		if lookupTableRVA == 0 {
			lookupTableRVA = dllDescriptor.FirstThunk
		}

		lookupTableBase := imageInfo.ImageBase + uint64(lookupTableRVA)
		iatBase := imageInfo.ImageBase + uint64(dllDescriptor.FirstThunk)

		for i := 0; ; i++ {
			entryOffset := uint64(i) * importEntrySize
			entryAddress := lookupTableBase + entryOffset
			entryBytes, err := uc.MemRead(entryAddress, importEntrySize)
			if err != nil {
				return ImportTable{}, fmt.Errorf("failed to read import lookup entry at 0x%x: %w", entryAddress, err)
			}

			lookupEntry := decodeImportEntry(entryBytes)

			if lookupEntry == 0 {
				break
			}

			if lookupEntry&ordinalMask != 0 {
				fmt.Printf("[pe:dll:fn] ordinal=0x%x (skipped)\n", lookupEntry&0xFFFF)
				continue
			}

			functionNameAddress := imageInfo.ImageBase + lookupEntry + 2
			functionNameBytes, err := uc.MemRead(functionNameAddress, 64)
			if err != nil {
				return ImportTable{}, fmt.Errorf("failed to read import function name at 0x%x: %w", functionNameAddress, err)
			}

			if nullIdx := bytes.IndexByte(functionNameBytes, 0); nullIdx != -1 {
				functionName := string(functionNameBytes[:nullIdx])
				fmt.Printf("[pe:dll:fn] %s\n", functionName)

				stubAddr := alloc()

				if err := uc.MemWrite(stubAddr, []byte{0xC3}); err != nil {
					return ImportTable{}, fmt.Errorf("failed to write RET to stub address 0x%x: %w", stubAddr, err)
				}

				importTable.ByName[functionName] = stubAddr
				importTable.ByAddress[stubAddr] = functionName

				encodedStubAddress, err := encodeImportAddress(stubAddr)
				if err != nil {
					return ImportTable{}, fmt.Errorf("failed to encode IAT entry for %s: %w", functionName, err)
				}

				iatEntryAddress := iatBase + entryOffset
				if err := uc.MemWrite(iatEntryAddress, encodedStubAddress); err != nil {
					return ImportTable{}, fmt.Errorf("failed to write IAT entry for %s at 0x%x: %w", functionName, iatEntryAddress, err)
				}

				fmt.Printf("[iatpatch] %s=0x%x\n", functionName, stubAddr)
			}
		}

		dllDescriptorAddress += importDescriptorSize
	}

	return importTable, nil
}

func setupTEB(uc unicorn.Unicorn, imageInfo *ImageInfo) error {
	memRegions := []MemRegion{
		{Base: 0x5000000, Size: 0x10000, Perms: unicorn.PROT_READ | unicorn.PROT_WRITE, Label: "teb"},
		{Base: 0x6000000, Size: 0x10000, Perms: unicorn.PROT_READ | unicorn.PROT_WRITE, Label: "peb"},
	}

	for _, r := range memRegions {
		if err := uc.MemMapProt(r.Base, r.Size, int(r.Perms)); err != nil {
			return fmt.Errorf("failed to map %s region: %w", r.Label, err)
		}
	}

	teb := memRegions[0]
	peb := memRegions[1]

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, peb.Base)

	err := uc.MemWrite(teb.Base+0x30, buf)
	if err != nil {
		return fmt.Errorf("failed to write peb addr into teb: %w", err)
	}

	binary.LittleEndian.PutUint64(buf, imageInfo.ImageBase)
	err = uc.MemWrite(peb.Base+0x10, buf)
	if err != nil {
		return fmt.Errorf("failed to write image base into peb: %w", err)
	}

	osVersionBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(osVersionBuf, 0x0A)
	err = uc.MemWrite(peb.Base+0xBC, osVersionBuf)
	if err != nil {
		return fmt.Errorf("failed to write Windows version into peb: %w", err)
	}

	binary.LittleEndian.PutUint64(buf, 0x3000000)
	err = uc.MemWrite(peb.Base+0x30, buf)
	if err != nil {
		return fmt.Errorf("failed to write fake heap into peb: %w", err)
	}

	err = uc.RegWrite(unicorn.X86_REG_GS_BASE, teb.Base)
	if err != nil {
		return fmt.Errorf("failed to point GS base at teb: %w", err)
	}

	return nil
}

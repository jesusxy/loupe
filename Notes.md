## Loupe

When executing the code in the emulator we have to set the `SP (stack pointer)` to `Stack.Base + Stack.Size`.
This would be our total allocated SPACE for the stack

The Stack.Size address will be at the top. In 0x86 Arch, the stack grows down. So each `PUSH` would decrease the `ADDRESS`

The Address grows DOWN into the allocated / mapped region

---

The `Code` region holds the _unpacking routine_ - the decryption logic itself. \
The `Data` region holds the _ENCRYPTED_ payload - the thing to be decrypted.

```
malware.exe
├── unpacking routine  ← runs first, this is what lives in the code region
└── encrypted blob     ← the real payload, sits in data region encrypted at rest
```

The unpacking routine's only job is to decrypt the blob and then jump into it.

Unpacking Assembly code:

```asm

mov rsi, 0x3000000
mov rcx, 4
myloop:
xor byte ptr [rsi], 0xAA
inc rsi
loop myloop
hlt

```

---

### Terminal Output

```
[stack] base=0x2000000 size=0x1000 perms=3
[data] base=0x3000000 size=0x1000 perms=3
Successfully wrote shellcode to memory region
[trace] 0x1000000 (7 bytes)
[trace] 0x1000007 (7 bytes)
[trace] 0x100000e (3 bytes)
[mem read] 0x3000000 (1 bytes)
[mem write] 0x3000000 (1 bytes) val=0x41
[trace] 0x1000011 (3 bytes)
[trace] 0x1000014 (2 bytes)
[trace] 0x100000e (3 bytes)
[mem read] 0x3000001 (1 bytes)
[mem write] 0x3000001 (1 bytes) val=0x42
[trace] 0x1000011 (3 bytes)
[trace] 0x1000014 (2 bytes)
[trace] 0x100000e (3 bytes)
[mem read] 0x3000002 (1 bytes)
[mem write] 0x3000002 (1 bytes) val=0x43
[trace] 0x1000011 (3 bytes)
[trace] 0x1000014 (2 bytes)
[trace] 0x100000e (3 bytes)
[mem read] 0x3000003 (1 bytes)
[mem write] 0x3000003 (1 bytes) val=0x44
[trace] 0x1000011 (3 bytes)
[trace] 0x1000014 (2 bytes)
[trace] 0x1000016 (1 bytes)
encrypted input:        ebe8e9ee
dumped output:          41424344
as string:                      ABCD
Emulator closed cleanly
```

---

How does the emulator even know execution has reached VirtualAlloc? What hook catches a CALL to a specific address, and what do you have to do after handling it to keep execution from dying?

Think about what happens to the instruction pointer and the stack when a CALL executes — what does the CPU do mechanically, and what does your hook need to undo or advance to keep things moving?

When `CALL 0x5000010` executes the CPU does exactly two things:

`PUSHes` the return address onto the stack — the address of the instruction right after the `CALL`, so execution knows where to come back to
Moves `RIP` to `0x5000010` — the target address

No explicit `JMP` needed — CA`LL does both atomically.

Now in our sandbox, `RIP` lands at `0x5000010`. There's no real function there. Our hook fires. We fake the return value by writing to `RAX`.
But here's the part you're missing — how do we return from the fake function?
In a real function, `RET` would:

`POP` the return address off the stack
Jump back to it

But we have no real `RET` instruction to execute. So our hook has to manually simulate what `RET` does:

Read the return address off the stack — it's sitting at [RSP]
Set `RIP` to that address
Advance `RSP` by 8 — same as a `POP`

---

Inside the callback you need to:

Look up `addr` in `importTable.ByAddress` to get the API name
Log which API was intercepted
Write a fake return value into RAX via RegWrite
Simulate RET manually:

- Read 8 bytes from [RSP] with MemRead — that's the return address
- Convert those bytes to a uint64
- Write that value into RIP via RegWrite
- Advance RSP by 8 via RegWrite

```
0x400000 + 0x1000 → .text (code from the actual PE)
0x400000 + 0x3000 → .data
0x400000 + 0x4000 → .rdata
0x400000 + 0x8000 → .idata (import table we'll patch)
0x2000000 → stack (we keep this)
```

The formula is:

```
go(uint64(section.VirtualSize) + 0xFFF) & ^uint64(0xFFF)
```

Step 1 is adding 0xFFF. This bumps the value up so that anything not already page aligned crosses into the next page boundary. So 0x1500 plus 0xFFF gives you 0x249FF.

Step 2 is the AND with the NOT of 0xFFF. The NOT of 0xFFF flips all the bits, which zeroes out the bottom 12 bits when you AND with it. This rounds the value down to the nearest page boundary. So 0x249FF becomes 0x24000.

**IMAGE_IMPORT_DESCRIPTOR**

```
Offset  Size  Field
0x00    4     OriginalFirstThunk  — RVA to INT (Import Name Table)
0x04    4     TimeDateStamp
0x08    4     ForwarderChain
0x0C    4     Name               — RVA to DLL name string
0x10    4     FirstThunk         — RVA to IAT (Import Address Table)
```

---

### Reading bytes

Every time you hit this decision, ask yourself: `where does the data live?` \
`File bytes` → binary.Read. \
`Emulated memory` → uc.MemRead. \
Raw `byte slice you already have` → slice indexing or binary.LittleEndian.UintX.

- binary.Read — use when you're reading from a bytes.Reader or io.Reader and deserializing directly into a struct or typed value
- uc.MemRead — use when you're reading raw bytes from emulated memory. It returns []byte directly, no reader needed
- io.ReadFull — use when you have a reader and need to guarantee all N bytes are read, no short reads

---

Good question. Neither — it's a virtual address.
When Windows loads a PE, it maps it into the process's virtual address space. The ImageBase in the optional header is where the linker preferred to place it in virtual memory. For 64-bit Windows executables the default preferred base is 0x140000000.
So the timeline is:

On disk — the file has no meaningful base, just RVAs (relative offsets)
In virtual memory (real Windows) — the loader maps it at 0x140000000 if possible, applies relocations if not
In your emulator — you're the loader, and you chose 0x400000 as your virtual address space base instead

So oh.ImageBase is the preferred virtual address on a real Windows system. IMAGE_BASE is the virtual address in your emulated address space. Same concept, different value.

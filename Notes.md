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

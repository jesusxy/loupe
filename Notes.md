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

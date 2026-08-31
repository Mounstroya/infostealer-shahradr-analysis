# 03 — Dynamic unpacking (emulation)

Static analysis alone can't get past this stage: the binary decrypts its real payload in memory at runtime. A Python-based emulation environment was set up to run the unpacker stub without ever executing the malware on real hardware.

## Environment

- Python 3.13 in an isolated venv (`speakeasy-emulator`, `unicorn` 1.0.2, `capstone`, `pefile`, `lief`, `pycryptodome`).
- **Speakeasy** (built on the **Unicorn** engine) emulating `shahradr_clean.exe`, loaded with its original base address and entry point (`base=0x140000000`, entry point `0x1420`).
- No `sudo` or elevated access used at any point.

Setup details and the version-compatibility issues that had to be resolved: [`../tools-used.md`](../tools-used.md).

## Finding 2 — the real cipher is AES-256-CBC, not RC4

The initial report described a "stream cipher / RC4 with key rotation." Instrumenting the Windows CryptoAPI calls inside the emulator showed the binary actually uses the **real Windows crypto stack**:

```
CryptAcquireContextW(PROV_RSA_AES)
CryptImportKey(bType=8, alg=CALG_AES_256, keylen=32)
CryptSetKeyParam(KP_IV, ...)
CryptDecrypt(...)
```

Extracted directly from memory during emulation:

- **AES-256 key (32 bytes):** `cfcc13c0242c3d3cabaf192aee60adb06b3246547ab35444b0a5ee2ade97821`
- **IV (16 bytes):** `ea2f9b0cf0859c950c2cc2574780e05`

**Mathematical confirmation that the key/IV are correct:** decrypting the first ciphertext block with that key/IV yields a result that exactly equals the IV itself — a property of AES-CBC when the first plaintext block is all zeros. The odds of that happening by chance are ~1/2¹²⁸, so this isn't a coincidence: the extracted algorithm, key, and IV are correct.

## Observed unpacking flow

```mermaid
sequenceDiagram
    participant CRT as fcn.140001020 (CRT init)
    participant Core as fcn.140012470 (unpacker)
    participant Buf1 as RW buffer (0x8c0f0 bytes)
    participant CAPI as CryptoAPI (AES-256-CBC)
    participant Buf2 as RWX buffer (Thread Pool context)
    participant TP as Windows Thread Pool

    CRT->>Core: control transfer after CRT init
    Core->>Buf1: VirtualAlloc(RW) + copy key/IV/ciphertext from .rdata
    Core->>CAPI: CryptImportKey + CryptSetKeyParam(IV) + CryptDecrypt
    CAPI-->>Buf2: decrypted payload (573,600 bytes)
    Core->>TP: CreateThreadpoolWork(callback=0x1400123b0, context=Buf2)
    TP->>TP: SubmitThreadpoolWork / pool dispatch
    Note over TP: on the real binary, the callback executes the payload;<br/>emulation intercepted execution right before that jump
```

## Finding 3 — control transfer goes through the Windows Thread Pool

The initial report assumed a plain direct call (`call rax`). Disassembly plus the emulation trace show the binary actually uses **`CreateThreadpoolWork` + `SubmitThreadpoolWork`** — the callback (`0x1400123b0`) receives the pointer to the already-decrypted buffer as its `Context` argument. This is an extra layer of indirection specifically aimed at defeating naive dynamic analysis: a breakpoint on `call rax` never fires, because the real "call" happens inside a thread-pool worker callback instead.

Static disassembly confirmed that, past the junk-code block, `[rbp - 0x20]` ends up holding exactly that same `Context` pointer — so it was possible to dump the buffer directly at the moment `CreateThreadpoolWork` is invoked, without needing to let the emulator actually run the callback.

## Result of the dump

- **Buffer dumped:** 573,600 bytes (`0x8c0a0`) from the context pointer passed to `CreateThreadpoolWork`.
- **Does not start with `MZ`** (the classic PE header). It starts with `e8 58 bc 07 00...` — an x86-64 `call` instruction, i.e. **position-independent shellcode**, not a flat PE image.
- Contains a plaintext HTTP request template: `GET /what-is-my-ip HTTP/1.1` to `ipinfo.io`, with a Chrome User-Agent — an anti-sandbox / IP-geolocation check before proceeding further. See [`04-payload-analysis.md`](04-payload-analysis.md).

## What was left unresolved

Decompiling (Ghidra via `rz-ghidra`) the functions involved (`fcn.140012470`, `fcn.140012230`) confirmed part of the memory-allocation logic and a **conditional in-place byte-reversal loop** — but the exact instructions where the CryptoAPI calls themselves happen were **not pinned down** in static disassembly (they show up resolved in the dynamic emulation trace, but not as named symbols in this session's static disassembly).

## Byte-reversal lead — checked, ruled out

Because the binary itself was found to contain a byte-reversal routine, it was worth checking whether the *entire* unpacked buffer needed to be reversed to reveal a real PE. As an experiment, the whole 573,600-byte buffer was reversed byte-for-byte and searched for the `MZ` signature:

```bash
python3 -c "
data = open('payload_unpacked.exe','rb').read()
rev = data[::-1]
idx = rev.find(b'MZ')
print('MZ found at offset:', idx)
print(rev[idx:idx+64].hex())
"
```

This reliably finds `MZ` at **offset 23224**. But checking the DOS header's `e_lfanew` field (the 4 bytes at offset `+0x3c`, which should point forward to the real `PE\0\0` header) shows it resolves to an offset far past the end of the 573,600-byte buffer:

```bash
python3 -c "
import struct
data = open('payload_unpacked.exe','rb').read()
rev = data[::-1]
off = 23224
e_lfanew = struct.unpack_from('<I', rev, off + 0x3c)[0]
print('e_lfanew:', hex(e_lfanew), '-> implied PE header at', off + e_lfanew, 'of', len(rev), 'bytes')
"
# e_lfanew: 0x6e80000 -> implied PE header at 115890872 of 573600 bytes  (out of range)
```

**Conclusion: this is another coincidental byte match, not a real PE header** — the same pattern as the earlier, similarly-placed "MZ" match at offset ~23212 in the non-reversed buffer (see [`04-payload-analysis.md`](04-payload-analysis.md)), which was already known to be coincidental. Reversing the whole buffer is not the missing step.

The actual next step for anyone continuing this analysis is still the one described in [`04-payload-analysis.md`](04-payload-analysis.md#whats-needed-to-reach-the-actual-stealer-functions): locate where `fcn.140012470` patches the pointer at offset `0xD`, and let the mapper run one step further with that pointer already in place.

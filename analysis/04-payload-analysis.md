# 04 — Unpacked payload analysis

## What the dumped buffer is

The 573,600-byte buffer obtained in [`03-dynamic-unpacking.md`](03-dynamic-unpacking.md) (SHA-256 `d468dedbb8e105ca4320a2d103e39437ccfd4633ef19c0fab7660efacbc8c344`, sample available under [`../samples/`](../samples/)) is **not a classic PE**. It's a *manual PE-mapping stub*, a common technique to keep the final payload from ever existing on disk (or even in memory) as a normal, signature-scannable executable:

1. It's position-independent code: it uses the classic `call`/`pop` trick to self-locate in memory (find its own address without depending on where the OS loaded it).
2. Once it knows its own address, the stub is prepared to read `e_lfanew` (the DOS-header field at offset `0x3c` that points to the real NT header) **from a PE image referenced by a pointer**, not from itself.
3. That pointer — expected at offset `0xD` of the buffer — is normally written just before the mapper uses it, and in this dump it's still zero, because the interception happened one step before the packer finished that last patch.

In other words: **the loader stub itself is complete and intact**, but it's missing its "target" (the final PE image containing the actual stealer logic) because the dump was taken one step too early.

## Anti-analysis / anti-sandbox evidence

ASCII strings extracted from the buffer include:

```
GET /what-is-my-ip HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
```

This points to a request to `ipinfo.io/what-is-my-ip` — a typical **network fingerprinting / geolocation check** pattern before deciding whether to proceed with full execution (many InfoStealer families refuse to run, or limit their activity, if they detect known datacenter/sandbox IP ranges, or restrict activity to specific countries).

The rest of the extracted strings are mostly high-entropy noise (short, non-printable-adjacent fragments) — consistent with most of the buffer still being packed/obfuscated data waiting on the final patch described above, rather than readable code or strings yet.

## What's needed to reach the actual stealer functions

To decompile the real data-theft functions (browser credentials via DPAPI, SQLite3 cookie/password databases, browser profile paths) someone would need to:

1. Locate, inside `fcn.140012470` (or an unexplored sub-function), the exact point where the pointer at offset `0xD` of the buffer gets written, before the mapper consumes it.
2. Let the emulation run one step further past `CreateThreadpoolWork`, with that pointer already patched, so the mapper actually reconstructs the final PE image in memory.
3. Dump that reconstructed image (fixing up PE headers if needed) and decompile it with Ghidra/rizin.
4. Optionally verify the unresolved lead noted in [`03-dynamic-unpacking.md`](03-dynamic-unpacking.md#what-was-left-unresolved) — an incidental "MZ" match found when reversing the whole buffer's byte order, at offset `23224`, never checked for validity.

This was left as pending work — see [`../README.md`](../README.md#status--known-limitations) and [`../data-exfiltrated.md`](../data-exfiltrated.md).

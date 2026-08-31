# 02 — Static analysis

## The file

- **Name:** `shahradr.exe`
- **Original size:** 126,525,440 bytes (126.5 MB)
- **SHA-256 (original):** `07bb18a008faf81b1586e1d112f0e1a8dc94fc70253eb52e8586b54fb6cfe2d7`
- **Type:** PE32+ for Windows, x86-64, GUI subsystem, stripped (external PDB symbols)
- **Compiler:** GCC MinGW-w64 x86-64
- **Manifest name / version:** `phasebuilder.0cedd7`, version `346.4.1.98` (embedded assembly manifest — likely a build-system artifact, potentially useful for clustering other samples from the same builder)

## Section table (`objdump -h`)

```
Idx Name          Size      VMA                Flags
 0  .text         003c8320  0000000140001000   CODE, READONLY
 1  .data         000000a0  00000001403ca000   DATA
 2  .rdata        00000608  00000001403cb000   READONLY, DATA
 3  .eh_fram      00000004  00000001403cc000   DATA
 4  .pdata        00004080  00000001403cd000   READONLY, DATA
 5  .xdata        00003ac4  00000001403d2000   READONLY, DATA
 6  .bss          00000200  00000001403d6000   (uninitialized)
 7  .idata        00000a34  00000001403d7000   READONLY, DATA (imports)
 8  .tls          00000010  00000001403d8000   DATA
 9  .rsrc         0002c7b8  00000001403d9000   READONLY, DATA (resources)
10  .reloc        074ab800  0000000140406000   READONLY, DATA
```

`.reloc` is `0x074ab800` = **122,337,280 bytes (~116.7 MiB)** — over 96% of the entire file. This matches the "~122.5 MB of padding" figure from the initial incident report closely enough, but **the content of that padding is not `0x00`** (see finding below).

## Imports (`strings` on the binary)

Confirmed imports relevant to the unpacking mechanism (see [`03-dynamic-unpacking.md`](03-dynamic-unpacking.md)):

```
KERNEL32.dll: VirtualAlloc, VirtualFree, VirtualProtect, VirtualQuery,
              CreateThreadpoolWork, SubmitThreadpoolWork,
              WaitForThreadpoolWorkCallbacks, CloseThreadpoolWork,
              LoadLibraryA, GetProcAddress, GetModuleHandleA,
              InitializeCriticalSection, EnterCriticalSection,
              LeaveCriticalSection, DeleteCriticalSection, TlsGetValue,
              SetUnhandledExceptionFilter, MultiByteToWideChar, GetLastError

api-ms-win-crt-*.dll (environment, heap, locale, math, private, runtime,
                       stdio, string) — standard MinGW-w64 Universal CRT split
```

The presence of `CreateThreadpoolWork` / `SubmitThreadpoolWork` / `WaitForThreadpoolWorkCallbacks` in the import table, before any dynamic analysis was done, was the first hint that control transfer doesn't happen through a plain direct call — confirmed later in [`03-dynamic-unpacking.md`](03-dynamic-unpacking.md).

The string dump also contains typical MinGW-w64 **pseudo-relocation runtime error strings** (`Unknown pseudo relocation protocol version %d.`, etc.) — a standard side effect of GCC's ASLR-support mechanism for MinGW binaries, not something malware-specific.

## Finding 1 — the `.reloc` "padding" is not null bytes

The initial incident report claimed the `.reloc` section was inflated with **122.5 MB of `0x00` bytes** specifically to defeat automated sandboxes (a common heuristic: skip scanning files above a size threshold).

Sampling the section across the full 126 MB original file showed that **almost none of those bytes are actually zero**. The real pattern is a **repeating 16-byte sequence with low entropy (~3.9 bits/byte)** — still padding for the same evasion purpose, but not literal null-byte filling. This is also why the attacker's own delivery archive (`malpack.7z`, see [`../samples/`](../samples/)) compresses the 126.5 MB file down to just 1.4 MB: a repeating low-entropy pattern compresses extremely well, however it's constructed.

This also confirms that truncating the binary to its first 5 MB (below) is safe — the real code isn't hidden anywhere inside that low-entropy tail.

## Truncating the binary for analysis (*unpadding*)

```bash
dd if=/tmp/malware_extract/shahradr.exe of=/tmp/shahradr_clean.exe bs=1M count=5
```

Result: a fully functional 5.0 MB binary (SHA-256 `83ad6dd1537d6abb4847da24183ea5c58e5ebc1af772251b001b0f07c0032a8d`), used for the rest of the static and dynamic analysis instead of loading the full 126 MB file into every tool.

## Entry point and key addresses

Confirmed by both `objdump -d` and rizin/Ghidra decompilation:

| Address / symbol | Role |
|---|---|
| `entry0` @ `0x140001420` | Binary entry point. Thin wrapper that calls `fcn.140001020`. |
| `fcn.140001020` | MinGW-w64 CRT init. Calls `fcn.140012470` (via `1400010d4: call 0x140012470`) once runtime setup finishes. |
| `fcn.140012470` | Unpacker core — see [`03-dynamic-unpacking.md`](03-dynamic-unpacking.md) for what it does at runtime. |
| `0x1400123b0` – `0x14001240f` | Junk-code block (semantic no-ops: `lea rsi,[rsi]`, `xchg rdi,rdi`, `mov r14,r14`) followed by the real control transfer (`call rax` at `0x14001240f`) — designed to defeat a naive linear disassembler. |

## Tools used in this phase

Full detail in [`../tools-used.md`](../tools-used.md). In short: Cutter (AppImage) plus its bundled `rizin`, run without `sudo` by reusing the binaries already extracted at `squashfs-root` by the AppImage itself, plus standard Binutils (`objdump`) and `strings` directly on Debian.

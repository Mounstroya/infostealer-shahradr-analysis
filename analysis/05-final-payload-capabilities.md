# 05 — The real final payload, reconstructed

## The missing piece was inside the buffer all along

[`04-payload-analysis.md`](04-payload-analysis.md) established that the unpacked buffer (`payload_unpacked.exe`, 573,600 bytes) is a *self-locating manual PE-mapper*: it finds its own address via a `call`/`pop` trick, and then treats that address as the base of a small in-memory structure (call it `arg4`) it uses to map a target PE. The mapper function (`fcn.0007bc74`) reads a pointer at `arg4+8` — which was zero in the raw dump, and previously assumed to be something patched in from outside.

Decompiling one more function closed that gap. `fcn.0007bc74` first calls a gate check (`fcn.0008aedf`, see below), and — critically — **also calls `fcn.0007ec2b(arg4)` before ever using `arg4+8`**. That function:

1. Reads a size field at `arg4+0x00` and a flags bitmask at `arg4+0x04`.
2. Allocates a new buffer of that size.
3. If flag bit 0 is set, calls `fcn.0007e9c4(arg4+0x48, size, arg4+0x18, arg4+0x38, new_buffer, &out_len)` — a **decryption call**, with a source pointer, a key pointer (`arg4+0x18`), and an IV pointer (`arg4+0x38`).
4. If flag bit 1 is set, reverses the newly-decrypted buffer end-to-end (the same conditional byte-reversal pattern already seen in the outer packer stage).
5. Writes the result into `*(arg4+8)` — **this is what fills in the "missing" pointer.**

In other words: **the buffer decrypts itself.** There's no external patch, no network fetch required to get past this point — the target image and the key to unlock it are both already sitting in the 573,600-byte buffer we already had.

## Extracting it

Since `arg4 = 5` (the return address after the 5-byte `call` at the very start of the buffer), the absolute file offsets are `arg4 + N`:

| Field | Offset (`arg4 + N`) | Absolute offset | Value |
|---|---|---|---|
| Embedded ciphertext size | `+0x00` | 5 | 506,896 bytes (`0x7bc10`) |
| Flags | `+0x04` | 9 | `0x3` (bit0: decrypt, bit1: reverse after decrypt) |
| Target pointer (zero until computed) | `+0x08` | 13 (`0xD`) | `0x0` in the raw dump — confirms this is exactly the "offset 0xD" field noted in [`04-payload-analysis.md`](04-payload-analysis.md) |
| AES-256 key (32 bytes) | `+0x18` | 29 | `4952f1563b2f0db80958a119b5024a4cfa4b861fbf3321b60ed70cd2a1a84698` |
| IV (16 bytes) | `+0x38` | 61 | `fbc177a9cd6419601a55fb5e1431b0a7` |
| Ciphertext (506,896 bytes) | `+0x48` | 77 | — |

Reproducing `fcn.0007ec2b` in Python:

```python
from Crypto.Cipher import AES
import struct

data = open('payload_unpacked.exe', 'rb').read()
base = 5  # arg4 = return address after the 5-byte self-locating `call`

size = struct.unpack_from('<I', data, base + 0x00)[0]
key  = data[base + 0x18 : base + 0x38]
iv   = data[base + 0x38 : base + 0x48]
ct   = data[base + 0x48 : base + 0x48 + size]

pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)

pad = pt[-1]                                   # strip PKCS7 padding (normal orientation)
if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
    pt = pt[:-pad]

final = pt[::-1]                               # flag bit1: reverse the whole thing
open('final_stealer_candidate.exe', 'wb').write(final)
```

Result: **a fully valid PE file.**

```
$ file final_stealer_candidate.exe
final_stealer_candidate.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 5 sections
```

- Size: 506,880 bytes
- SHA-256: `3f6c58760052c60e33c2951196f7c46f54f9fd1d390956fef7aeb3b9156312ee`
- Sections: `.text`, `.rdata`, `.data`, `.pdata`, `.reloc` — a completely ordinary-looking section layout, no more padding tricks
- Linker timestamp: Fri Aug 28 04:27:28 2026 — one day before this specific infection, consistent with a per-campaign or per-build compile
- Encrypted copy included under [`../samples/`](../samples/)

## The gate check, explained

`fcn.0008aedf` (called before the decryption above) combines two sub-checks (`fcn.0008a2be`, `fcn.0008a92c`); the mapper only proceeds if **both** return "pass". Decompiling `fcn.0008a2be` shows it:

1. Sends a real HTTP request: `GET /what-is-my-ip HTTP/1.1` to `Host: ipinfo.io` (matches the strings already found in [`04-payload-analysis.md`](04-payload-analysis.md)).
2. Parses the **HTML** response (not the JSON API) looking for a table/span field literally labeled `ASN type` (`<td>`/`</td>`, `<span>`/`</span>` tags appear as reference strings for this parsing).
3. Lowercases the extracted value and checks whether it contains the substring **`hosting`** (also found verbatim as a string in the buffer).
4. If it does, the check fails (returns 1) and the mapper never runs.

**This is a residential-IP gate**: it only continues if the outbound connection's ASN doesn't look like a datacenter/cloud/VPS provider — exactly the kind of IP address any sandbox, VM, or cloud-hosted analysis environment would have, and exactly the kind a real infected home user would not. This is the concrete mechanism behind the "anti-sandbox check" noted earlier, and it explains why simply running this binary in a typical analysis VM would silently do nothing.

It's worth noting this check **did not need to be bypassed** to get the result above — the decryption in `fcn.0007ec2b` and the network gate in `fcn.0008a2be`/`fcn.0008a92c` are two independent code paths off the same `fcn.0007bc74`, and the decryption path doesn't depend on the gate check passing first when reproduced statically in Python instead of by letting the real binary run.

## What the reconstructed payload actually does

The import table of `final_stealer_candidate.exe` is deliberately minimal and padded (KERNEL32.dll with ~200 mostly-unused functions, plus a couple of `USER32.dll`/`ntdll.dll` entries) — a standard technique to make static import analysis useless. The real capability list only shows up in the **strings**, which reveal DLLs and APIs resolved dynamically at runtime (via `LoadLibrary`/`GetProcAddress`, invisible to the static import table):

| Evidence found | What it means |
|---|---|
| `AmsiScanBuffer`, `AmsiScanString`, `\System32\Amsi.dll` | **AMSI bypass** — patches Windows' Antimalware Scan Interface in memory so script/buffer content stops being scanned. |
| A literal path to `ntdll.dll` under `C:\Windows\System32\` | Consistent with **NTDLL unhooking** — reading a clean copy of `ntdll.dll` from disk to overwrite any EDR hooks placed in the in-memory copy. |
| `splwow64.exe`, `RuntimeBroker.exe`, `%SystemRoot%\...\explorer.exe` | Legitimate Windows process names referenced as **injection/masquerading targets** — hiding the malware's activity inside or as a trusted-looking process. |
| `msiexec`, `/i`, `open` | Builds an `msiexec /i <path>` command line — abusing the legitimate Windows Installer as a **LOLBin** to execute a package quietly. |
| `Run`, `RunOnce` (registry key names) | **Persistence** via the standard `HKCU\...\Run`/`RunOnce` auto-start registry keys. |
| `Winhttp.dll`, `Urlmon.dll` | Dynamically-loaded networking stack — for downloading further components and/or exfiltrating stolen data. |
| `Crypt32.dll`, `Advapi32.dll` | Windows crypto/registry APIs — consistent with decrypting DPAPI-protected browser secrets. |
| `Ole32.dll`, `OleAut32.dll`, `IIDFromString` | COM interop — needed to call into a browser's elevated COM service. |
| **`appbound`** (literal string) | **The single most specific finding.** This is the internal name Chromium uses for **App-Bound Encryption**, the credential-protection mechanism introduced in Chrome 127+ (2024) specifically to defeat DPAPI-only infostealers. Combined with the `Ole32`/`OleAut32`/`IIDFromString` COM evidence above, this confirms the malware implements the (well-documented, publicly known) **App-Bound Encryption bypass** technique used by current-generation stealer families to still decrypt passwords/cookies from up-to-date Chrome installs. |
| `Netapi32.dll` | Network/domain enumeration (system fingerprinting). |
| `Shell32.dll` | Almost certainly used for known-folder resolution (`SHGetKnownFolderPath` or similar) — i.e., locating `%LOCALAPPDATA%`/`%APPDATA%` browser profile directories. |
| `Program Files (x86)`, `Local\`, `Roaming\` (path fragments) | Consistent with enumerating installed browsers and their profile folders under `AppData\Local` and `AppData\Roaming`. |
| `OZD89c34thJVDqoM5a1MZkChlwn38` and repeated junk tokens (`ppapaas`, `siuhgsehug`, ...) | An unusual fixed-looking token (possibly a build/campaign identifier) alongside clear junk/decoy strings meant to pollute string-based signature matching. |

Put together, this is a **modern, actively-maintained Chromium-targeting InfoStealer** with defense evasion (AMSI bypass, NTDLL unhooking, process masquerading), a persistence mechanism, and — most notably — specific engineering to defeat Chrome's newest anti-theft protection (App-Bound Encryption), not just "generic DPAPI decryption" as older stealers do. See [`../data-exfiltrated.md`](../data-exfiltrated.md) for what this means for data actually at risk, and [`../iocs.md`](../iocs.md) for the consolidated indicators.

## What's still not done

The strings above establish *capability*, not a byte-for-byte trace of execution. Nobody has:

- Decompiled the actual App-Bound Encryption bypass routine instruction-by-instruction.
- Observed real network exfiltration traffic (this would require detonating the binary in a monitored, network-isolated VM with a residential-looking egress IP — remember the ASN gate above).
- Confirmed the exact registry `Run` value name or process-masquerading technique used (DLL injection vs. process hollowing vs. something else) at the instruction level.

Those are the natural next steps for anyone who wants to go beyond "what it's capable of" to "exactly how it does it, instruction by instruction."

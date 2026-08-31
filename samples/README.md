# ⚠️ Real malware samples — encrypted, handle with extreme care

This folder contains an **AES-256 encrypted, filename-obfuscated 7z archive** with the real artifacts collected during this investigation. This repository is **private**; do not make it public without first reconsidering whether these files should be removed or moved to a dedicated malware-sharing platform (e.g. MalwareBazaar) instead.

## What's inside `malware-samples-PROTECTED.7z`

| File | Original size | SHA-256 |
|---|---|---|
| `malpack.7z` | 1,412,274 bytes | `f83dbb02d34bc4dedf53ac7f24aca7eda27d0d08d4c5962ee6172b85518892ea` |
| `shahradr_clean.exe` | 5,242,880 bytes | `83ad6dd1537d6abb4847da24183ea5c58e5ebc1af772251b001b0f07c0032a8d` |
| `payload_unpacked.exe` | 573,600 bytes | `d468dedbb8e105ca4320a2d103e39437ccfd4633ef19c0fab7660efacbc8c344` |

- **`malpack.7z`** is the *original archive exactly as served by the attacker's infrastructure* (`sillygoosetoon.cfd/dl/689838.7z`), still protected with the malware's **own** password (`10000` — see [`../iocs.md`](../iocs.md)). Extracting it reproduces the original 126.5 MB `shahradr.exe` (SHA-256 `07bb18a008faf81b1586e1d112f0e1a8dc94fc70253eb52e8586b54fb6cfe2d7`) exactly. That original file is **not** stored directly in this repo — it's 120+ MB (over GitHub's file size limit) and 96% of it is low-entropy padding anyway (see [`../analysis/02-static-analysis.md`](../analysis/02-static-analysis.md)); `malpack.7z` reproduces it losslessly at 1/90th the size.
- **`shahradr_clean.exe`** is the truncated, functional-for-analysis binary used throughout the reverse-engineering work (first 5 MB of the original, produced with `dd`).
- **`payload_unpacked.exe`** is the AES-decrypted second-stage buffer dumped from the emulator (see [`../analysis/03-dynamic-unpacking.md`](../analysis/03-dynamic-unpacking.md)) — this is shellcode/a manual PE-mapper stub, **not** a directly runnable Windows program on its own.

None of these files are directly executable as delivered here — they're wrapped in an encrypted 7z container, and `malpack.7z` inside it has its own separate password.

## How to safely extract (isolated VM / sandbox only)

```bash
# 1. Extract the outer container (this repo's password)
7z x malware-samples-PROTECTED.7z -p'infected'

# 2. (Optional) Extract the attacker's original archive (malware's own password)
7z x malpack.7z -p'10000'
```

**Do this only inside a disposable, network-isolated VM you're prepared to wipe.** Never double-click, never run, never open these files on your daily-driver machine. Antivirus engines will very likely flag `shahradr_clean.exe` / the extracted original — that is expected and correct behavior, not a false positive.

## Why keep the real samples at all

The point of a private research repo like this one is reproducibility: someone continuing this analysis (including a future version of yourself) should be able to re-run the static/dynamic analysis in [`../analysis/`](../analysis/) against the exact same bytes, rather than trusting written descriptions alone.

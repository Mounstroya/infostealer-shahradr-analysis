# Indicators of Compromise (IOCs)

All of these are attacker-controlled infrastructure/artifacts, not the victim's data — kept unredacted since they're exactly what's useful for detection and blocking.

## Domains, IPs and URLs

| Indicator | Role |
|---|---|
| `dragonphoenixstar.cfd` | Serves per-victim stage-1/stage-2 PowerShell tokens, the portable `7z.exe` mirror, and the delivery-callback endpoint |
| `sillygoosetoon.cfd` | Serves the password-protected `.7z` archive |
| `91.92.33.156` | Hosts the C2 panel (`/panel/pb-fire`) and an alternate `7z.exe` mirror (`/t/7z.exe`) |
| `http://91.92.33.156/panel/pb-fire` | C2 panel endpoint (Russian-language interface), receives the POST beacon |
| `http://sillygoosetoon.cfd/dl/689838.7z` | Direct download URL for the delivered archive (this campaign's ID: `689838`) |
| `dragonphoenixstar.cfd/dl-callback/<session-id>/<archive-name>/<token>` | Delivery-confirmation telemetry callback pattern |
| `dragonphoenixstar.cfd/<16-char-token>` | Per-victim stage-loading URL pattern (two chained instances observed per infection) |

## Network behavior

| Indicator | Value |
|---|---|
| Required User-Agent substring | `WindowsPowerShell/5.1` — requests without it get an HTTP 301 instead of the payload |
| Custom HTTP header sent by the dropper | `X-Panel-Internal: 1` |
| Anti-sandbox check found in the unpacked payload | `GET /what-is-my-ip HTTP/1.1` to `ipinfo.io`, Chrome User-Agent |

## Files and passwords

| Indicator | Value |
|---|---|
| Binary name | `shahradr.exe` |
| Real `.7z` archive password (confirmed from the dropper script) | `10000` |
| Password claimed in the (inaccurate) initial report | `ShahradR_Pass2026` — **do not rely on this one** |
| Infection marker | `%TEMP%\rx_unpack.ok` |
| Original binary size (with padding) | 126,525,440 bytes (126.5 MB) |
| Truncated/functional binary size | 5,242,880 bytes (5 MB) |
| Decrypted payload buffer size | 573,600 bytes (`0x8c0a0`) |
| `.reloc` section size | `0x074ab800` = 122,337,280 bytes |
| Manifest identity / version | `phasebuilder.0cedd7` / `346.4.1.98` |

## SHA-256 hashes

| File | SHA-256 |
|---|---|
| `shahradr.exe` (original, 126.5 MB) | `07bb18a008faf81b1586e1d112f0e1a8dc94fc70253eb52e8586b54fb6cfe2d7` |
| `shahradr_clean.exe` (truncated, 5 MB) | `83ad6dd1537d6abb4847da24183ea5c58e5ebc1af772251b001b0f07c0032a8d` |
| `payload_unpacked.exe` (decrypted stage-2 buffer) | `d468dedbb8e105ca4320a2d103e39437ccfd4633ef19c0fab7660efacbc8c344` |
| `malpack.7z` (original delivered archive) | `f83dbb02d34bc4dedf53ac7f24aca7eda27d0d08d4c5962ee6172b85518892ea` |

Encrypted copies of these files are available under [`samples/`](samples/) for anyone continuing this analysis.

## Internal cryptography (needed to reproduce the unpacking)

| Indicator | Value |
|---|---|
| Algorithm | AES-256-CBC (Windows CryptoAPI, `CALG_AES_256`) |
| Key (32 bytes, hex) | `cfcc13c0242c3d3cabaf192aee60adb06b3246547ab35444b0a5ee2ade97821` |
| IV (16 bytes, hex) | `ea2f9b0cf0859c950c2cc2574780e05` |

## Internal binary addresses (this specific build)

| Address | Role |
|---|---|
| `0x140001420` | `entry0` |
| `0x140001020` | CRT init (MinGW-w64) |
| `0x140012470` | Unpacker core |
| `0x140012230` | Memory allocation / conditional byte-reversal function |
| `0x1400123b0` – `0x14001240f` | Junk code + real control transfer |

> These addresses are valid for this specific build of the malware (internal binary offsets) — useful for a YARA rule or unpacking script targeted at this exact sample, but expected to shift in recompiled variants of the same family.

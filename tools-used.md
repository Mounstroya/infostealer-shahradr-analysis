# Tools used in this investigation

| Tool | Version | What it was used for |
|---|---|---|
| **Debian GNU/Linux** | — | Analysis host. No passwordless `sudo` at any point — everything was done in user space. |
| **`curl`** | — | Reproduced the stage-1/stage-2 PowerShell fetches and the archive download directly against the live infrastructure, without ever executing the returned content. Also used to discover the User-Agent gating behavior of the C2. |
| **`dd`** | — | Truncated (*unpadded*) the 126.5 MB binary down to a functional 5 MB copy (`bs=1M count=5`), stripping the low-entropy padding without losing any real code. |
| **`objdump`** (Binutils) | — | Section table and linear disassembly of the original binary — cross-checked against the rizin/Ghidra findings below. |
| **`strings`** | — | Extracted readable strings from both the original binary (imports, manifest, MinGW runtime strings) and the unpacked payload buffer (the `ipinfo.io` anti-sandbox check). |
| **Cutter** (AppImage) | — | GUI reverse-engineering tool. Its already-mounted AppImage (`squashfs-root`) was reused to get working `rizin` binaries without installing anything via `apt`. |
| **rizin** | 0.7.1 (extracted from Cutter's AppImage) | Headless static disassembly (`rz-asm`), function listing, and the analysis engine backing the Ghidra plugin. |
| **rz-ghidra** (`core_ghidra.so`) | bundled with Cutter | Ghidra decompiler via rizin, used to get C pseudocode for `fcn.140012470` and `fcn.140012230`. Required pointing `SLEIGHHOME` at the Sleigh specs (`x86-64.sla`) bundled in the same AppImage. |
| **Python** | 3.13.5 | Language used for the emulation environment. |
| **Isolated Python venv** | — | Dedicated virtual environment (`malware_venv`), kept separate from the system Python. |
| **Speakeasy** (`speakeasy-emulator`) | 1.5.11 | Windows PE emulation engine (built on Unicorn) used to run the unpacker stub with no real Windows machine involved, with custom hooks over CryptoAPI, memory writes, and the Thread Pool APIs. |
| **Unicorn Engine** | 1.0.2 (pinned deliberately) | The underlying CPU emulation engine behind Speakeasy. Kept at 1.0.2 instead of 2.x because Speakeasy 1.5.11 isn't compatible with Unicorn 2.x's internal API. |
| **setuptools** | — | Provided the `distutils` compatibility shim, removed from Python 3.13 but required by `unicorn==1.0.2`. |
| **Capstone** | 5.0.9 | Disassembly engine used internally by the tooling. |
| **pefile** / **lief** | 2024.8.26 / 1.0.0 | Parsing PE structures (headers, sections) from Python. |
| **pycryptodome** | — | Independent verification of the AES-256-CBC decryption (confirming the real key/IV outside of the emulator itself). |
| **7-Zip (`7z`)** | 25.01 | Extracting the attacker's password-protected archive for analysis, and building the AES-256-encrypted, filename-obfuscated bundle under [`samples/`](samples/) for this repo. |

## Custom analysis script

During the investigation, a Python script — `appendix/unpack_shahradr.py` — was written and iteratively fixed. It:

1. Loads `shahradr_clean.exe` into Speakeasy with its original base address and image.
2. Hooks the CryptoAPI functions (`CryptAcquireContextW`, `CryptImportKey`, `CryptSetKeyParam`, `CryptDecrypt`) to log them and, where Speakeasy didn't already model them, re-implement the real decryption (parsing the key `BLOBHEADER` and running real AES/RC4/3DES/DES depending on the algorithm ID).
3. Hooks `CreateThreadpoolWork` to capture the context pointer (the already-decrypted buffer) at the exact moment the callback is scheduled, instead of re-executing the function and risking emulator re-entrancy issues.
4. Dumps the relevant buffers to disk for follow-up analysis with `strings`/rizin.

This repository includes the script (paths generalized, no personal directory names) — see [`appendix/unpack_shahradr.py`](appendix/unpack_shahradr.py).

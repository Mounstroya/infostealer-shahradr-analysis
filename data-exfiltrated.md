# What data this malware can steal

**Update:** the investigation initially stalled before reaching the real payload (see history in [`TIMELINE.md`](TIMELINE.md)), but the final-stage PE was later reconstructed — see [`analysis/05-final-payload-capabilities.md`](analysis/05-final-payload-capabilities.md). The findings below are now based on real evidence (strings and dynamically-loaded DLLs found in the reconstructed payload), not just family-level inference.

## Confirmed capabilities (from the reconstructed final payload)

- **Chrome App-Bound Encryption bypass.** The literal string `appbound` plus COM interop evidence (`Ole32.dll`, `OleAut32.dll`, `IIDFromString` loaded dynamically) confirm this malware specifically targets **App-Bound Encryption**, the mechanism Chrome 127+ introduced in 2024 to stop exactly this kind of DPAPI-based credential theft. This means **saved passwords and cookies in an up-to-date Chrome are not safe** from this malware — it's built for the current generation of browser protections, not an outdated technique.
- **Browser profile enumeration.** Path fragments for `AppData\Local\` and `AppData\Roaming\`, plus dynamically-loaded `Shell32.dll` (used for resolving known-folder paths), indicate it locates browser profile directories directly rather than guessing fixed paths.
- **Defense evasion, not just theft.** The payload also patches **AMSI** (`AmsiScanBuffer`/`AmsiScanString`) to stop script-content scanning, and shows evidence consistent with **unhooking `ntdll.dll`** (reading a clean copy from `C:\Windows\System32\`) to remove EDR's in-memory API hooks.
- **Process masquerading.** References to legitimate process names (`splwow64.exe`, `RuntimeBroker.exe`, `explorer.exe`) suggest it injects into, or disguises itself as, a trusted system process.
- **Persistence.** References to the `Run`/`RunOnce` registry auto-start keys indicate it re-launches itself after reboot.
- **LOLBin execution.** A constructed `msiexec /i <path>` command line suggests it (or a helper stage) installs/executes via the legitimate Windows Installer to blend in with normal system activity.
- **Networking/exfiltration stack.** `Winhttp.dll` and `Urlmon.dll` are loaded dynamically — the actual channel used to send stolen data back was not captured live (would require network monitoring during a real detonation), but the C2 panel destination is documented in [`analysis/06-c2-infrastructure.md`](analysis/06-c2-infrastructure.md).

Full technical detail and the exact strings/evidence for each item: [`analysis/05-final-payload-capabilities.md`](analysis/05-final-payload-capabilities.md).

## Still not directly observed

- The exact registry key/value name used for persistence.
- A byte-for-byte trace of the App-Bound Encryption bypass routine.
- Real exfiltration network traffic (this binary refuses to run its real logic unless the outbound IP looks residential rather than a hosting/datacenter provider — see the ASN gate check in [`analysis/05-final-payload-capabilities.md`](analysis/05-final-payload-capabilities.md) — so live detonation would need a matching network environment).
- Whether cryptocurrency wallets, FTP/VPN clients, or messaging apps are also targeted by additional "grabber" modules — no direct evidence either way was found in the strings reviewed.

## What to do if your machine was exposed to this sample

Given the confirmed App-Bound Encryption bypass capability, treat this as a **full credential compromise of every browser account saved on the affected machine**, not a partial/uncertain one:

1. Rotate the passwords for every account saved in the browser on the affected machine — ideally from a separate, clean device.
2. Sign out of all devices/sessions on critical services (invalidates any stolen session cookies).
3. Review and move funds out of any exposed cryptocurrency wallet.
4. Enable 2FA anywhere it wasn't already on.
5. Reinstall the operating system on the affected machine rather than just removing the malware — this InfoStealer specifically evades AMSI/EDR and persists via the registry; a manual cleanup can't be trusted to have removed everything.

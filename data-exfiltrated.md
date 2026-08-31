# What data this malware can steal

**Important:** this investigation reached the point of unpacking the final payload's loader stub (see [`analysis/04-payload-analysis.md`](analysis/04-payload-analysis.md)), but **the actual data-theft functions were never decompiled** — the manual PE-mapper stub was left incomplete (it's missing a pointer that gets patched right before real execution). So what follows combines:

- **Confirmed by this analysis:** the existence of a C2 panel designed to receive credentials/cookies (explicitly mentioned in the initial forensic report, see [`analysis/05-c2-infrastructure.md`](analysis/05-c2-infrastructure.md)), and the fact that the binary's imports and dropper behavior (silent execution, Mark-of-the-Web removal, beaconing) are all consistent with this class of malware.
- **Not confirmed / inferred by family:** the exact files it reads, which DPAPI/SQLite3 APIs it calls, and the exact exfiltration format — none of that code was reached or decompiled in this session.

## Typical categories for this kind of InfoStealer (Russian-language "PB-Fire" panel)

This class of panel typically targets the following categories of data on a compromised machine (**generic to the family, not confirmed item-by-item for this specific sample**):

- Passwords saved in Chromium/Firefox-based browsers (DPAPI-protected on Windows).
- Active session cookies (allow hijacking already-logged-in sessions without needing the password).
- Browser autofill/form history.
- Cryptocurrency wallet data (browser extension wallets or local desktop wallet files) — common in this kind of campaign.
- FTP/VPN/messaging client configuration files, if the stealer bundles additional "grabber" modules.
- Screenshots or system fingerprinting info, consistent with the IP/geolocation check found in the partial payload (`ipinfo.io/what-is-my-ip`).

## What to do if your machine was exposed to this sample

Since the exact scope wasn't confirmed, the safe assumption is to treat the incident as if **everything above** was stolen:

1. Rotate the passwords for every account saved in the browser on the affected machine — ideally from a separate, clean device.
2. Sign out of all devices/sessions on critical services (invalidates any stolen session cookies).
3. Review and move funds out of any exposed cryptocurrency wallet.
4. Enable 2FA anywhere it wasn't already on.
5. Reinstall the operating system on the affected machine rather than just removing the malware — an InfoStealer this sophisticated (real crypto, Thread Pool-based evasion, anti-sandbox checks) isn't something to trust a manual cleanup with.

## Pending work to confirm the real scope

Completing the reconstruction described in [`analysis/04-payload-analysis.md`](analysis/04-payload-analysis.md) would allow decompiling the actual functions and replacing this section with confirmed findings instead of family-level inference.

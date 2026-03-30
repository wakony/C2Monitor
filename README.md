# C2Monitor

Lightweight Command & Control beacon detection for Windows. Catches malware callbacks that your antivirus misses.

> **See also: [CerberusWard](https://github.com/wakony/cerberusward)** — static supply chain scanner that catches compromised code BEFORE it runs. Use CerberusWard for prevention, C2Monitor for runtime detection. Together they provide full-lifecycle supply chain protection.

## What It Does

C2Monitor detects malware that has already bypassed your antivirus and is "phoning home" to an attacker's server. It catches:

- **Beaconing** - processes calling back at regular intervals (the #1 C2 signature)
- **Known C2 servers** - cross-references connections against abuse.ch Feodo Tracker (updated every 6 hours)
- **DGA domains** - randomly generated domain names used by malware (Shannon entropy analysis)
- **DNS tunneling** - data exfiltration over DNS from non-system processes
- **Phishing chains** - Office apps spawning cmd/powershell (initial access detection)
- **Encoded PowerShell** - obfuscated commands used by attackers
- **Lateral movement** - outbound RDP connections from your workstation
- **Unsigned executables** making network connections from temp folders
- **Blockchain C2 resolution** - detects processes querying blockchain RPC endpoints to resolve C2 addresses (Lazarus Group TTPs)
- **DevGuard** - real-time blockchain C2 monitoring that activates automatically when dev servers start (`next dev`, `vite`, `npm run dev`, etc.)

## Install

```powershell
# Download the installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wakony/C2Monitor/master/Install-C2Monitor.ps1" -OutFile "$env:TEMP\Install-C2Monitor.ps1"

# Review it first — this is a security tool that runs as SYSTEM.
# You should read every line. The full source is also in the src/ directory.
notepad "$env:TEMP\Install-C2Monitor.ps1"

# Run as Administrator
Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File $env:TEMP\Install-C2Monitor.ps1"
```

## What Gets Installed

| Component | Purpose | Resource Usage |
|-----------|---------|---------------|
| **Sysmon** (Microsoft) | Kernel-level network/process logging | ~26 MB RAM, always running |
| **Deep Scan** | Beaconing analysis + threat intel | ~100 MB, runs 10 min every 30 min, then exits |
| **Quick Watch** | Connection spot-checks | ~50 MB, runs few seconds every 5 min, then exits |
| **Notifier** | Desktop toast alerts | ~75 MB RAM, always running in your session |
| **DevGuard** | Real-time dev server blockchain monitor | ~30 MB, active only while dev servers run |

**Total persistent footprint: ~120 MB RAM** (DevGuard is idle when no dev server is running)

All data stays on your machine. No cloud. No subscription. No telemetry.

## How Detection Works

### Beaconing Detection
The deep scanner samples all outbound TCP connections 20 times over 10 minutes. It calculates the **coefficient of variation** of connection intervals per process/destination pair. A low CV (< 0.30) with consistent timing indicates automated beaconing rather than human-driven traffic.

### Threat Intelligence
Every 6 hours, the scanner downloads the latest known C2 server IPs from [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) and cross-references all active connections and Sysmon network logs against this list.

### DGA Detection
DNS queries logged by Sysmon are analyzed for **Shannon entropy**. Domains with entropy > 3.5 and length > 15 characters are flagged as potential Domain Generation Algorithm output.

### Process Lineage
Sysmon process creation events are checked for suspicious parent-child relationships (e.g., `WINWORD.EXE` spawning `powershell.exe`), which is the classic phishing attack chain.

### Blockchain C2 Detection
Advanced malware (notably Lazarus Group / DPRK campaigns) hides C2 server addresses in blockchain transactions. The malware contacts legitimate blockchain RPC endpoints (TRON, BSC, Ethereum, Solana, Aptos, etc.) to read transaction data containing XOR-encrypted C2 addresses. Traditional IP/domain blacklists miss this because the RPC endpoints are legitimate services. C2Monitor detects this by monitoring which **processes** contact blockchain RPC domains -- a build tool like `node.exe` or `npm` querying `trongrid.io` during a build is a critical red flag, since no legitimate build process should ever call blockchain APIs. The scanner maintains a separate trusted process list for blockchain access (crypto wallets, browsers) distinct from the general network trusted list.

This detection capability was developed from firsthand experience with a **real Lazarus Group (DPRK) supply chain attack**. The attack injected obfuscated JavaScript into build configuration files (`postcss.config.mjs`, `next.config.mjs`) which, when executed during a normal build, queried blockchain RPC endpoints to retrieve encrypted C2 addresses from on-chain transaction data. Because the RPC endpoints themselves are legitimate infrastructure, the C2 resolution was invisible to traditional network security tools.

### DevGuard (Real-time Dev Server Protection)

DevGuard closes the gap between scheduled scans by providing **instant** blockchain C2 detection during dev sessions. It continuously monitors for dev server process launches (`next dev`, `vite`, `npm run dev`, `pnpm dev`, `yarn dev`, `gatsby develop`, `nuxt dev`, `remix dev`, `astro dev`, `ng serve`, `bun dev`, etc.) and when one starts, it immediately begins monitoring that process and all its children for blockchain RPC calls.

This matters because the Lazarus Group attack executed **during `next build` / `next dev`** — the malware in `postcss.config.mjs` ran as part of the normal build process. DevGuard catches this within 15 seconds instead of waiting up to 30 minutes for the next deep scan.

DevGuard runs as a persistent background service but is effectively idle when no dev server is running. It checks for new dev server processes every 5 seconds and monitors active sessions every 15 seconds (configurable).

## Configuration

After installation, edit `C:\ProgramData\C2Monitor\config.json` to customize:

- **Trusted processes** - whitelist apps you know are safe (browsers, VPN, etc.)
- **C2 ports** - add/remove ports to monitor
- **Scan intervals** - adjust sample count and timing
- **Alert cooldown** - how long before the same alert can fire again (default: 60 min)
- **Threat intel refresh** - how often to update C2 IP list (default: 6 hours)
- **Blockchain RPC domains** - blockchain API endpoints to monitor for C2 resolution attempts
- **Blockchain trusted processes** - processes allowed to contact blockchain RPCs (crypto wallets, browsers)
- **Build tool process names** - build tools that should never contact blockchain APIs
- **DevGuard** - monitor interval, max session duration, enable/disable

See [`src/config.default.json`](src/config.default.json) for the full default configuration.

## Alerts

When something is detected, you get:
1. **Desktop toast notification** (immediate, on-screen)
2. **Log entry** at `C:\ProgramData\C2Monitor\alerts.log`
3. **Windows Event Log** entry (Application > Source: C2Monitor)

Each alert includes: severity, description, process name, PID, full file path, remote IP:port, and SHA256 hash of the suspicious file. Duplicate alerts are suppressed for 60 minutes (configurable) to prevent notification fatigue.

### What To Do When You Get an Alert

**CRITICAL — BLOCKCHAIN C2 / KNOWN C2 SERVER / BEACONING:**
1. **Disconnect from the internet immediately.** Pull ethernet or disable Wi-Fi.
2. Note the process name and file path from the alert.
3. Open Task Manager, find the process, and **End Task**.
4. Check the file path — if it's inside `node_modules`, a project directory, or a temp folder, the project may be compromised.
5. **Do not run `npm install` or `npm run dev` again** in that project until you've inspected `package.json`, `postcss.config.mjs`, `next.config.mjs`, and any other config files for injected code. Look for unusually long lines, trailing whitespace hiding code, or obfuscated JavaScript.
6. Check your alert log at `C:\ProgramData\C2Monitor\alerts.log` for the full details including the SHA256 hash.
7. Upload the SHA256 hash to [VirusTotal](https://www.virustotal.com/) to check if the file is known malware.
8. If confirmed malicious: rotate all credentials accessible from that machine (API keys, tokens, passwords). Assume anything in environment variables or browser saved passwords may be compromised.

**HIGH — C2 PORT / UNSIGNED EXECUTABLE / BLOCKCHAIN RPC:**
1. Check the process name and file path. Is this something you installed?
2. If you don't recognize it, search the SHA256 hash on VirusTotal.
3. If the file is in a temp folder or has no valid signature, treat it as suspicious until confirmed safe.

**MEDIUM — DGA DOMAIN / EXCESSIVE DNS:**
1. Check if the flagged domain belongs to a service you use. Some legitimate services use high-entropy subdomains.
2. If the domain looks random (e.g., `a8x7kq2m9p4.example.com`), investigate the process making the request.

**False positives are normal.** If you keep seeing alerts for a process you trust, add it to `trustedProcesses` in `C:\ProgramData\C2Monitor\config.json`. For blockchain-related false positives (e.g., you're a Web3 developer), add your tools to `blockchainTrustedProcesses` instead.

## Security

- Install directory is ACL-locked: only SYSTEM and Administrators can write, preventing script tampering by malware
- Scans run as SYSTEM via scheduled tasks for tamper resistance
- Connection history uses file-level locking to prevent corruption
- All downloads enforce TLS 1.2

## See Also

**[CerberusWard](https://github.com/wakony/cerberusward)** — Static supply chain integrity scanner. While C2Monitor detects blockchain C2 calls *during* builds, CerberusWard catches the injected code *before* it runs. Use both together: CerberusWard scans your config files for obfuscated payloads before `npm install` / `npm run build`, and C2Monitor watches the network if anything slips through.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\C2Monitor\Uninstall-C2Monitor.ps1
```

Cleanly removes everything: Sysmon, scheduled tasks, registry entries, and optionally archives your alert logs.

## Requirements

- Windows 10 or 11
- PowerShell 5.1+ (included with Windows)
- Administrator privileges (for Sysmon and scheduled tasks)
- ~120 MB RAM

## Trusted Source

**The only official source for C2Monitor is this repository: [github.com/wakony/C2Monitor](https://github.com/wakony/C2Monitor)**

Do not download C2Monitor from any other source, fork, mirror, or third-party website. If you didn't get it from this repo, don't run it. If someone repackages this tool, it is not endorsed or supported.

## Liability Waiver

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.** By downloading, installing, or using C2Monitor, you acknowledge and agree to the following:

1. **No guarantee of protection.** C2Monitor is a supplementary detection tool. It does not replace professional security software, endpoint detection and response (EDR) solutions, or security services. No security tool can detect every threat.
2. **No liability.** The author(s) of C2Monitor shall not be held liable for any damages, losses, data breaches, security incidents, or consequences of any kind arising from the use or inability to use this software — including but not limited to missed detections, false positives, false negatives, system performance impact, or compatibility issues.
3. **Use at your own risk.** This tool runs with Administrator/SYSTEM privileges and installs Microsoft Sysmon. You are solely responsible for evaluating whether this tool is appropriate for your environment and for reviewing the source code before installation.
4. **Not professional security advice.** Alerts generated by C2Monitor are informational. They are not a substitute for professional incident response. If you believe you are under active attack, contact a qualified security professional or your local law enforcement cyber unit.

By using this software, you accept these terms. If you do not agree, do not install or use C2Monitor.

See [LICENSE](LICENSE) for full MIT license terms.

## License

MIT

Author: Wakony

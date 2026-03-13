# C2Monitor DevGuard v1.0.0
# Real-time blockchain C2 detection for development sessions.
# Watches for dev server processes (next dev, vite, npm run dev, etc.)
# and monitors their network activity for blockchain RPC calls.
#
# Runs as SYSTEM via scheduled task (at logon, persistent).
# When a dev server starts, DevGuard monitors it until the process exits.
# This closes the gap between the 5-min quick scan and 30-min deep scan
# by providing instant detection during the most vulnerable window:
# when build tools execute potentially compromised config files.
#
# Usage:
#   C2DevGuard.ps1                          — Persistent watcher mode (default)
#   C2DevGuard.ps1 -ProcessId 1234          — Monitor a specific dev process

param(
    [int]$ProcessId = 0,
    [string]$CommandLine = "",
    [string]$ImagePath = ""
)

#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

$LogDir = "C:\ProgramData\C2Monitor"
$AlertLog = Join-Path $LogDir "alerts.log"
$CooldownFile = Join-Path $LogDir "alert-cooldowns.json"
$ConfigFile = Join-Path $LogDir "config.json"
$DevGuardLog = Join-Path $LogDir "devguard.log"

$Config = $null
if (Test-Path $ConfigFile) { try { $Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json } catch {} }

$CooldownMinutes = if ($Config.scanning.alertCooldownMinutes) { $Config.scanning.alertCooldownMinutes } else { 60 }
$SuspiciousPaths = if ($Config.suspiciousPaths) { @($Config.suspiciousPaths) } else { @("\AppData\Local\Temp\","\Users\Public\","\Windows\Temp\") }

$BlockchainRpcDomains = if ($Config.blockchainRpcDomains) { @($Config.blockchainRpcDomains) } else {
    @("trongrid.io","tronstack.io","tronapi.com",
      "aptoslabs.com","aptos.dev",
      "bsc-dataseed.binance.org","bsc-rpc.publicnode.com","bscscan.com",
      "infura.io","alchemy.com","quicknode.com","cloudflare-eth.com",
      "solana.com","helius.dev","genesysgo.net",
      "api.avax.network","snowtrace.io",
      "polygonscan.com","polygon-rpc.com",
      "chainstack.com","getblock.io","ankr.com",
      "llamarpc.com","drpc.org")
}
$BlockchainTrustedProcs = if ($Config.blockchainTrustedProcesses) { @($Config.blockchainTrustedProcesses) } else {
    @("MetaMask","Exodus","Ledger Live","Phantom",
      "brave","opera",
      "firefox","chrome","msedge",
      "solflare","trust-wallet")
}

# Dev server command patterns — matched against Sysmon CommandLine
$DevServerPatterns = @(
    "next dev", "next start",
    "vite", "vite dev", "vite preview",
    "npm run dev", "npm run start", "npm run serve", "npm run build",
    "npx dev", "npx next", "npx vite", "npx nuxt",
    "pnpm dev", "pnpm run dev", "pnpm run start", "pnpm run build",
    "yarn dev", "yarn run dev", "yarn start", "yarn build",
    "nuxt dev", "nuxt build",
    "gatsby develop", "gatsby build",
    "remix dev",
    "astro dev", "astro build",
    "turbo run dev", "turbo run build",
    "bun run dev", "bun dev", "bun run build",
    "webpack serve", "webpack-dev-server",
    "ng serve", "ng build",
    "react-scripts start", "react-scripts build"
)

# Scan interval while monitoring a dev session (seconds)
$MonitorIntervalSec = if ($Config.devGuard.monitorIntervalSeconds) { $Config.devGuard.monitorIntervalSeconds } else { 15 }
# Max session duration to prevent runaway monitoring (hours)
$MaxSessionHours = if ($Config.devGuard.maxSessionHours) { $Config.devGuard.maxSessionHours } else { 12 }

# --- Utility Functions ---

function Write-DevGuardLog {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $DevGuardLog -Value "[$ts] $Message"
}

function Test-AlertCooldown {
    param([string]$AlertKey)
    $cooldowns = @{}
    if (Test-Path $CooldownFile) {
        try {
            $parsed = Get-Content $CooldownFile -Raw | ConvertFrom-Json
            foreach ($prop in $parsed.PSObject.Properties) { $cooldowns[$prop.Name] = $prop.Value }
        } catch {}
    }
    $cutoff = (Get-Date).AddMinutes(-$CooldownMinutes).ToString("o")
    $expired = @($cooldowns.Keys | Where-Object { $cooldowns[$_] -lt $cutoff })
    foreach ($k in $expired) { $cooldowns.Remove($k) }
    if ($cooldowns.ContainsKey($AlertKey) -and $cooldowns[$AlertKey] -gt $cutoff) { return $true }
    $cooldowns[$AlertKey] = (Get-Date).ToString("o")
    try { [System.IO.File]::WriteAllText($CooldownFile, ($cooldowns | ConvertTo-Json -Depth 3)) } catch {}
    return $false
}

function Write-DevGuardAlert {
    param([string]$Severity, [string]$Message, [string]$CooldownKey)
    if ($CooldownKey -and (Test-AlertCooldown -AlertKey $CooldownKey)) { return }
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Severity] $Message"
    Add-Content -Path $AlertLog -Value $line
    Write-DevGuardLog $line
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("C2Monitor")) {
            New-EventLog -LogName Application -Source "C2Monitor"
        }
        $et = if ($Severity -eq "CRITICAL") { "Error" } else { "Warning" }
        Write-EventLog -LogName Application -Source "C2Monitor" -EventId 1003 -EntryType $et -Message $line
    } catch {}
}

function Test-BlockchainDomain {
    param([string]$DomainName)
    if (-not $DomainName) { return $false }
    $lower = $DomainName.ToLower()
    foreach ($rpc in $BlockchainRpcDomains) {
        if ($lower -eq $rpc -or $lower -like "*.$rpc") { return $true }
    }
    return $false
}

function Get-ChildProcessIds {
    param([int]$ParentPid)
    $children = @()
    try {
        $wmiProcs = Get-WmiObject Win32_Process -Filter "ParentProcessId=$ParentPid" -ErrorAction SilentlyContinue
        foreach ($wp in $wmiProcs) {
            $children += $wp.ProcessId
            $children += Get-ChildProcessIds -ParentPid $wp.ProcessId
        }
    } catch {}
    return $children
}

# --- Mode 1: Event-triggered (called with -ProcessId) ---
# Monitors a specific dev server process and its children for blockchain RPC calls

function Watch-DevProcess {
    param([int]$ProcessId, [string]$CommandLine, [string]$ImagePath)

    Write-DevGuardLog "DevGuard activated: PID $ProcessId | Cmd: $CommandLine | Image: $ImagePath"

    $sessionStart = Get-Date
    $maxEnd = $sessionStart.AddHours($MaxSessionHours)

    while ((Get-Date) -lt $maxEnd) {
        # Check if the dev process is still running
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $proc) {
            Write-DevGuardLog "Dev process PID $ProcessId exited. DevGuard session ending."
            break
        }

        # Get all child PIDs (dev servers spawn child processes)
        $watchPids = @($ProcessId) + @(Get-ChildProcessIds -ParentPid $ProcessId)

        # Check Sysmon DNS queries from watched PIDs (last scan interval)
        $scanWindow = (Get-Date).AddSeconds(-($MonitorIntervalSec + 5))
        try {
            $dnsEvents = Get-WinEvent -FilterHashtable @{
                LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 22
                StartTime = $scanWindow
            } -MaxEvents 200 -ErrorAction SilentlyContinue

            foreach ($evt in $dnsEvents) {
                $xml = [xml]$evt.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
                $query = $data["QueryName"]; $img = $data["Image"]
                $evtPid = if ($data["ProcessId"]) { [int]$data["ProcessId"] } else { 0 }
                if (-not $query -or -not $img) { continue }

                # Only check events from the dev process tree
                if ($evtPid -notin $watchPids) { continue }

                if (Test-BlockchainDomain -DomainName $query) {
                    $procLeaf = Split-Path $img -Leaf
                    $hash = if ($img -and (Test-Path $img)) { (Get-FileHash $img -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "N/A" }
                    $ck = "$procLeaf|$query|DEVGUARD"

                    Write-DevGuardAlert -Severity "CRITICAL" -CooldownKey $ck `
                        -Message "BLOCKCHAIN C2 [DEVGUARD]: Dev server process queried blockchain RPC $query | Process: $procLeaf (PID $evtPid) | Parent dev PID: $ProcessId | File: $img | Cmd: $CommandLine | SHA256: $hash"
                }
            }
        } catch {}

        # Check Sysmon network connections from watched PIDs
        try {
            $netEvents = Get-WinEvent -FilterHashtable @{
                LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 3
                StartTime = $scanWindow
            } -MaxEvents 200 -ErrorAction SilentlyContinue

            foreach ($evt in $netEvents) {
                $xml = [xml]$evt.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
                $destHost = $data["DestinationHostname"]; $img = $data["Image"]
                $evtPid = if ($data["ProcessId"]) { [int]$data["ProcessId"] } else { 0 }
                if (-not $img) { continue }

                if ($evtPid -notin $watchPids) { continue }

                if ($destHost -and (Test-BlockchainDomain -DomainName $destHost)) {
                    $procLeaf = Split-Path $img -Leaf
                    $destIp = $data["DestinationIp"]
                    $destPort = if ($data["DestinationPort"]) { [int]$data["DestinationPort"] } else { 443 }
                    $hash = if ($img -and (Test-Path $img)) { (Get-FileHash $img -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "N/A" }
                    $ck = "$procLeaf|$destHost|DEVGUARD-NET"

                    Write-DevGuardAlert -Severity "CRITICAL" -CooldownKey $ck `
                        -Message "BLOCKCHAIN C2 [DEVGUARD]: Dev server connected to blockchain RPC $destHost ($destIp) | Process: $procLeaf (PID $evtPid) | Parent dev PID: $ProcessId | File: $img | Remote: ${destIp}:${destPort} | SHA256: $hash"
                }
            }
        } catch {}

        # Also check live TCP connections from watched PIDs against DNS cache
        try {
            $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
            $blockchainIps = @{}
            foreach ($entry in $dnsCache) {
                if ($entry.Entry -and $entry.Data -and (Test-BlockchainDomain -DomainName $entry.Entry)) {
                    $blockchainIps[$entry.Data] = $entry.Entry
                }
            }

            if ($blockchainIps.Count -gt 0) {
                foreach ($wPid in $watchPids) {
                    $pidConns = Get-NetTCPConnection -OwningProcess $wPid -State Established -ErrorAction SilentlyContinue
                    foreach ($conn in $pidConns) {
                        if ($blockchainIps.ContainsKey($conn.RemoteAddress)) {
                            $domain = $blockchainIps[$conn.RemoteAddress]
                            $wProc = Get-Process -Id $wPid -ErrorAction SilentlyContinue
                            $wPn = if ($wProc) { $wProc.ProcessName } else { "UNKNOWN" }
                            $wFp = if ($wProc) { $wProc.Path } else { "UNKNOWN" }
                            $wHash = if ($wFp -and (Test-Path $wFp)) { (Get-FileHash $wFp -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "N/A" }
                            $ck = "$wPn|$domain|DEVGUARD-LIVE"

                            Write-DevGuardAlert -Severity "CRITICAL" -CooldownKey $ck `
                                -Message "BLOCKCHAIN C2 [DEVGUARD]: Active dev connection to blockchain RPC $domain | Process: $wPn (PID $wPid) | Parent dev PID: $ProcessId | File: $wFp | Remote: $($conn.RemoteAddress):$($conn.RemotePort) | SHA256: $wHash"
                        }
                    }
                }
            }
        } catch {}

        Start-Sleep -Seconds $MonitorIntervalSec
    }

    Write-DevGuardLog "DevGuard session ended for PID $ProcessId (duration: $([math]::Round(((Get-Date) - $sessionStart).TotalMinutes, 1)) min)"
}

# --- Mode 2: Sysmon event subscription (persistent watcher) ---
# Subscribes to Sysmon process creation events and auto-launches Watch-DevProcess
# when a dev server starts. This is the primary mode.

function Start-DevGuardWatcher {
    Write-DevGuardLog "DevGuard watcher starting — monitoring for dev server launches"

    # Track active monitoring sessions to prevent duplicates
    $script:activeSessions = @{}

    # Poll Sysmon Event ID 1 (process creation) for dev server launches
    $lastCheck = Get-Date

    while ($true) {
        try {
            $procEvents = Get-WinEvent -FilterHashtable @{
                LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 1
                StartTime = $lastCheck
            } -MaxEvents 50 -ErrorAction SilentlyContinue

            $lastCheck = Get-Date

            foreach ($evt in $procEvents) {
                $xml = [xml]$evt.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
                $cmdLine = $data["CommandLine"]; $img = $data["Image"]
                $pid_ = if ($data["ProcessId"]) { [int]$data["ProcessId"] } else { 0 }
                if (-not $cmdLine -or -not $img -or $pid_ -eq 0) { continue }

                # Check if this command matches a dev server pattern
                $isDevServer = $false
                $lowerCmd = $cmdLine.ToLower()
                foreach ($pattern in $DevServerPatterns) {
                    if ($lowerCmd -like "*$pattern*") { $isDevServer = $true; break }
                }
                if (-not $isDevServer) { continue }

                # Skip if already monitoring this PID
                if ($script:activeSessions.ContainsKey($pid_)) { continue }

                # Verify process is still running
                $proc = Get-Process -Id $pid_ -ErrorAction SilentlyContinue
                if (-not $proc) { continue }

                Write-DevGuardLog "Dev server detected: PID $pid_ | Cmd: $cmdLine"
                $script:activeSessions[$pid_] = $true

                # Launch monitoring in a background job
                $scriptBlock = {
                    param($ScriptPath, $Pid_, $CmdLine, $ImgPath)
                    & $ScriptPath -ProcessId $Pid_ -CommandLine $CmdLine -ImagePath $ImgPath
                }
                Start-Job -ScriptBlock $scriptBlock -ArgumentList $PSCommandPath, $pid_, $cmdLine, $img | Out-Null
            }
        } catch {}

        # Clean up finished sessions
        $finished = @()
        foreach ($sPid in $script:activeSessions.Keys) {
            $p = Get-Process -Id $sPid -ErrorAction SilentlyContinue
            if (-not $p) { $finished += $sPid }
        }
        foreach ($f in $finished) { $script:activeSessions.Remove($f) }

        # Clean up completed jobs
        Get-Job -State Completed -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 5
    }
}

# --- Entry Point ---

if ($ProcessId -gt 0) {
    # Mode 1: Monitor a specific process (called by the watcher or event trigger)
    Watch-DevProcess -ProcessId $ProcessId -CommandLine $CommandLine -ImagePath $ImagePath
} else {
    # Mode 2: Persistent watcher — detect dev server launches and auto-monitor
    Start-DevGuardWatcher
}

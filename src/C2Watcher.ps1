# C2Monitor Quick Watcher v1.0.0
# This is the readable source for the quick scanner embedded in Install-C2Monitor.ps1.
# The installer deploys this to C:\ProgramData\C2Monitor\C2Watcher.ps1
# Runs every 5 minutes as SYSTEM via scheduled task.

#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

$LogDir = "C:\ProgramData\C2Monitor"
$AlertLog = Join-Path $LogDir "alerts.log"
$ThreatIntelFile = Join-Path $LogDir "threat-intel-ips.txt"
$CooldownFile = Join-Path $LogDir "alert-cooldowns.json"
$ConfigFile = Join-Path $LogDir "config.json"

$Config = $null
if (Test-Path $ConfigFile) { try { $Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json } catch {} }

$CooldownMinutes  = if ($Config.scanning.alertCooldownMinutes) { $Config.scanning.alertCooldownMinutes } else { 60 }
$C2Ports          = if ($Config.c2Ports) { @($Config.c2Ports) } else { @(4444,4445,5555,5556,8443,8888,1234,1337,2222,50050,50051,6666,6667,6697,9090,9999,4443,8880,7443) }
$TrustedProcesses = if ($Config.trustedProcesses) { @($Config.trustedProcesses) } else { @("svchost","System","Idle","firefox","chrome","msedge","explorer") }
$SuspiciousPaths  = if ($Config.suspiciousPaths) { @($Config.suspiciousPaths) } else { @("\AppData\Local\Temp\","\Users\Public\","\Windows\Temp\") }

$BlockchainRpcDomains     = if ($Config.blockchainRpcDomains) { @($Config.blockchainRpcDomains) } else {
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
$BlockchainTrustedProcs   = if ($Config.blockchainTrustedProcesses) { @($Config.blockchainTrustedProcesses) } else {
    @("MetaMask","Exodus","Ledger Live","Phantom",
      "brave","opera",
      "firefox","chrome","msedge",
      "solflare","trust-wallet")
}
$BuildToolProcessNames    = if ($Config.buildToolProcessNames) { @($Config.buildToolProcessNames) } else {
    @("node","npm","npx","pnpm","yarn",
      "next","vite","webpack","esbuild","turbo",
      "bun","deno","tsx","ts-node","rollup","parcel")
}
$BrowserProcesses = @("firefox","chrome","msedge","brave","opera","vivaldi","waterfox","librewolf","chromium","arc")

$knownC2IPs = @()
if (Test-Path $ThreatIntelFile) {
    $knownC2IPs = @(Get-Content $ThreatIntelFile | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" })
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

function Write-QuickAlert {
    param([string]$Severity, [string]$Message, [string]$CooldownKey)
    if ($CooldownKey -and (Test-AlertCooldown -AlertKey $CooldownKey)) { return }
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Severity] $Message"
    Add-Content -Path $AlertLog -Value $line
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("C2Monitor")) {
            New-EventLog -LogName Application -Source "C2Monitor"
        }
        $et = if ($Severity -eq "CRITICAL") { "Error" } else { "Warning" }
        Write-EventLog -LogName Application -Source "C2Monitor" -EventId 1002 -EntryType $et -Message $line
    } catch {}
}

$conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" }

foreach ($c in $conns) {
    $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    $pn = if ($proc) { $proc.ProcessName } else { "UNKNOWN" }
    $fp = if ($proc) { $proc.Path } else { "UNKNOWN" }
    if ($pn -in $TrustedProcesses) { continue }

    $ck = "$pn|$($c.RemoteAddress)"

    if ($c.RemoteAddress -in $knownC2IPs) {
        $hash = if ($fp -and (Test-Path $fp)) { (Get-FileHash $fp -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "N/A" }
        Write-QuickAlert -Severity "CRITICAL" -CooldownKey "$ck|C2IP" `
            -Message "KNOWN C2 IP (abuse.ch) | Process: $pn (PID $($c.OwningProcess)) | File: $fp | Remote: $($c.RemoteAddress):$($c.RemotePort) | SHA256: $hash"
    }
    if ($c.RemotePort -in $C2Ports) {
        Write-QuickAlert -Severity "HIGH" -CooldownKey "$ck|PORT" `
            -Message "C2 port $($c.RemotePort) | Process: $pn (PID $($c.OwningProcess)) | File: $fp | Remote: $($c.RemoteAddress)"
    }
    if ($fp -and $fp -ne "UNKNOWN") {
        foreach ($sp in $SuspiciousPaths) {
            if ($fp -like "*$sp*") {
                $sig = (Get-AuthenticodeSignature -FilePath $fp -ErrorAction SilentlyContinue).Status
                if ($sig -notin @("Valid")) {
                    Write-QuickAlert -Severity "HIGH" -CooldownKey "$ck|PATH" `
                        -Message "Unsigned from suspicious path | Process: $pn | File: $fp | Remote: $($c.RemoteAddress):$($c.RemotePort) | Sig: $sig"
                }
                break
            }
        }
    }
    if ($c.RemotePort -eq 3389) {
        Write-QuickAlert -Severity "CRITICAL" -CooldownKey "$ck|RDP" `
            -Message "Outbound RDP | Process: $pn | File: $fp | Remote: $($c.RemoteAddress)"
    }
}

# --- Blockchain C2 Quick Check ---
# Check DNS cache for blockchain RPC domains contacted by non-browser processes
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    foreach ($entry in $dnsCache) {
        $cacheName = $entry.Entry
        if (-not $cacheName) { continue }

        # Check if this DNS entry matches a blockchain RPC domain
        $isBlockchain = $false
        $lowerName = $cacheName.ToLower()
        foreach ($rpc in $BlockchainRpcDomains) {
            if ($lowerName -eq $rpc -or $lowerName -like "*.$rpc") { $isBlockchain = $true; break }
        }
        if (-not $isBlockchain) { continue }

        # Found a blockchain domain in DNS cache; check active connections for matching IPs
        $resolvedIps = @()
        if ($entry.Data) { $resolvedIps += $entry.Data }

        foreach ($rip in $resolvedIps) {
            $matchConns = Get-NetTCPConnection -RemoteAddress $rip -State Established -ErrorAction SilentlyContinue
            foreach ($mc in $matchConns) {
                $mProc = Get-Process -Id $mc.OwningProcess -ErrorAction SilentlyContinue
                $mPn = if ($mProc) { $mProc.ProcessName } else { "UNKNOWN" }
                $mFp = if ($mProc) { $mProc.Path } else { "UNKNOWN" }

                # Skip blockchain-trusted processes
                if ($mPn -in $BlockchainTrustedProcs) { continue }

                $mCk = "$mPn|$cacheName"
                $mHash = if ($mFp -and (Test-Path $mFp)) { (Get-FileHash $mFp -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "N/A" }

                # CRITICAL: Build tool process
                $isBuildTool = $false
                if ($mPn -in $BuildToolProcessNames) { $isBuildTool = $true }
                if ($mFp -and $mFp -like "*\node_modules\*") { $isBuildTool = $true }

                if ($isBuildTool) {
                    Write-QuickAlert -Severity "CRITICAL" -CooldownKey "$mCk|BLOCKCHAIN" `
                        -Message "BLOCKCHAIN C2: Build tool connected to blockchain RPC $cacheName | Process: $mPn (PID $($mc.OwningProcess)) | File: $mFp | Remote: $($rip):$($mc.RemotePort) | SHA256: $mHash"
                    continue
                }

                # CRITICAL: Suspicious path
                $isSuspicious = $false
                if ($mFp -and $mFp -ne "UNKNOWN") {
                    foreach ($sp in $SuspiciousPaths) {
                        if ($mFp -like "*$sp*") { $isSuspicious = $true; break }
                    }
                }

                if ($isSuspicious) {
                    Write-QuickAlert -Severity "CRITICAL" -CooldownKey "$mCk|BLOCKCHAIN" `
                        -Message "BLOCKCHAIN C2: Suspicious-path process connected to blockchain RPC $cacheName | Process: $mPn (PID $($mc.OwningProcess)) | File: $mFp | Remote: $($rip):$($mc.RemotePort) | SHA256: $mHash"
                    continue
                }

                # HIGH: Any other non-trusted process
                Write-QuickAlert -Severity "HIGH" -CooldownKey "$mCk|BLOCKCHAIN" `
                    -Message "BLOCKCHAIN C2: Non-browser process connected to blockchain RPC $cacheName | Process: $mPn (PID $($mc.OwningProcess)) | File: $mFp | Remote: $($rip):$($mc.RemotePort) | SHA256: $mHash"
            }
        }
    }
} catch {}

# Also do a quick Sysmon DNS check (last 5 minutes) for blockchain domains
try {
    $bcQuickDns = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 22
        StartTime = (Get-Date).AddMinutes(-5)
    } -MaxEvents 200 -ErrorAction SilentlyContinue

    foreach ($evt in $bcQuickDns) {
        $xml = [xml]$evt.ToXml()
        $data = @{}
        foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
        $query = $data["QueryName"]; $img = $data["Image"]
        if (-not $query -or -not $img) { continue }

        # Check if this is a blockchain RPC domain
        $isBlockchain = $false
        $lowerQuery = $query.ToLower()
        foreach ($rpc in $BlockchainRpcDomains) {
            if ($lowerQuery -eq $rpc -or $lowerQuery -like "*.$rpc") { $isBlockchain = $true; break }
        }
        if (-not $isBlockchain) { continue }

        $procName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $img -Leaf))
        $procLeaf = Split-Path $img -Leaf

        if ($procName -in $BlockchainTrustedProcs) { continue }

        $qHash = if ($img -and (Test-Path $img)) { (Get-FileHash $img -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "N/A" }
        $qCk = "$procName|$query"

        # Build tool = CRITICAL
        $isBuild = $false
        if ($procName -in $BuildToolProcessNames) { $isBuild = $true }
        if ($img -and $img -like "*\node_modules\*") { $isBuild = $true }

        if ($isBuild) {
            Write-QuickAlert -Severity "CRITICAL" -CooldownKey "$qCk|BLOCKCHAIN-DNS" `
                -Message "BLOCKCHAIN C2: Build tool queried blockchain RPC $query | Process: $procLeaf | File: $img | SHA256: $qHash"
            continue
        }

        # Suspicious path = CRITICAL
        $isSusp = $false
        foreach ($sp in $SuspiciousPaths) {
            if ($img -like "*$sp*") { $isSusp = $true; break }
        }

        if ($isSusp) {
            Write-QuickAlert -Severity "CRITICAL" -CooldownKey "$qCk|BLOCKCHAIN-DNS" `
                -Message "BLOCKCHAIN C2: Suspicious-path process queried blockchain RPC $query | Process: $procLeaf | File: $img | SHA256: $qHash"
            continue
        }

        # Non-trusted, non-browser = HIGH
        Write-QuickAlert -Severity "HIGH" -CooldownKey "$qCk|BLOCKCHAIN-DNS" `
            -Message "BLOCKCHAIN C2: Non-browser process queried blockchain RPC $query | Process: $procLeaf | File: $img | SHA256: $qHash"
    }
} catch {}

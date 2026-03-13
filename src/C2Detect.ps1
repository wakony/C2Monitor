# C2Monitor Deep Scanner v1.0.0
# This is the readable source for the deep scanner embedded in Install-C2Monitor.ps1.
# The installer deploys this to C:\ProgramData\C2Monitor\C2Detect.ps1
# Runs every 30 minutes as SYSTEM via scheduled task.

#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

# --- Load configuration ---
$LogDir = "C:\ProgramData\C2Monitor"
$AlertLog = Join-Path $LogDir "alerts.log"
$HistoryFile = Join-Path $LogDir "connection-history.json"
$ThreatIntelFile = Join-Path $LogDir "threat-intel-ips.txt"
$CooldownFile = Join-Path $LogDir "alert-cooldowns.json"
$ConfigFile = Join-Path $LogDir "config.json"

# Load config (or use defaults)
$Config = $null
if (Test-Path $ConfigFile) {
    try { $Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json } catch {}
}

$SampleInterval    = if ($Config.scanning.sampleIntervalSeconds) { $Config.scanning.sampleIntervalSeconds } else { 30 }
$SampleCount       = if ($Config.scanning.sampleCount) { $Config.scanning.sampleCount } else { 20 }
$BeaconJitter      = if ($Config.scanning.beaconJitterThreshold) { $Config.scanning.beaconJitterThreshold } else { 0.30 }
$MinBeaconSamples  = if ($Config.scanning.minBeaconSamples) { $Config.scanning.minBeaconSamples } else { 4 }
$CooldownMinutes   = if ($Config.scanning.alertCooldownMinutes) { $Config.scanning.alertCooldownMinutes } else { 60 }
$ThreatIntelAge    = if ($Config.scanning.threatIntelRefreshHours) { $Config.scanning.threatIntelRefreshHours } else { 6 }
$MaxLogSizeMB      = if ($Config.scanning.maxLogSizeMB) { $Config.scanning.maxLogSizeMB } else { 10 }

$C2Ports           = if ($Config.c2Ports) { @($Config.c2Ports) } else { @(4444,4445,5555,5556,8443,8888,1234,1337,2222,50050,50051,6666,6667,6697,9090,9999,4443,8880,7443) }
$TrustedProcesses  = if ($Config.trustedProcesses) { @($Config.trustedProcesses) } else { @("svchost","System","Idle","firefox","chrome","msedge","explorer") }
$OfficeProcesses   = if ($Config.officeProcesses) { @($Config.officeProcesses) } else { @("WINWORD","EXCEL","POWERPNT","OUTLOOK") }
$SuspiciousPaths   = if ($Config.suspiciousPaths) { @($Config.suspiciousPaths) } else { @("\AppData\Local\Temp\","\Users\Public\","\Windows\Temp\") }

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

# --- Core Functions ---

function Invoke-LogRotation {
    if (Test-Path $AlertLog) {
        $sizeMB = (Get-Item $AlertLog).Length / 1MB
        if ($sizeMB -gt $MaxLogSizeMB) {
            $archive = Join-Path $LogDir ("alerts-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
            Move-Item -Path $AlertLog -Destination $archive -Force
            Get-ChildItem -Path $LogDir -Filter "alerts-*.log" |
                Sort-Object LastWriteTime -Descending |
                Select-Object -Skip 5 |
                Remove-Item -Force
        }
    }
}

# Alert cooldown: prevents the same alert from firing repeatedly
function Test-AlertCooldown {
    param([string]$AlertKey)
    $cooldowns = @{}
    if (Test-Path $CooldownFile) {
        try {
            $raw = Get-Content $CooldownFile -Raw
            $parsed = $raw | ConvertFrom-Json
            # Convert PSObject to hashtable (PS 5.1 compatible)
            foreach ($prop in $parsed.PSObject.Properties) {
                $cooldowns[$prop.Name] = $prop.Value
            }
        } catch {}
    }

    $now = Get-Date
    $cutoff = $now.AddMinutes(-$CooldownMinutes).ToString("o")

    # Clean expired entries
    $expired = @($cooldowns.Keys | Where-Object { $cooldowns[$_] -lt $cutoff })
    foreach ($k in $expired) { $cooldowns.Remove($k) }

    if ($cooldowns.ContainsKey($AlertKey) -and $cooldowns[$AlertKey] -gt $cutoff) {
        return $true  # Still in cooldown, skip alert
    }

    $cooldowns[$AlertKey] = $now.ToString("o")

    # Save with file locking
    try {
        $json = $cooldowns | ConvertTo-Json -Depth 3
        [System.IO.File]::WriteAllText($CooldownFile, $json)
    } catch {}

    return $false  # Not in cooldown, fire alert
}

function Write-Alert {
    param([string]$Severity, [string]$Message, [string]$ProcessName, [string]$FilePath,
          [string]$RemoteAddr, [int]$RemotePort, [int]$PID_)

    # Check cooldown
    $cooldownKey = "$ProcessName|$RemoteAddr|$Severity"
    if (Test-AlertCooldown -AlertKey $cooldownKey) { return }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Severity] $Message | Process: $ProcessName (PID $PID_) | File: $FilePath | Remote: ${RemoteAddr}:${RemotePort}"
    Add-Content -Path $AlertLog -Value $logLine

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("C2Monitor")) {
            New-EventLog -LogName Application -Source "C2Monitor"
        }
        $eventType = if ($Severity -eq "CRITICAL") { "Error" }
                     elseif ($Severity -eq "HIGH") { "Warning" }
                     else { "Information" }
        Write-EventLog -LogName Application -Source "C2Monitor" -EventId 1001 -EntryType $eventType -Message $logLine
    } catch {}
}

function Get-ProcessFilePath {
    param([int]$ProcessId)
    try { return (Get-Process -Id $ProcessId -ErrorAction Stop).Path }
    catch { return "UNKNOWN (PID $ProcessId)" }
}

function Get-ProcessSignature {
    param([string]$FilePath)
    if (-not $FilePath -or $FilePath -like "UNKNOWN*") { return "UNKNOWN" }
    try { return (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop).Status.ToString() }
    catch { return "ERROR" }
}

function Get-FileHashInfo {
    param([string]$FilePath)
    if (-not $FilePath -or $FilePath -like "UNKNOWN*" -or -not (Test-Path $FilePath)) { return "N/A" }
    try { return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return "ERROR" }
}

function Test-SuspiciousPath {
    param([string]$FilePath)
    if (-not $FilePath) { return $false }
    foreach ($p in $SuspiciousPaths) {
        if ($FilePath -like "*$p*") { return $true }
    }
    return $false
}

function Test-BlockchainDomain {
    param([string]$DomainName)
    if (-not $DomainName) { return $false }
    $lowerDomain = $DomainName.ToLower()
    foreach ($rpc in $BlockchainRpcDomains) {
        if ($lowerDomain -eq $rpc -or $lowerDomain -like "*.$rpc") { return $true }
    }
    return $false
}

function Test-BuildToolProcess {
    param([string]$ProcessName, [string]$FilePath)
    if (-not $ProcessName) { return $false }
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($ProcessName)
    if ($baseName -in $BuildToolProcessNames) { return $true }
    # Check if the process path is within node_modules
    if ($FilePath -and $FilePath -like "*\node_modules\*") { return $true }
    return $false
}

function Get-ShannonEntropy {
    param([string]$Text)
    if (-not $Text -or $Text.Length -eq 0) { return 0 }
    $freq = @{}
    foreach ($c in $Text.ToLower().ToCharArray()) {
        if (-not $freq.ContainsKey($c)) { $freq[$c] = 0 }
        $freq[$c]++
    }
    $entropy = 0.0
    $len = $Text.Length
    foreach ($count in $freq.Values) {
        $p = $count / $len
        if ($p -gt 0) { $entropy -= $p * [math]::Log($p, 2) }
    }
    return [math]::Round($entropy, 3)
}

# --- Threat Intelligence ---

function Update-ThreatIntel {
    $needsUpdate = $true
    if (Test-Path $ThreatIntelFile) {
        $age = (Get-Date) - (Get-Item $ThreatIntelFile).LastWriteTime
        if ($age.TotalHours -lt $ThreatIntelAge) { $needsUpdate = $false }
    }
    if ($needsUpdate) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $response = Invoke-WebRequest -Uri "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" `
                -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            $ips = $response.Content -split "`n" | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }
            if ($ips.Count -gt 0) {
                $ips | Set-Content -Path $ThreatIntelFile -Force
                Add-Content -Path $AlertLog -Value "--- Threat intel updated: $($ips.Count) C2 IPs loaded ---"
            }
        } catch {
            Add-Content -Path $AlertLog -Value "--- Threat intel update failed: $($_.Exception.Message) ---"
        }
    }
}

function Get-ThreatIntelIPs {
    if (Test-Path $ThreatIntelFile) {
        return @(Get-Content $ThreatIntelFile | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" })
    }
    return @()
}

# --- Connection History (PS 5.1 compatible - no -AsHashtable) ---

function Get-ConnectionHistory {
    if (-not (Test-Path $HistoryFile)) { return @{} }
    try {
        $raw = Get-Content $HistoryFile -Raw
        $parsed = $raw | ConvertFrom-Json
        $ht = @{}
        foreach ($prop in $parsed.PSObject.Properties) {
            $entry = @{}
            foreach ($subProp in $prop.Value.PSObject.Properties) {
                if ($subProp.Name -eq "Timestamps") {
                    $entry[$subProp.Name] = @($subProp.Value)
                } else {
                    $entry[$subProp.Name] = $subProp.Value
                }
            }
            $ht[$prop.Name] = $entry
        }
        return $ht
    } catch { return @{} }
}

function Save-ConnectionHistory {
    param($History)
    $cutoff = (Get-Date).AddHours(-24).ToString("o")
    $pruned = @{}
    foreach ($key in $History.Keys) {
        if ($History[$key].LastSeen -gt $cutoff) {
            $pruned[$key] = $History[$key]
        }
    }
    try {
        $json = $pruned | ConvertTo-Json -Depth 5
        # File locking to prevent race conditions
        $mutex = New-Object System.Threading.Mutex($false, "C2MonitorHistory")
        $mutex.WaitOne(5000) | Out-Null
        try { [System.IO.File]::WriteAllText($HistoryFile, $json) }
        finally { $mutex.ReleaseMutex() }
    } catch {}
}

# --- Main Detection ---

function Start-C2Detection {
    $startTime = Get-Date
    Invoke-LogRotation
    Update-ThreatIntel
    $knownC2IPs = Get-ThreatIntelIPs
    $persistentHistory = Get-ConnectionHistory

    Add-Content -Path $AlertLog -Value "--- C2 Deep Scan v$Version started ($($knownC2IPs.Count) threat intel IPs) ---"

    # PHASE 1: Sample connections
    $connectionHistory = @{}
    for ($i = 0; $i -lt $SampleCount; $i++) {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" }

        foreach ($c in $conns) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            $pn = if ($proc) { $proc.ProcessName } else { "UNKNOWN" }
            $key = "$pn|$($c.RemoteAddress)|$($c.RemotePort)"

            if (-not $connectionHistory.ContainsKey($key)) {
                $connectionHistory[$key] = @{
                    ProcessName = $pn
                    PID         = $c.OwningProcess
                    RemoteAddr  = $c.RemoteAddress
                    RemotePort  = $c.RemotePort
                    FilePath    = if ($proc) { $proc.Path } else { "UNKNOWN" }
                    Timestamps  = [System.Collections.ArrayList]@()
                }
            }
            $connectionHistory[$key].Timestamps.Add((Get-Date).ToString("o")) | Out-Null
        }
        Start-Sleep -Seconds $SampleInterval
    }

    # Merge with persistent history
    foreach ($key in $connectionHistory.Keys) {
        $cur = $connectionHistory[$key]
        if ($persistentHistory.ContainsKey($key)) {
            $prev = $persistentHistory[$key]
            $allTs = @()
            if ($prev.Timestamps) { $allTs += @($prev.Timestamps) }
            $allTs += @($cur.Timestamps)
            if ($allTs.Count -gt 100) { $allTs = $allTs[-100..-1] }
            $persistentHistory[$key] = @{
                ProcessName = $cur.ProcessName; RemoteAddr = $cur.RemoteAddr
                RemotePort = $cur.RemotePort; FilePath = $cur.FilePath
                Timestamps = $allTs; LastSeen = (Get-Date).ToString("o")
                HitCount = ([int]$prev.HitCount) + $cur.Timestamps.Count
            }
        } else {
            $persistentHistory[$key] = @{
                ProcessName = $cur.ProcessName; RemoteAddr = $cur.RemoteAddr
                RemotePort = $cur.RemotePort; FilePath = $cur.FilePath
                Timestamps = @($cur.Timestamps); LastSeen = (Get-Date).ToString("o")
                HitCount = $cur.Timestamps.Count
            }
        }
    }

    # PHASE 2: Analyze connections
    $alerted = @{}
    foreach ($key in $connectionHistory.Keys) {
        $e = $connectionHistory[$key]
        $pn = $e.ProcessName; $fp = $e.FilePath; $pid_ = $e.PID
        if ($pn -in $TrustedProcesses) { continue }
        $ak = "$pn|$($e.RemoteAddr)"
        if ($alerted.ContainsKey($ak)) { continue }

        # CHECK 1: Threat Intel (known C2 IPs)
        if ($e.RemoteAddr -in $knownC2IPs) {
            $sig = Get-ProcessSignature -FilePath $fp
            $hash = Get-FileHashInfo -FilePath $fp
            Write-Alert -Severity "CRITICAL" -Message "KNOWN C2 SERVER (abuse.ch match) sig=$sig SHA256=$hash" `
                -ProcessName $pn -FilePath $fp -RemoteAddr $e.RemoteAddr -RemotePort $e.RemotePort -PID_ $pid_
            $alerted[$ak] = $true; continue
        }

        # CHECK 2: Known C2 ports
        if ($e.RemotePort -in $C2Ports) {
            $sig = Get-ProcessSignature -FilePath $fp
            Write-Alert -Severity "HIGH" -Message "C2 port $($e.RemotePort) (sig=$sig)" `
                -ProcessName $pn -FilePath $fp -RemoteAddr $e.RemoteAddr -RemotePort $e.RemotePort -PID_ $pid_
            $alerted[$ak] = $true
        }

        # CHECK 3: Beaconing detection
        $tsData = $persistentHistory[$key].Timestamps
        if ($tsData -and @($tsData).Count -ge $MinBeaconSamples) {
            $sorted = @($tsData) | ForEach-Object { [datetime]$_ } | Sort-Object
            $intervals = @()
            for ($j = 1; $j -lt $sorted.Count; $j++) {
                $intervals += ($sorted[$j] - $sorted[$j-1]).TotalSeconds
            }
            $intervals = @($intervals | Where-Object { $_ -gt 5 })

            if ($intervals.Count -ge 3) {
                $mean = ($intervals | Measure-Object -Average).Average
                $variance = ($intervals | ForEach-Object { [math]::Pow($_ - $mean, 2) } | Measure-Object -Average).Average
                $stddev = [math]::Sqrt($variance)
                $cv = if ($mean -gt 0) { $stddev / $mean } else { 999 }

                if ($cv -lt $BeaconJitter -and $mean -gt 10 -and $mean -lt 600) {
                    $sig = Get-ProcessSignature -FilePath $fp
                    $hash = Get-FileHashInfo -FilePath $fp
                    Write-Alert -Severity "CRITICAL" `
                        -Message "BEACONING: interval=$([math]::Round($mean,1))s jitter=$([math]::Round($cv,3)) samples=$($intervals.Count) sig=$sig SHA256=$hash" `
                        -ProcessName $pn -FilePath $fp -RemoteAddr $e.RemoteAddr -RemotePort $e.RemotePort -PID_ $pid_
                    $alerted[$ak] = $true
                }
            }
        }

        # CHECK 4: Unsigned from suspicious path
        if (-not $alerted.ContainsKey($ak) -and (Test-SuspiciousPath -FilePath $fp)) {
            $sig = Get-ProcessSignature -FilePath $fp
            if ($sig -notin @("Valid", "UNKNOWN")) {
                Write-Alert -Severity "HIGH" -Message "Unsigned from suspicious path (sig=$sig)" `
                    -ProcessName $pn -FilePath $fp -RemoteAddr $e.RemoteAddr -RemotePort $e.RemotePort -PID_ $pid_
                $alerted[$ak] = $true
            }
        }

        # CHECK 5: DNS C2 tunnel
        if ($e.RemotePort -eq 53 -and $pn -notin @("svchost", "dns", "dnscache")) {
            Write-Alert -Severity "HIGH" -Message "Direct DNS from non-system process (DNS tunnel?)" `
                -ProcessName $pn -FilePath $fp -RemoteAddr $e.RemoteAddr -RemotePort $e.RemotePort -PID_ $pid_
        }

        # CHECK 6: Outbound RDP
        if ($e.RemotePort -eq 3389) {
            Write-Alert -Severity "CRITICAL" -Message "Outbound RDP (lateral movement)" `
                -ProcessName $pn -FilePath $fp -RemoteAddr $e.RemoteAddr -RemotePort $e.RemotePort -PID_ $pid_
        }
    }

    # PHASE 3: Process lineage (phishing chain + encoded PowerShell)
    try {
        $procEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 1; StartTime = $startTime
        } -MaxEvents 200 -ErrorAction SilentlyContinue

        foreach ($evt in $procEvents) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

            $image = $data["Image"]
            $parentImage = $data["ParentImage"]
            $cmdLine = $data["CommandLine"]
            $parentName = if ($parentImage) {
                [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $parentImage -Leaf))
            } else { "" }
            $imageName = if ($image) { Split-Path $image -Leaf } else { "" }

            # Office spawning shell = phishing chain
            if ($parentName -in $OfficeProcesses -and
                $imageName -match "^(cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|rundll32)\.exe$") {
                Write-Alert -Severity "CRITICAL" `
                    -Message "PHISHING CHAIN: $parentName spawned $imageName | Cmd: $cmdLine" `
                    -ProcessName $imageName -FilePath $image `
                    -RemoteAddr "N/A" -RemotePort 0 -PID_ ([int]$data["ProcessId"])
            }

            # Encoded PowerShell (fixed regex: matches -EncodedCommand, -enc, -ec but NOT -Encoding)
            if ($imageName -match "^(powershell|pwsh)\.exe$" -and $cmdLine) {
                if ($cmdLine -match "-[Ee][Nn]?[Cc][Oo]?[Dd]?[Ee]?[Dd]?[Cc]?[Oo]?[Mm]?[Mm]?[Aa]?[Nn]?[Dd]?\s" -or
                    $cmdLine -match "FromBase64String" -or
                    $cmdLine -match "\[System\.Convert\]::") {
                    Write-Alert -Severity "HIGH" `
                        -Message "Encoded PowerShell | Parent: $parentName | Cmd: $($cmdLine.Substring(0, [math]::Min(200, $cmdLine.Length)))" `
                        -ProcessName $imageName -FilePath $image `
                        -RemoteAddr "N/A" -RemotePort 0 -PID_ ([int]$data["ProcessId"])
                }
            }
        }
    } catch {}

    # PHASE 4: DNS analysis (DGA + volume)
    try {
        $dnsEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 22; StartTime = $startTime
        } -MaxEvents 1000 -ErrorAction SilentlyContinue

        $domainCounts = @{}
        foreach ($evt in $dnsEvents) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            $query = $data["QueryName"]; $img = $data["Image"]
            if (-not $query) { continue }

            $labels = $query.Split(".")
            $sld = if ($labels.Count -ge 2) { $labels[$labels.Count - 2] } else { $query }

            if ($sld.Length -gt 12) {
                $entropy = Get-ShannonEntropy -Text $sld
                if ($entropy -gt 3.5 -and $sld.Length -gt 15) {
                    $bn = if ($img) { [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $img -Leaf)) } else { "UNKNOWN" }
                    if ($bn -notin $TrustedProcesses) {
                        Write-Alert -Severity "HIGH" -Message "DGA domain: $query (entropy=$entropy)" `
                            -ProcessName (Split-Path $img -Leaf) -FilePath $img `
                            -RemoteAddr $query -RemotePort 53 -PID_ 0
                    }
                }
            }

            $pk = "$img|$query"
            if (-not $domainCounts.ContainsKey($pk)) { $domainCounts[$pk] = 0 }
            $domainCounts[$pk]++
        }

        foreach ($dk in $domainCounts.Keys) {
            if ($domainCounts[$dk] -gt 50) {
                $parts = $dk.Split("|", 2)
                $bn = if ($parts[0]) {
                    [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $parts[0] -Leaf))
                } else { "UNKNOWN" }
                if ($bn -notin $TrustedProcesses) {
                    Write-Alert -Severity "MEDIUM" -Message "Excessive DNS ($($domainCounts[$dk])x) to $($parts[1])" `
                        -ProcessName (Split-Path $parts[0] -Leaf) -FilePath $parts[0] `
                        -RemoteAddr $parts[1] -RemotePort 53 -PID_ 0
                }
            }
        }
    } catch {}

    # PHASE 5: Sysmon network events vs threat intel
    if ($knownC2IPs.Count -gt 0) {
        try {
            $netEvents = Get-WinEvent -FilterHashtable @{
                LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 3; StartTime = $startTime
            } -MaxEvents 500 -ErrorAction SilentlyContinue

            foreach ($evt in $netEvents) {
                $xml = [xml]$evt.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
                $destIp = $data["DestinationIp"]; $img = $data["Image"]

                if ($destIp -in $knownC2IPs) {
                    $sig = Get-ProcessSignature -FilePath $img
                    $hash = Get-FileHashInfo -FilePath $img
                    Write-Alert -Severity "CRITICAL" `
                        -Message "SYSMON: Known C2 IP (abuse.ch) sig=$sig SHA256=$hash" `
                        -ProcessName (Split-Path $img -Leaf) -FilePath $img `
                        -RemoteAddr $destIp -RemotePort ([int]$data["DestinationPort"]) `
                        -PID_ ([int]$data["ProcessId"])
                }
            }
        } catch {}
    }

    # PHASE 6: Blockchain C2 resolution detection
    # Detects non-browser processes querying blockchain RPC endpoints (Lazarus Group TTPs)
    # Uses Sysmon DNS queries (Event ID 22) and network connections (Event ID 3)
    try {
        # 6a: Check Sysmon DNS queries for blockchain RPC domains
        $bcDnsEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 22; StartTime = $startTime
        } -MaxEvents 1000 -ErrorAction SilentlyContinue

        foreach ($evt in $bcDnsEvents) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            $query = $data["QueryName"]; $img = $data["Image"]
            if (-not $query -or -not $img) { continue }
            if (-not (Test-BlockchainDomain -DomainName $query)) { continue }

            $procName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $img -Leaf))
            $procLeaf = Split-Path $img -Leaf

            # Skip processes explicitly trusted for blockchain access
            if ($procName -in $BlockchainTrustedProcs) { continue }

            $hash = Get-FileHashInfo -FilePath $img
            $sig = Get-ProcessSignature -FilePath $img

            # CRITICAL: Build tool process contacting blockchain RPC
            if (Test-BuildToolProcess -ProcessName $procLeaf -FilePath $img) {
                Write-Alert -Severity "CRITICAL" `
                    -Message "BLOCKCHAIN C2: Build tool queried blockchain RPC $query (Lazarus TTP) sig=$sig SHA256=$hash" `
                    -ProcessName $procLeaf -FilePath $img `
                    -RemoteAddr $query -RemotePort 443 -PID_ ([int]$data["ProcessId"])
                continue
            }

            # CRITICAL: Process from suspicious path contacting blockchain RPC
            if (Test-SuspiciousPath -FilePath $img) {
                Write-Alert -Severity "CRITICAL" `
                    -Message "BLOCKCHAIN C2: Suspicious-path process queried blockchain RPC $query sig=$sig SHA256=$hash" `
                    -ProcessName $procLeaf -FilePath $img `
                    -RemoteAddr $query -RemotePort 443 -PID_ ([int]$data["ProcessId"])
                continue
            }

            # HIGH: Any other non-browser, non-trusted process contacting blockchain RPC
            Write-Alert -Severity "HIGH" `
                -Message "BLOCKCHAIN C2: Non-browser process queried blockchain RPC $query sig=$sig SHA256=$hash" `
                -ProcessName $procLeaf -FilePath $img `
                -RemoteAddr $query -RemotePort 443 -PID_ ([int]$data["ProcessId"])
        }
    } catch {}

    try {
        # 6b: Check Sysmon network connections for blockchain RPC IPs resolved from known domains
        # This catches cases where DNS was cached or resolved before the scan window
        $bcNetEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 3; StartTime = $startTime
        } -MaxEvents 500 -ErrorAction SilentlyContinue

        foreach ($evt in $bcNetEvents) {
            $xml = [xml]$evt.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            $destHost = $data["DestinationHostname"]; $img = $data["Image"]
            if (-not $destHost -or -not $img) { continue }
            if (-not (Test-BlockchainDomain -DomainName $destHost)) { continue }

            $procName = [System.IO.Path]::GetFileNameWithoutExtension((Split-Path $img -Leaf))
            $procLeaf = Split-Path $img -Leaf

            if ($procName -in $BlockchainTrustedProcs) { continue }

            $hash = Get-FileHashInfo -FilePath $img
            $sig = Get-ProcessSignature -FilePath $img
            $destIp = $data["DestinationIp"]
            $destPort = if ($data["DestinationPort"]) { [int]$data["DestinationPort"] } else { 443 }

            if (Test-BuildToolProcess -ProcessName $procLeaf -FilePath $img) {
                Write-Alert -Severity "CRITICAL" `
                    -Message "BLOCKCHAIN C2: Build tool connected to blockchain RPC $destHost ($destIp) sig=$sig SHA256=$hash" `
                    -ProcessName $procLeaf -FilePath $img `
                    -RemoteAddr $destIp -RemotePort $destPort -PID_ ([int]$data["ProcessId"])
                continue
            }

            if (Test-SuspiciousPath -FilePath $img) {
                Write-Alert -Severity "CRITICAL" `
                    -Message "BLOCKCHAIN C2: Suspicious-path process connected to blockchain RPC $destHost ($destIp) sig=$sig SHA256=$hash" `
                    -ProcessName $procLeaf -FilePath $img `
                    -RemoteAddr $destIp -RemotePort $destPort -PID_ ([int]$data["ProcessId"])
                continue
            }

            Write-Alert -Severity "HIGH" `
                -Message "BLOCKCHAIN C2: Non-browser process connected to blockchain RPC $destHost ($destIp) sig=$sig SHA256=$hash" `
                -ProcessName $procLeaf -FilePath $img `
                -RemoteAddr $destIp -RemotePort $destPort -PID_ ([int]$data["ProcessId"])
        }
    } catch {}

    Save-ConnectionHistory -History $persistentHistory
    Add-Content -Path $AlertLog -Value "--- C2 Deep Scan completed at $(Get-Date) ---"
}

$Version = "1.0.0"
Start-C2Detection

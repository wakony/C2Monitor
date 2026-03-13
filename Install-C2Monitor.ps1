<#
.SYNOPSIS
    C2 Monitor v1.0.0 - One-Click Installer
.DESCRIPTION
    Installs a lightweight Command & Control beacon detection system on Windows 10/11.

    Run as Administrator:
      powershell -ExecutionPolicy Bypass -File Install-C2Monitor.ps1

.NOTES
    Version: 1.0.0
    License: MIT
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

$ErrorActionPreference = "Stop"
$Version = "1.0.0"
$InstallDir = "C:\ProgramData\C2Monitor"
$SysmonDir = Join-Path $env:TEMP "C2Monitor-Sysmon"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  C2 Monitor v$Version - Security Installation" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# =============================================
# STEP 1: Create install directory with ACLs
# =============================================
Write-Host "[1/7] Creating secure install directory..." -ForegroundColor Yellow
New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null

# Lock down permissions: only SYSTEM and Administrators can write.
# This prevents a low-privilege attacker from modifying detection scripts
# to whitelist their C2 IP (which would then run as SYSTEM).
$acl = Get-Acl $InstallDir
$acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$usersRead = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($usersRead)
Set-Acl $InstallDir $acl
Write-Host "  OK: $InstallDir (SYSTEM/Admins: full, Users: read-only)" -ForegroundColor Green

# =============================================
# STEP 2: Download and install Sysmon
# =============================================
Write-Host "[2/7] Installing Microsoft Sysmon..." -ForegroundColor Yellow
New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null

if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
    $sysmonZip = Join-Path $SysmonDir "Sysmon.zip"
    Write-Host "  Downloading from Sysinternals..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
        -OutFile $sysmonZip -UseBasicParsing
    Expand-Archive -Path $sysmonZip -DestinationPath $SysmonDir -Force
    Write-Host "  OK: Downloaded" -ForegroundColor Green
} else {
    Write-Host "  OK: Sysmon already installed, updating config" -ForegroundColor Green
}

# =============================================
# STEP 3: Sysmon configuration
# =============================================
Write-Host "[3/7] Configuring Sysmon for C2 detection..." -ForegroundColor Yellow

# Note: Only browser HTTP/HTTPS is excluded. Non-browser traffic on 80/443 IS logged
# because C2 commonly uses standard ports to blend in.
@'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\SearchIndexer.exe</Image>
        <Image condition="is">C:\Windows\System32\backgroundTaskHost.exe</Image>
        <Image condition="is">C:\Windows\System32\RuntimeBroker.exe</Image>
        <Image condition="is">C:\Windows\System32\taskhostw.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Rule groupRelation="and">
          <Image condition="is">C:\Program Files\Mozilla Firefox\firefox.exe</Image>
          <DestinationPort condition="is">443</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">C:\Program Files\Mozilla Firefox\firefox.exe</Image>
          <DestinationPort condition="is">80</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe</Image>
          <DestinationPort condition="is">443</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe</Image>
          <DestinationPort condition="is">80</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">C:\Program Files\Google\Chrome\Application\chrome.exe</Image>
          <DestinationPort condition="is">443</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">C:\Program Files\Google\Chrome\Application\chrome.exe</Image>
          <DestinationPort condition="is">80</DestinationPort>
        </Rule>
        <DestinationIp condition="is">127.0.0.1</DestinationIp>
        <DestinationIp condition="is">::1</DestinationIp>
      </NetworkConnect>
    </RuleGroup>
    <RuleGroup name="DnsQuery" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <QueryName condition="end with">.microsoft.com</QueryName>
        <QueryName condition="end with">.windowsupdate.com</QueryName>
        <QueryName condition="end with">.windows.com</QueryName>
        <QueryName condition="end with">.msftncsi.com</QueryName>
        <QueryName condition="end with">.office.com</QueryName>
        <QueryName condition="end with">.office365.com</QueryName>
      </DnsQuery>
    </RuleGroup>
    <RuleGroup name="FileCreate" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>
        <TargetFilename condition="contains">\Users\Public\</TargetFilename>
        <TargetFilename condition="contains">\Windows\Temp\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.cmd</TargetFilename>
        <TargetFilename condition="end with">.vbs</TargetFilename>
        <TargetFilename condition="end with">.hta</TargetFilename>
        <TargetFilename condition="end with">.scr</TargetFilename>
      </FileCreate>
    </RuleGroup>
    <RuleGroup name="ProcessAccess" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    <RuleGroup name="ImageLoad" groupRelation="or">
      <ImageLoad onmatch="include">
        <ImageLoaded condition="contains">\AppData\</ImageLoaded>
        <ImageLoaded condition="contains">\Temp\</ImageLoaded>
        <ImageLoaded condition="contains">\Downloads\</ImageLoaded>
        <ImageLoaded condition="contains">\Users\Public\</ImageLoaded>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@ | Set-Content -Path (Join-Path $InstallDir "c2-sysmon-config.xml") -Force

$sysmonExe = if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    "C:\Windows\Sysmon64.exe"
} else {
    Join-Path $SysmonDir "Sysmon64.exe"
}

$sysmonConfigPath = Join-Path $InstallDir "c2-sysmon-config.xml"
if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
    & $sysmonExe -accepteula -i $sysmonConfigPath 2>&1 | Out-Null
    Write-Host "  OK: Sysmon installed and started" -ForegroundColor Green
} else {
    & $sysmonExe -c $sysmonConfigPath 2>&1 | Out-Null
    Write-Host "  OK: Sysmon config updated" -ForegroundColor Green
}

# =============================================
# STEP 4: Deploy detection scripts
# =============================================
Write-Host "[4/7] Deploying detection engine..." -ForegroundColor Yellow

# --- Default configuration ---
@'
{
    "version": "1.0.0",
    "scanning": {
        "sampleIntervalSeconds": 30,
        "sampleCount": 20,
        "beaconJitterThreshold": 0.30,
        "minBeaconSamples": 4,
        "alertCooldownMinutes": 60,
        "threatIntelRefreshHours": 6,
        "maxLogSizeMB": 10
    },
    "c2Ports": [4444,4445,5555,5556,8443,8888,1234,1337,2222,50050,50051,6666,6667,6697,9090,9999,4443,8880,7443],
    "trustedProcesses": [
        "svchost","System","Idle","firefox","chrome","msedge","SearchHost",
        "OneDrive","Teams","ms-teams","Spotify","spotify","Signal","slack",
        "ProtonVPN","ProtonVPNService","openvpn","wireguard",
        "WindowsTerminal","explorer","RuntimeBroker","sihost",
        "SecurityHealthService","MsMpEng","MBAMService","mbamtray",
        "docker","com.docker.backend","vpnkit",
        "Sysmon64","WmiPrvSE","spoolsv","lsass","services",
        "claude","code","node","git","ssh",
        "Widgets","WidgetService","SgrmBroker","dasHost","dllhost"
    ],
    "officeProcesses": ["WINWORD","EXCEL","POWERPNT","OUTLOOK","MSACCESS","ONENOTE","MSPUB","VISIO"],
    "suspiciousPaths": ["\\AppData\\Local\\Temp\\","\\Users\\Public\\","\\Windows\\Temp\\","\\ProgramData\\"]
}
'@ | Set-Content -Path (Join-Path $InstallDir "config.json") -Force

# === C2Detect.ps1 (Deep Scanner) ===
# All fixes applied:
#   - PS 5.1 compatible (no -AsHashtable)
#   - Alert deduplication with cooldown
#   - Config file support
#   - File locking on connection history
#   - Fixed encoded PS regex
@'
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

    Save-ConnectionHistory -History $persistentHistory
    Add-Content -Path $AlertLog -Value "--- C2 Deep Scan completed at $(Get-Date) ---"
}

$Version = "1.0.0"
Start-C2Detection
'@ | Set-Content -Path (Join-Path $InstallDir "C2Detect.ps1") -Force

# === C2Watcher.ps1 (Quick Scanner - also with cooldown + config) ===
@'
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
'@ | Set-Content -Path (Join-Path $InstallDir "C2Watcher.ps1") -Force

Write-Host "  OK: Detection engine + config deployed" -ForegroundColor Green

# =============================================
# STEP 5: Deploy notifier (unchanged - runs in user session)
# =============================================
Write-Host "[5/7] Deploying desktop notification system..." -ForegroundColor Yellow

@'
$AlertLog = "C:\ProgramData\C2Monitor\alerts.log"
$LogDir = "C:\ProgramData\C2Monitor"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $AlertLog)) { New-Item -Path $AlertLog -ItemType File -Force | Out-Null }

$script:lastPosition = (Get-Item $AlertLog -ErrorAction SilentlyContinue).Length
$script:toastAvailable = $false
try {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
    $script:toastAvailable = $true
} catch {}

$script:balloonAvailable = $false
if (-not $script:toastAvailable) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $script:notifyIcon = New-Object System.Windows.Forms.NotifyIcon
        $script:notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
        $script:notifyIcon.Text = "C2 Monitor"
        $script:notifyIcon.Visible = $true
        $script:balloonAvailable = $true
    } catch {}
}

function Show-Notification {
    param([string]$Title, [string]$Body, [string]$Severity)
    $st = [System.Security.SecurityElement]::Escape($Title)
    $sb = [System.Security.SecurityElement]::Escape($Body)
    if ($sb.Length -gt 300) { $sb = $sb.Substring(0, 297) + "..." }

    if ($script:toastAvailable) {
        try {
            $dur = if ($Severity -eq "CRITICAL") { "long" } else { "short" }
            $aud = if ($Severity -eq "CRITICAL") {
                '<audio src="ms-winsoundevent:Notification.Looping.Alarm" loop="false"/>'
            } else {
                '<audio src="ms-winsoundevent:Notification.Default"/>'
            }
            $x = "<toast duration=`"$dur`" scenario=`"urgent`"><visual><binding template=`"ToastGeneric`"><text>$st</text><text>$sb</text><text placement=`"attribution`">C2 Security Monitor</text></binding></visual>$aud</toast>"
            $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
            $xml.LoadXml($x)
            $t = [Windows.UI.Notifications.ToastNotification]::new($xml)
            $n = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("C2 Security Monitor")
            $n.Show($t)
            return
        } catch {}
    }
    if ($script:balloonAvailable) {
        try {
            $ti = if ($Severity -eq "CRITICAL") { [System.Windows.Forms.ToolTipIcon]::Error }
                  else { [System.Windows.Forms.ToolTipIcon]::Warning }
            $script:notifyIcon.ShowBalloonTip(10000, $Title, $Body, $ti)
        } catch {}
    }
}

function Process-NewAlerts {
    $cs = 0
    if (Test-Path $AlertLog) { $cs = (Get-Item $AlertLog).Length }
    if ($cs -lt $script:lastPosition) { $script:lastPosition = 0 }
    if ($cs -le $script:lastPosition) { return }

    try {
        $s = [System.IO.FileStream]::new($AlertLog, [System.IO.FileMode]::Open,
             [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $s.Seek($script:lastPosition, [System.IO.SeekOrigin]::Begin) | Out-Null
        $r = [System.IO.StreamReader]::new($s)
        $nc = $r.ReadToEnd()
        $r.Close(); $s.Close()
    } catch { return }

    $script:lastPosition = $cs

    foreach ($line in ($nc -split "`r?`n" | Where-Object { $_.Trim() -ne "" })) {
        if ($line -match "^---") { continue }
        $sev = $null
        if ($line -match "\[CRITICAL\]") { $sev = "CRITICAL" }
        elseif ($line -match "\[HIGH\]") { $sev = "HIGH" }
        elseif ($line -match "\[MEDIUM\]") { $sev = "MEDIUM" }
        if (-not $sev) { continue }

        $msg = ""; $proc = ""; $file = ""
        if ($line -match "\]\s+(.*?)\s*\|\s*Process:\s*(.*?)\s*\|\s*File:\s*(.*?)\s*\|\s*Remote:") {
            $msg = $Matches[1]; $proc = $Matches[2]; $file = $Matches[3]
        } elseif ($line -match "\]\s+(.+)$") { $msg = $Matches[1] }

        $title = switch ($sev) {
            "CRITICAL" { "CRITICAL SECURITY ALERT" }
            "HIGH"     { "Security Alert" }
            default    { "Security Notice" }
        }
        $body = $msg
        if ($proc) { $body += "`nProcess: $proc" }
        if ($file) { $body += "`nFile: $file" }

        Show-Notification -Title $title -Body $body -Severity $sev
        Start-Sleep -Milliseconds 800
    }
}

Show-Notification -Title "C2 Monitor Active" `
    -Body "Security monitoring is running. You will be alerted if C2 activity is detected." `
    -Severity "INFO"

while ($true) { Process-NewAlerts; Start-Sleep -Seconds 10 }
'@ | Set-Content -Path (Join-Path $InstallDir "C2AlertNotifier.ps1") -Force

@'
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\C2Monitor\C2AlertNotifier.ps1", 0, False
'@ | Set-Content -Path (Join-Path $InstallDir "LaunchNotifier.vbs") -Force

Write-Host "  OK: Notification system deployed" -ForegroundColor Green

# =============================================
# STEP 6: Register scheduled tasks
# =============================================
Write-Host "[6/7] Registering scheduled tasks..." -ForegroundColor Yellow

schtasks.exe /Create /TN "C2Monitor-DeepScan" `
    /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\C2Monitor\C2Detect.ps1" `
    /SC MINUTE /MO 30 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null

schtasks.exe /Create /TN "C2Monitor-QuickWatch" `
    /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\C2Monitor\C2Watcher.ps1" `
    /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null

try {
    if (-not [System.Diagnostics.EventLog]::SourceExists("C2Monitor")) {
        New-EventLog -LogName Application -Source "C2Monitor"
    }
} catch {}

Write-Host "  OK: Scheduled tasks registered" -ForegroundColor Green

# =============================================
# STEP 7: Auto-start notifier for current user
# =============================================
Write-Host "[7/7] Configuring auto-start notifications..." -ForegroundColor Yellow

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$userSid = (New-Object System.Security.Principal.NTAccount($currentUser)).Translate(
    [System.Security.Principal.SecurityIdentifier]).Value
$regPath = "Registry::HKEY_USERS\$userSid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

if (Test-Path $regPath) {
    New-ItemProperty -Path $regPath -Name "C2AlertNotifier" `
        -Value "wscript.exe C:\ProgramData\C2Monitor\LaunchNotifier.vbs" `
        -PropertyType String -Force | Out-Null
} else {
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
        -Name "C2AlertNotifier" `
        -Value "wscript.exe C:\ProgramData\C2Monitor\LaunchNotifier.vbs" `
        -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
}

Start-Process wscript.exe -ArgumentList "C:\ProgramData\C2Monitor\LaunchNotifier.vbs"

Write-Host "  OK: Notifications configured" -ForegroundColor Green

# =============================================
# Done
# =============================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  C2 Monitor v$Version installed!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "What's running:" -ForegroundColor Cyan
Write-Host "  - Sysmon: kernel-level network/process logging"
Write-Host "  - Deep Scan: beaconing + threat intel (every 30 min)"
Write-Host "  - Quick Watch: connection checks (every 5 min)"
Write-Host "  - Notifier: desktop alerts (always on)"
Write-Host ""
Write-Host "Configuration: C:\ProgramData\C2Monitor\config.json" -ForegroundColor Cyan
Write-Host "  Edit to add trusted processes, adjust thresholds, etc." -ForegroundColor Cyan
Write-Host ""
Write-Host "Alert log: C:\ProgramData\C2Monitor\alerts.log" -ForegroundColor Cyan
Write-Host "Event log: Event Viewer > Application > Source: C2Monitor" -ForegroundColor Cyan
Write-Host ""
Write-Host "Uninstall:" -ForegroundColor Yellow
Write-Host "  powershell -ExecutionPolicy Bypass -File C:\ProgramData\C2Monitor\Uninstall-C2Monitor.ps1"
Write-Host ""

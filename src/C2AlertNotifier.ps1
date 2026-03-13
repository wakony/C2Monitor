# C2Monitor Desktop Notifier v1.0.0
# This is the readable source for the notifier embedded in Install-C2Monitor.ps1.
# The installer deploys this to C:\ProgramData\C2Monitor\C2AlertNotifier.ps1
# Runs in user session, monitors alerts.log and shows toast notifications.

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

# Hanif KA sysmon automation script

$SharedPath = "C:\Program Files (x86)\ossec-agent\shared"
#You need to change  it based on your environment
$SysmonExe  = "C:\Windows\Sysmon64.exe"
#You need to change  it based on your environment
$LogFile    = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$TimeWindowMinutes = 2

function Write-Log {
    param ([string]$Message)

    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts Autosysmon - $Message"
    $line | Out-File -FilePath $LogFile -Append -Encoding ascii
}

function Get-SysmonConfigHash {
    try {
        $output = & $SysmonExe -c 2>$null
        foreach ($line in $output) {
            if ($line -match 'Config hash:\s+SHA256=([A-F0-9]{64})') {
                return $Matches[1]
            }
        }
    }
    catch {
        Write-Log "ERROR: Failed to read current Sysmon config hash"
    }
    return $null
}

Write-Log "Sysmon Wodle script started"

if (!(Test-Path $SharedPath)) {
    Write-Log "ERROR: Shared path not found"
    exit 0
}

if (!(Test-Path $SysmonExe)) {
    Write-Log "ERROR: Sysmon executable not found"
    exit 0
}

$Xml = Get-ChildItem -Path $SharedPath -Filter *.xml -ErrorAction SilentlyContinue |
    Where-Object {
        $_.LastWriteTime -gt (Get-Date).AddMinutes(-$TimeWindowMinutes)
    } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $Xml) {
    Write-Log "No recent Sysmon XML detected"
    exit 0
}

Write-Log "Detected XML: $($Xml.FullName)"

$CurrentHash = Get-SysmonConfigHash
$NewHash     = (Get-FileHash -Path $Xml.FullName -Algorithm SHA256).Hash

Write-Log "Current Sysmon hash: $CurrentHash"
Write-Log "New XML hash:       $NewHash"

if ($CurrentHash -and ($CurrentHash -eq $NewHash)) {
    Write-Log "Sysmon configuration already up-to-date. No action required."
    exit 0
}

Write-Log "Hash mismatch detected. Applying new Sysmon configuration."

try {
    $proc = Start-Process `
        -FilePath $SysmonExe `
        -ArgumentList "-c `"$($Xml.FullName)`" -accepteula" `
        -NoNewWindow `
        -Wait `
        -PassThru

    Write-Log "Sysmon exited with code: $($proc.ExitCode)"
    Write-Log "Sysmon configuration successfully updated"
    exit 0
}
catch {
    Write-Log "ERROR applying Sysmon configuration: $_"
    exit 0
}

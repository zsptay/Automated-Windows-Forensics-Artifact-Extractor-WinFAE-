<#

.SYNOPSIS

    WinFAE - Windows Forensic Artifact Extractor

.DESCRIPTION

    A triage script designed for DFIR responders to quickly collect volatile state 

    data, network connections, persistence mechanisms, and critical event logs from 

    a suspected compromised Windows host. Outputs data in structured JSON format.

.PARAMETER OutputDir

    The target directory where the forensic artifacts will be saved. Defaults to C:\Triage_Collection

.EXAMPLE

    PS C:\> .\Get-ForensicArtifacts.ps1 -OutputDir "D:\Forensics"

.NOTES

    Author: Prashanta Sapkota

    Required Privileges: Administrator

#>
 
[CmdletBinding()]

param (

    [string]$OutputDir = "C:\Triage_Collection"

)
 
# --- 1. Admin Privilege Validation ---

Write-Host "[*] Validating administrator privileges..." -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {

    Write-Error "[!] CRITICAL: This script must be executed from an elevated PowerShell prompt (Run as Administrator)."

    Exit

}
 
# --- 2. Initialize Triage Directory ---

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$HostName = $env:COMPUTERNAME

$TriagePath = Join-Path $OutputDir "WinFAE_${HostName}_${Timestamp}"
 
Write-Host "[*] Creating forensic output directory at: $TriagePath" -ForegroundColor Cyan

New-Item -ItemType Directory -Path $TriagePath -Force | Out-Null
 
# --- Helper Function to Export to JSON ---

function Export-ForensicData {

    param (

        [object]$Data,

        [string]$Filename

    )

    $TargetFile = Join-Path $TriagePath "$Filename.json"

    $Data | ConvertTo-Json -Depth 5 | Out-File -FilePath $TargetFile -Encoding utf8

    Write-Host "[+] Successfully extracted: $Filename.json" -ForegroundColor Green

}
 
Write-Host "`n=== STARTING FORENSIC ARTIFACT EXTRACTION ===" -ForegroundColor Yellow
 
# --- 3. Extract Metadata & System Info ---

Write-Host "[*] Collecting system metadata..." -ForegroundColor Cyan

$SysInfo = [PSCustomObject]@{

    HostName         = $env:COMPUTERNAME

    OS_Version       = (Get-CimInstance Win32_OperatingSystem).Caption

    OS_Build         = (Get-CimInstance Win32_OperatingSystem).Version

    BootTime         = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime

    Domain           = $env:USERDOMAIN

    CurrentUser      = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    UTCExtractionTime= [DateTime]::UtcNow.ToString("o")

}

Export-ForensicData -Data $SysInfo -Filename "01_System_Metadata"
 
 
# --- 4. Volatile Process List & Hash Computation ---

Write-Host "[*] Extracting active processes and computing binary SHA-256 hashes..." -ForegroundColor Cyan

$Processes = Get-Process | ForEach-Object {

    $Path = $_.Path

    $SHA256 = "N/A"

    # Calculate hash if the executable is accessible on disk

    if ($Path -and (Test-Path $Path)) {

        try {

            $SHA256 = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash

        } catch {

            $SHA256 = "Access Denied / Reading Error"

        }

    }

    [PSCustomObject]@{

        PID         = $_.Id

        ProcessName = $_.ProcessName

        Path        = $Path

        SHA256      = $SHA256

        Company     = $_.Company

        StartTime   = $_.StartTime

    }

}

Export-ForensicData -Data $Processes -Filename "02_Volatile_Processes"
 
 
# --- 5. Network Connections Mapping ---

Write-Host "[*] Harvesting active network connections and PID associations..." -ForegroundColor Cyan

$NetworkConnections = Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue | ForEach-Object {

    $ProcessName = "Unknown"

    try {

        $ProcessName = (Get-Process -Id $_.OwningProcess).ProcessName

    } catch {}
 
    [PSCustomObject]@{

        LocalAddress  = $_.LocalAddress

        LocalPort     = $_.LocalPort

        RemoteAddress = $_.RemoteAddress

        RemotePort    = $_.RemotePort

        State         = $_.State

        OwningProcess = $_.OwningProcess

        ProcessName   = $ProcessName

    }

}

Export-ForensicData -Data $NetworkConnections -Filename "03_Network_Connections"
 
 
# --- 6. Registry Persistence (Run / RunOnce) ---

Write-Host "[*] Auditing Registry Persistence Keys (HKLM & HKCU Run keys)..." -ForegroundColor Cyan

$RegistryRunPaths = @(

    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",

    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",

    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",

    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

)
 
$RegistryEntries = foreach ($RegPath in $RegistryRunPaths) {

    if (Test-Path $RegPath) {

        $Key = Get-Item $RegPath

        foreach ($ValueName in $Key.GetValueNames()) {

            [PSCustomObject]@{

                RegistryHive = $RegPath

                ValueName    = $ValueName

                ValueData    = $Key.GetValue($ValueName)

            }

        }

    }

}

Export-ForensicData -Data $RegistryEntries -Filename "04_Registry_Persistence"
 
 
# --- 7. Scheduled Tasks Audit ---

Write-Host "[*] Querying non-default Scheduled Tasks (potential persistent payloads)..." -ForegroundColor Cyan

# Filters out standard Microsoft system-related scheduled tasks to minimize noise

$ScheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {

    [PSCustomObject]@{

        TaskName = $_.TaskName

        TaskPath = $_.TaskPath

        State    = $_.State

        Action   = $_.Actions.Execute

    }

}

Export-ForensicData -Data $ScheduledTasks -Filename "05_Scheduled_Tasks"
 
 
# --- 8. Host File Inspection (DNS Redirection Verification) ---

Write-Host "[*] Reading local hosts file for potential DNS redirection hijacking..." -ForegroundColor Cyan

$HostsPath = "$env:windir\System32\drivers\etc\hosts"

$HostsContent = Get-Content $HostsPath | Where-Object { $_ -match "^\s*[^#]" } # Keep lines that are not commented out

Export-ForensicData -Data $HostsContent -Filename "06_Hosts_File_Overrides"
 
 
# --- 9. High-Value Event Log Extraction (Logon & Process Actions) ---

Write-Host "[*] Dumping critical Event Logs (last 50 Security logons & process creations)..." -ForegroundColor Cyan

# Event 4624: Successful Logon | Event 4688: Process Creation (if command-line auditing is enabled)

$ForensicEvents = Get-WinEvent -FilterHashtable @{

    LogName = 'Security'

    Id      = 4624, 4688

} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {

    [PSCustomObject]@{

        TimeCreated = $_.TimeCreated

        EventID     = $_.Id

        Message     = $_.Message

    }

}

Export-ForensicData -Data $ForensicEvents -Filename "07_Event_Log_Extracts"
 
 
# --- 10. Compress Evidence Collection to ZIP ---

Write-Host "`n[*] Compressing collected artifacts into a secure ZIP folder..." -ForegroundColor Cyan

$ZipPath = Join-Path $OutputDir "WinFAE_${HostName}_${Timestamp}.zip"

Compress-Archive -Path $TriagePath -DestinationPath $ZipPath -Force
 
Write-Host "`n========================================================" -ForegroundColor Yellow

Write-Host "[+] Forensic Triage Extraction Completed Successfully!" -ForegroundColor Green

Write-Host "[+] Uncompressed Output Folder: $TriagePath" -ForegroundColor Green

Write-Host "[+] Consolidated Zip Payload: $ZipPath" -ForegroundColor Green

Write-Host "========================================================" -ForegroundColor Yellow 
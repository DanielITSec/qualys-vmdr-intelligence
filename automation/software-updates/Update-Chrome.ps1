<#
.SYNOPSIS
    Standardizes Google Chrome to Enterprise (System-wide) and removes user-level installs.

.DESCRIPTION
    Ensures Google Chrome for Enterprise is installed and updated. The script identifies 
    existing installations (x86, x64, or User-level) and only performs a cleanup/reinstall 
    if an update is required or if non-standard (x86/User) installs are detected.
    This version checks the latest version online via API before downloading the MSI.

.AUTHOR
    Daniel Lima
    https://github.com/DanielITSec

.VERSION
    2.6.2

.LASTEDIT
    2026-02-25

.NOTES
    DISCLAIMER:
    This script is provided "as is" and without warranties of any kind.
    
    ALWAYS test scripts in a staging environment before using them in production.

.EXAMPLE
    .\Update-Chrome.ps1
#>

# ---------------------------------------------------------------------------
# Configuration & Global Variables
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12

$ChromeMsiUrl   = "http://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
$VersionApiUrl  = "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions"
$TempDir        = Join-Path $env:WinDir "Temp"
$OutputFile     = Join-Path $TempDir "ChromeEnterprise.msi"
$LogPath        = Join-Path $TempDir "ChromeEnterpriseInstall.log"

$Pathx86 = "${env:ProgramFiles(x86)}\Google"
$Pathx64 = "$env:ProgramFiles\Google"

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("Info", "Warning", "Error")][string]$Level = "Info"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Color = switch($Level) {
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        Default   { "White" }
    }
    Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
}

function Get-LatestChromeVersionOnline {
    try {
        $Response = Invoke-RestMethod -Uri $VersionApiUrl
        # The API returns versions in descending order; index 0 is the newest
        if ($Response.versions.version[0]) {
            return [version]$Response.versions.version[0]
        }
    } catch {
        Write-Log "Failed to retrieve latest version from Google API: $($_.Exception.Message)" "Warning"
    }
    return $null
}

function Invoke-ChromeCleanup {
    [CmdletBinding()]
    param([string]$Path)

    Write-Log "Starting cleanup for path: $Path"

    Get-Process chrome* -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "Terminating Chrome process (PID: $($_.Id))" "Warning"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }

    $UninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $ChromeEntry = Get-ItemProperty $UninstallKey -ErrorAction SilentlyContinue | Where-Object { 
        $_.DisplayName -like "Google Chrome*" -and ($_.InstallLocation -like "*$Path*" -or $_.UninstallString -like "*$Path*")
    } | Select-Object -First 1

    if ($ChromeEntry.UninstallString) {
        Write-Log "Registry uninstall string found. Executing formal uninstallation..."
        try {
            if ($ChromeEntry.UninstallString -match "msiexec") {
                $Guid = ($ChromeEntry.UninstallString -split '/I' -split '/X')[1].Trim()
                Start-Process "msiexec.exe" -ArgumentList "/X$Guid /qn /norestart" -Wait
            } else {
                $ExePath = $ChromeEntry.UninstallString.Split('"')[1]
                $Arguments = "--uninstall --multi-install --chrome --system-level --force-uninstall"
                Start-Process -FilePath $ExePath -ArgumentList $Arguments -Wait -NoNewWindow
            }
            Start-Sleep -Seconds 5
        } catch {
            Write-Log "Registry uninstall failed: $($_.Exception.Message)" "Error"
        }
    }

    if (Test-Path $Path) {
        Write-Log "Manual file removal fallback for $Path" "Warning"
        $null = cmd /c "takeown /F `"$Path`" /R /D Y > nul 2>&1"
        $null = cmd /c "icacls `"$Path`" /grant:r $env:USERNAME:(F) /T > nul 2>&1"
        Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Main Script Logic
# ---------------------------------------------------------------------------

# 1. OS Compatibility Check
$OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
if ($OSVersion -notlike "10.*" -and $OSVersion -notlike "11.*") {
    Write-Log "Legacy OS Detected ($OSVersion). Running basic deployment." "Warning"
    if (!(Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir }
    Invoke-WebRequest -Uri $ChromeMsiUrl -OutFile $OutputFile
    Start-Process "msiexec.exe" -ArgumentList "/i `"$OutputFile`" /qn" -Wait
    exit 0
}

# 2. Discovery Phase
Write-Log "Scanning environment state..."
$Currentx64Version = $null
$x86Detected = $false
$UserLevelDetectedPaths = @()

$Exe64 = Get-ChildItem -Path $Pathx64 -Filter "chrome.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Exe64) { $Currentx64Version = [version]$Exe64.VersionInfo.FileVersion }

if (Test-Path $Pathx86) {
    if (Get-ChildItem -Path $Pathx86 -Filter "chrome.exe" -Recurse -ErrorAction SilentlyContinue) { $x86Detected = $true }
}

$UserProfiles = Get-ChildItem -Path "$($env:SystemDrive)\Users" | Where-Object { $_.PSIsContainer -and $_.Name -ne "Public" }
foreach ($UserProfile in $UserProfiles) {
    $UserChromePath = Join-Path $UserProfile.FullName "AppData\Local\Google\Chrome"
    if (Test-Path $UserChromePath) { $UserLevelDetectedPaths += $UserChromePath }
}

# 3. Online Version Check (Before Download)
Write-Log "Checking latest available version via Google API..."
$LatestVersion = Get-LatestChromeVersionOnline

if ($null -eq $LatestVersion) {
    Write-Log "Could not determine latest version online. Proceeding to download for manual inspection." "Warning"
}

# 4. Decision Engine
$UpdateRequired = $false
if ($null -eq $Currentx64Version -or ($null -ne $LatestVersion -and $Currentx64Version -lt $LatestVersion)) { 
    $UpdateRequired = $true 
}

$CleanupRequired = $false
if ($x86Detected -or ($UserLevelDetectedPaths.Count -gt 0)) { 
    $CleanupRequired = $true 
}

if (-not $UpdateRequired -and -not $CleanupRequired) {
    Write-Log "Chrome x64 (v$Currentx64Version) is up to date and no conflicts found. Exiting before download."
    exit 0
}

# 5. Execution Phase
Write-Log "Action required: UpdateNeeded=$UpdateRequired, CleanupNeeded=$CleanupRequired"

# Perform Download ONLY if we reached this point
if ($UpdateRequired) {
    if (!(Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir | Out-Null }
    
    $NeedsDownload = $true
    # Safer nested check for PS 5.1 compatibility
    if (Test-Path $OutputFile) {
        if ((Get-Item $OutputFile).LastWriteTime.Date -eq (Get-Date).Date) {
            Write-Log "Recent installer already exists in $TempDir. Skipping download."
            $NeedsDownload = $false
        }
    }

    if ($NeedsDownload) {
        $DownloadVersion = if ($null -ne $LatestVersion) { $LatestVersion } else { 'Latest' }
        Write-Log "Downloading Chrome Enterprise MSI (v$DownloadVersion)..."
        Invoke-WebRequest -Uri $ChromeMsiUrl -OutFile $OutputFile
    }
}

# Cleanup conflicts
if ($x86Detected) { Invoke-ChromeCleanup -Path $Pathx86 }
foreach ($Path in $UserLevelDetectedPaths) { Invoke-ChromeCleanup -Path $Path }

# Perform Update
if ($UpdateRequired) {
    Write-Log "Updating Chrome x64 from $Currentx64Version to $LatestVersion..."
    if ($Currentx64Version) { Invoke-ChromeCleanup -Path $Pathx64 }
    
    $MsiArgs = @("/i", "`"$OutputFile`"", "/qn", "/norestart", "/l*v", "`"$LogPath`"")
    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $MsiArgs -Wait -PassThru
    
    if ($Process.ExitCode -eq 0) {
        Write-Log "Success: Chrome updated to v$LatestVersion"
        Remove-Item $OutputFile -ErrorAction SilentlyContinue
    } else {
        Write-Log "Installation failed (Code: $($Process.ExitCode))." "Error"
    }
}

Write-Log "Process finished."

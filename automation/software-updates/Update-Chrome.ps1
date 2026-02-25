<#
.SYNOPSIS
    Standardizes Google Chrome to Enterprise (System-wide) and removes user-level installs.

.DESCRIPTION
    Ensures Google Chrome for Enterprise is installed and updated. The script identifies 
    existing installations (x86, x64, or User-level), uninstalls conflicting versions, 
    and performs a clean installation of the latest Enterprise MSI.

.AUTHOR
    Daniel Lima
    https://github.com/DanielITSec

.VERSION
    2.4.0

.LASTEDIT
    2026-02-24

.NOTES
    DISCLAIMER:
    This script is provided "as is" and without warranties of any kind, either express 
    or implied. The user assumes all responsibility and risk for the use of this script. 
    In no event shall the author or copyright holders be liable for any claim, damages, 
    or other liability, whether in an action of contract, tort, or otherwise, arising 
    from, out of, or in connection with the script or the use or other dealings in 
    the script. 
    
    ALWAYS test scripts in a staging environment before using them in production.

.EXAMPLE
    .\Update-Chrome.ps1
#>

# ---------------------------------------------------------------------------
# Configuration & Global Variables
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls12

$ChromeMsiUrl = "http://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
$TempDir      = Join-Path $env:WinDir "Temp"
$OutputFile   = Join-Path $TempDir "ChromeEnterprise.msi"
$LogPath      = Join-Path $TempDir "ChromeEnterpriseInstall.log"

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

function Invoke-ChromeCleanup {
    [CmdletBinding()]
    param([string]$Path)

    Write-Log "Starting cleanup for path: $Path"

    # Kill Chrome processes not running from Program Files
    Get-Process chrome* -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Path -notlike "*Program Files*") {
            Write-Log "Terminating user-space Chrome process (PID: $($_.Id))" "Warning"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }

    # Attempt Registry-based uninstall first
    $UninstallKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $ChromeEntry = Get-ItemProperty $UninstallKey | Where-Object { 
        $_.DisplayName -like "Google Chrome*" -and $_.InstallLocation -like "*$Path*" 
    } | Select-Object -First 1

    if ($ChromeEntry.UninstallString) {
        Write-Log "Registry uninstall string found. Executing..."
        try {
            if ($ChromeEntry.UninstallString -match "msiexec") {
                $Guid = ($ChromeEntry.UninstallString -split '/I' -split '/X')[1].Trim()
                Start-Process "msiexec.exe" -ArgumentList "/X$Guid /qn" -Wait
            } else {
                # Handle setup.exe style uninstalls
                $ExePath = $ChromeEntry.UninstallString.Split('"')[1]
                $Arguments = "--uninstall --multi-install --chrome --system-level --force-uninstall"
                Start-Process -FilePath $ExePath -ArgumentList $Arguments -Wait -NoNewWindow
            }
        } catch {
            Write-Log "Registry uninstall failed: $($_.Exception.Message)" "Error"
        }
    }

    # Force delete files if directory still exists (using robust system calls)
    if (Test-Path $Path) {
        Write-Log "Manual file removal required for $Path" "Warning"
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
    Write-Log "Legacy OS Detected ($OSVersion). Proceeding with basic installer logic." "Warning"
    if (!(Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir }
    Invoke-WebRequest -Uri $ChromeMsiUrl -OutFile $OutputFile
    Start-Process "msiexec.exe" -ArgumentList "/i `"$OutputFile`" /qn" -Wait
    exit 0
}

# 2. Discovery Phase
Write-Log "Scanning for existing installations..."
$UserInstallsCount = 0
$OldVersion = $null

# Check System-wide (x86) - Needs cleanup to avoid dual-install issues
if (Test-Path $Pathx86) {
    $Exe = Get-ChildItem -Path $Pathx86 -Filter "chrome.exe" -Recurse -ErrorAction SilentlyContinue
    if ($Exe) {
        Write-Log "Legacy x86 system install detected. Scheduling removal."
        $OldVersion = [version]$Exe.VersionInfo.FileVersion
        Invoke-ChromeCleanup -Path $Pathx86
    }
}

# Check System-wide (x64) - Remove before installing the new one to ensure a clean state
if (Test-Path $Pathx64) {
    $Exe = Get-ChildItem -Path $Pathx64 -Filter "chrome.exe" -Recurse -ErrorAction SilentlyContinue
    if ($Exe) {
        $DetectedVersion = [version]$Exe.VersionInfo.FileVersion
        Write-Log "Existing x64 system install detected (Version: $DetectedVersion). Removing for clean update..."
        if ($null -eq $OldVersion) { $OldVersion = $DetectedVersion }
        Invoke-ChromeCleanup -Path $Pathx64
    }
}

# Check User-level installs
$UserProfiles = Get-ChildItem -Path "$($env:SystemDrive)\Users" | Where-Object { $_.PSIsContainer -and $_.Name -ne "Public" }
foreach ($UserProfile in $UserProfiles) {
    $UserChromePath = Join-Path $UserProfile.FullName "AppData\Local\Google\Chrome"
    if (Test-Path $UserChromePath) {
        Write-Log "Found user-level install for profile: $($UserProfile.Name)" "Warning"
        Invoke-ChromeCleanup -Path $UserChromePath
        $UserInstallsCount++
    }
}

# 3. Preparation & Download
if (!(Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir | Out-Null }

$SkipDownload = $false
if (Test-Path $OutputFile) {
    $FileDate = (Get-Item $OutputFile).LastWriteTime.Date
    $Today = (Get-Date).Date
    if ($FileDate -eq $Today) {
        Write-Log "A recently downloaded installer (from today) already exists. Skipping download."
        $SkipDownload = $true
    } else {
        Remove-Item -Path $OutputFile -Force
    }
}

if (-not $SkipDownload) {
    Write-Log "Downloading latest Chrome Enterprise MSI..."
    try {
        Invoke-WebRequest -Uri $ChromeMsiUrl -OutFile $OutputFile
    } catch {
        Write-Log "Failed to download MSI: $($_.Exception.Message)" "Error"
        exit 1
    }
}

# Extract Version from MSI via Shell COM
$Shell = New-Object -ComObject Shell.Application
$Folder = $Shell.NameSpace((Split-Path $OutputFile))
$File = $Folder.ParseName((Split-Path -Leaf $OutputFile))
$LatestVersionString = ($Folder.GetDetailsOf($File, 24) -split ' ')[0]
$LatestVersion = [version]$LatestVersionString

# 4. Installation Phase
Write-Log "Executing System-wide installation (Version: $LatestVersion)"
$MsiArgs = @(
    "/i", "`"$OutputFile`"",
    "/qn",
    "/norestart",
    "/l*v", "`"$LogPath`""
)

$Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $MsiArgs -Wait -PassThru

if ($Process.ExitCode -ne 0) {
    Write-Log "MSI Installation returned exit code: $($Process.ExitCode)" "Error"
}

# 5. Verification
$FinalPath = Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"
if (Test-Path $FinalPath) {
    $InstalledVersion = [version](Get-Item $FinalPath).VersionInfo.FileVersion
    
    # PowerShell 5.1 compatible null-coalescing logic
    $DisplayOldVersion = if ($null -ne $OldVersion) { $OldVersion } else { "None" }
    
    if ($InstalledVersion -ge $LatestVersion) {
        Write-Log "Success: Chrome updated to version $InstalledVersion (Previous: $DisplayOldVersion)"
    } else {
        Write-Log "Version mismatch: Expected $LatestVersion but found $InstalledVersion" "Warning"
    }
} else {
    Write-Log "Verification failed: Chrome.exe not found in Program Files after installation." "Error"
    exit 1
}

Write-Log "Script completed successfully."

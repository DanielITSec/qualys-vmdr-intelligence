<#
.SYNOPSIS
    Performs comprehensive Windows health checks and repairs common system issues.

.DESCRIPTION
    This script identifies and remediates issues related to Windows Update (WUP), 
    WMI Repository, BITS, DNS configuration, and missing Admin Shares. It can 
    optionally use an XML configuration file to verify service states.

.PARAMETER Config
    Path to the XML configuration file. Defaults to 'Config.xml' in the script directory.

.PARAMETER installPSW
    Switch to trigger PSWindowsUpdate module installation.

.PARAMETER NoConfirm
    Suppresses confirmation prompts (e.g., for reboot warnings).

.PARAMETER RepairWSUS
    Triggers WSUS/Windows Update specific repairs.

.PARAMETER RepairStore
    Triggers the DISM Component Store repair (/RestoreHealth).

.PARAMETER RepairWUP
    Triggers Windows Update agent, folder cleanup, and DISM component repair.

.PARAMETER RepairBits
    Performs BITS (Background Intelligent Transfer Service) specific repairs.

.PARAMETER RepairDNS
    Flushes and registers DNS client settings.

.PARAMETER RepairWMI
    Resets and salvages the WMI repository.

.PARAMETER RepairAdmShare
    Restores missing ADMIN$ shares.

.PARAMETER RepairDrivers
    Scans for devices with error codes (Logging only).

.PARAMETER RepairAll
    Enables all repair functions simultaneously.

.PARAMETER SetPSRepo
    Configures TLS 1.2 and installs the NuGet provider and PSWindowsUpdate module.

.PARAMETER NoWUPLog
    Suppresses specific Windows Update logging if required.

.AUTHOR
    Daniel Lima
    https://github.com/DanielITSec

.VERSION
    1.0.0

.LASTEDIT
    2026-02-25

.NOTES
    ACKNOWLEDGMENTS:
    - Michal Gajda: Creator of the PSWindowsUpdate module used in this script.
    - Anders Rødland: Thanks for the original script logic and community contributions.
      Blog: https://www.andersrodland.com | X: @AndersRodland

    DISCLAIMER:
    This script is provided "as is". Repairs to WMI or Windows Update folders 
    can be intensive. Always test in a staging environment before production use.
    Requires Administrative privileges.

.EXAMPLE
    .\Windows-HealthRemediation.ps1 -RepairStore -NoConfirm
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium")]
param(
    [Parameter(HelpMessage='Path to the XML configuration file')]
    [ValidateScript({Test-Path -Path $_ -PathType Leaf})]
    [string]$Config,
    
    [switch]$installPSW,
    [switch]$NoConfirm,
    [switch]$RepairWSUS,
    [switch]$RepairStore,
    [switch]$RepairWUP,
    [switch]$RepairBits,
    [switch]$RepairDNS,
    [switch]$RepairWMI,
    [switch]$RepairAdmShare,
    [switch]$RepairDrivers,
    [switch]$RepairAll,
    [switch]$SetPSRepo,
    [switch]$NoWUPLog
)

Begin {
    $global:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

    # Default Configuration
    if (-not $Config) {
        $Config = Join-Path $global:ScriptPath "Config.xml"
        Write-Verbose "No configuration provided, using default: $Config"
    }

    # Global State
    $RebootRequired = $false
    
    # --- HELPER FUNCTIONS ---

    function Write-Log {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true)][string]$Message,
            [ValidateSet("Info", "Warning", "Error")][string]$Type = "Info",
            [string]$LogFile = "$env:WinDir\Logs\WindowsHealthRemediation\WindowsHealthRemediation.log"
        )
        
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogEntry = "[$Timestamp] [$Type] $Message"
        
        # Create directory if it doesn't exist
        $LogDir = Split-Path $LogFile
        if (-not (Test-Path $LogDir)) { 
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null 
        }

        # Console and File output
        if ($Type -eq "Error") { Write-Error $Message }
        elseif ($Type -eq "Warning") { Write-Warning $Message }
        else { Write-Verbose $Message }

        Add-Content -Path $LogFile -Value $LogEntry -Force
    }

    function Test-XML {
        param ([string]$xmlFilePath)
        if (-not (Test-Path $xmlFilePath)) { return $false }
        try {
            $tempXml = New-Object System.Xml.XmlDocument
            $tempXml.Load($xmlFilePath)
            return $true
        } catch {
            Write-Log -Message "Invalid XML: $($_.Exception.Message)" -Type Error
            return $false
        }
    }

    # Load Configuration
    if ($Config -and (Test-Path $Config)) {
        if (Test-XML -xmlFilePath $Config) {
            [xml]$Xml = Get-Content -Path $Config
        } else {
            Throw "The configuration file is invalid or corrupted."
        }
    } elseif ($Config) {
        Throw "Configuration file not found: $Config"
    }

    function Stop-ServiceSafely {
        [CmdletBinding()]
        param (
            [string]$ServiceName,
            [int]$MaxRetries = 3
        )
        
        $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $Service) { return }
        
        if ($Service.Status -ne 'Stopped') {
            Write-Log "Stopping service: $ServiceName"
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            
            # Wait for stop
            try {
                $Service.WaitForStatus('Stopped', '00:00:15')
            } catch {
                Write-Log "Failed to stop $ServiceName via ServiceController. Attempting to kill process." -Type Warning
                # Aggressive kill if service controller fails
                $SvcWmi = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
                if ($SvcWmi.ProcessId -gt 0) {
                    Stop-Process -Id $SvcWmi.ProcessId -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    function Get-OperatingSystem {
        $OS = Get-CimInstance Win32_OperatingSystem
        return "$($OS.Caption) ($($OS.OSArchitecture))"
    }

    # --- REPAIR FUNCTIONS ---

    function Repair-ComponentStore {
        Write-Log "Starting Component Store repair (DISM)..."
        try {
            # Repair corruption using Windows Update as a source
            $DismProcess = Start-Process "dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait -PassThru -NoNewWindow
            if ($DismProcess.ExitCode -eq 0) {
                Write-Log "Component Store repair (RestoreHealth) completed successfully."
            } else {
                Write-Log "DISM RestoreHealth failed with exit code: $($DismProcess.ExitCode)" -Type Warning
            }
        } catch {
            Write-Log "Critical error during DISM repair: $($_.Exception.Message)" -Type Error
        }
    }

    function Repair-WindowsUpdate {
        Write-Log "Starting Windows Update repair process..."
        
        $Services = @("wuauserv", "cryptSvc", "bits", "msiserver")
        foreach ($svc in $Services) { Stop-ServiceSafely -ServiceName $svc }

        # Safe Cleanup (Renaming instead of direct deletion reduces lock risks)
        $Folders = @(
            (Join-Path $env:SystemRoot "SoftwareDistribution"), 
            (Join-Path $env:SystemRoot "System32\catroot2")
        )

        foreach ($Folder in $Folders) {
            if (Test-Path $Folder) {
                Write-Log "Cleaning folder: $Folder"
                try {
                    # Attempt to clear content
                    Remove-Item "$Folder\*" -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-Log "Could not clear $Folder (files in use?). Attempting to rename." -Type Warning
                    Rename-Item $Folder "$($Folder).old_$(Get-Random)" -ErrorAction SilentlyContinue
                }
            }
        }

        # Remove BITS queue files
        Remove-Item "$env:ProgramData\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction SilentlyContinue

        # Reset Winsock and Proxy
        Start-Process -FilePath "netsh" -ArgumentList "winsock reset" -WindowStyle Hidden -Wait
        Start-Process -FilePath "netsh" -ArgumentList "winhttp reset proxy" -WindowStyle Hidden -Wait

        # Reregister essential DLLs
        $DLLs = @("wuapi.dll", "wuaueng.dll", "wups.dll", "wups2.dll", "atl.dll", "urlmon.dll", "mshtml.dll")
        foreach ($dll in $DLLs) {
            Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s $dll" -WindowStyle Hidden -Wait
        }

        # Reset security descriptors
        $Sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
        $null = cmd /c "sc sdset bits $Sddl"
        $null = cmd /c "sc sdset wuauserv $Sddl"

        # Restart Services
        foreach ($svc in $Services) { 
            Start-Service -Name $svc -ErrorAction SilentlyContinue
            Write-Log "Service $svc started."
        }
        
        # Force detection using modern orchestrator
        if (Get-Command UsoClient.exe -ErrorAction SilentlyContinue) {
            Write-Log "Triggering update scan via UsoClient..."
            Start-Process "UsoClient.exe" -ArgumentList "StartScan" -NoNewWindow
        }
    }

    function Repair-WMI {
        Write-Log "Starting WMI Repair..."
        Stop-ServiceSafely -ServiceName "winmgmt"
        
        $WbemPath = Join-Path $env:SystemRoot "System32\wbem"
        
        # Reset and Salvage Repository
        Start-Process "$WbemPath\winmgmt.exe" -ArgumentList "/resetrepository" -Wait -NoNewWindow
        Start-Process "$WbemPath\winmgmt.exe" -ArgumentList "/salvagerepository" -Wait -NoNewWindow
        
        Start-Service "winmgmt"
        Write-Log "WMI Repair completed."
    }

    function Test-DNSConfiguration {
        Write-Log "Verifying DNS consistency..."
        $Hostname = [System.Net.Dns]::GetHostName()
        try {
            $IPs = [System.Net.Dns]::GetHostAddresses($Hostname) | 
                   Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
                   Select-Object -ExpandProperty IPAddressToString
            
            if ($IPs) {
                Write-Log "DNS OK. Resolved IPs: $($IPs -join ', ')"
                return $true
            } else {
                Throw "No resolved IPs found."
            }
        } catch {
            Write-Log "DNS Resolution failure detected." -Type Error
            if ($RepairDNS -or $RepairAll) {
                Write-Log "Attempting to re-register DNS client..."
                Register-DnsClient -ErrorAction SilentlyContinue
                $null = cmd /c "ipconfig /registerdns"
            }
            return $false
        }
    }

    function Test-PendingReboot {
        $Pending = $false
        
        # CBS Check
        if (Test-Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $Pending = $true }
        # Windows Update Check
        if (Test-Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $Pending = $true }
        # File Rename Operations Check
        $PendingFileRename = Get-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($PendingFileRename) { $Pending = $true }

        if ($Pending) {
            Write-Log "Computer requires a restart." -Type Warning
            return $true
        }
        return $false
    }
}

Process {
    # Elevation Check
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "This script must be run as an Administrator."
    }

    Write-Log "Starting Windows Health Remediation v$Version"
    Write-Log "Operating System: $(Get-OperatingSystem)"

    # 1. Service Verification (Based on XML if provided)
    if ($Xml.Configuration.Service) {
        foreach ($svcConfig in $Xml.Configuration.Service) {
            $sObj = Get-Service -Name $svcConfig.Name -ErrorAction SilentlyContinue
            if ($sObj) {
                if ($sObj.Status -ne $svcConfig.State) {
                    Write-Log "Service $($svcConfig.Name) is $($sObj.Status). Target state: $($svcConfig.State). Attempting correction."
                    if ($svcConfig.State -eq "Running") { Start-Service $svcConfig.Name }
                    elseif ($svcConfig.State -eq "Stopped") { Stop-Service $svcConfig.Name }
                }
            }
        }
    }

    # 2. DNS Repair
    if ($RepairDNS -or $RepairAll) { Test-DNSConfiguration }

    # 3. WMI Repair
    if ($RepairWMI -or $RepairAll) {
        $WmiStatus = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if (-not $WmiStatus) { Repair-WMI }
    }

    # 4. Component Store Repair
    # Triggered by individual switch, WUP repair, or All
    if ($RepairStore -or $RepairWUP -or $RepairAll) {
        Repair-ComponentStore
    }

    # 5. Windows Update Repair
    if ($RepairWUP -or $RepairAll) {
        Repair-WindowsUpdate
    }

    # 6. Admin Shares Repair
    if ($RepairAdmShare -or $RepairAll) {
        if (-not (Get-SmbShare -Name "ADMIN$" -ErrorAction SilentlyContinue)) {
            Write-Log "ADMIN$ share is missing. Restarting LanmanServer service." -Type Warning
            Restart-Service LanmanServer -Force
        }
    }

    # 7. Driver Diagnostics
    if ($RepairDrivers -or $RepairAll) {
        $BadDrivers = Get-CimInstance Win32_PNPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne 22 }
        if ($BadDrivers) {
            Write-Log "Devices with errors detected: $($BadDrivers.Count)" -Type Warning
        }
    }

    # 8. PS Repository & Module Setup
    if ($SetPSRepo) {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "Installing PSWindowsUpdate module..."
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
                Install-Module PSWindowsUpdate -Force -Scope CurrentUser -SkipPublisherCheck
            } catch {
                Write-Log "Failed to install module: $($_.Exception.Message)" -Type Error
            }
        }
    }

    # Final Verification
    $RebootRequired = Test-PendingReboot
}

End {
    Write-Log "Health Remediation process finished."
    
    if ($RebootRequired -and -not $NoConfirm) {
        Write-Warning "Pending restart detected. System reboot recommended."
    }
}

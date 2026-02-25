<#
.SYNOPSIS
    Logs off specific users from local or remote Windows servers.

.DESCRIPTION
    Identifies session IDs for multiple users using the 'quser' utility and 
    terminates those sessions using the 'logoff' command. Supports multiple 
    remote servers via the RPC protocol.

.PARAMETER Usernames
    An array of SAM account names of the users to log off.

.PARAMETER Servers
    An array of hostnames or IP addresses of the servers to check for active sessions.

.AUTHOR
    Daniel Lima
    https://github.com/DanielITSec

.VERSION
    2.2.1

.LASTEDIT
    2026-02-24
    
.NOTES
    DISCLAIMER:
    This script is provided "as is" and without warranties of any kind. 
    The user assumes all responsibility and risk. Logging off a user may 
    result in data loss if they have unsaved work.
    
    ALWAYS test scripts in a staging environment before using them in production.

.EXAMPLE
    .\Invoke-UserLogoff.ps1 -Usernames "jdoe", "asmith" -Servers "RDS-SRV-01", "RDS-SRV-02"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the usernames to be logged off.")]
    [Alias('U', 'User', 'Username')]
    [string[]]$Usernames,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the server names or IPs.")]
    [Alias('S', 'Srv', 'Server')]
    [string[]]$Servers
)

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function Write-Log {
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

# ---------------------------------------------------------------------------
# Main Logic
# ---------------------------------------------------------------------------

foreach ($Device in $Servers) {
    Write-Log "--------------------------------------------------"
    Write-Log "Processing server: $Device"

    try {
        # Execute quser once per server to get all active sessions
        $quserRaw = quser /server:$Device 2>&1

        # Check if quser failed (usually means no sessions found or server unreachable)
        if ($LASTEXITCODE -ne 0) {
            if ($quserRaw -match "No User exists") {
                Write-Log "No active sessions found on $Device." "Warning"
                continue
            }
            throw "Failed to connect to $Device. Ensure RPC access is enabled. Error: $quserRaw"
        }

        # Professional Parsing of quser output
        $Sessions = $quserRaw | ForEach-Object {
            $Line = $_.Trim()
            # Replace multiple spaces with a comma for CSV conversion
            $CSVLine = $Line -replace '\s{2,}', ','
            return $CSVLine
        } | ConvertFrom-Csv

        # Iterate through each username for the current server
        foreach ($User in $Usernames) {
            Write-Log "Searching for session for user '$User' on '$Device'..."
            
            # Locate the target user session from the parsed list
            $TargetSession = $Sessions | Where-Object { $_.USERNAME -eq $User }

            if (-not $TargetSession) {
                Write-Log "User '$User' is not logged into '$Device'." "Warning"
                continue
            }

            # Extract ID (Prefer numeric ID for reliability)
            $SessionId = $TargetSession.ID
            
            # Validation: Ensure we have a valid numeric ID
            if ($null -eq $SessionId -or $SessionId -notmatch '^\d+$') {
                # Fallback to Session Name if ID isn't found
                $SessionId = $TargetSession.SESSIONNAME
            }

            if ($null -eq $SessionId) {
                Write-Log "Found session for '$User' on $Device`: but could not determine ID or Name." "Error"
                continue
            }

            Write-Log "Session for '$User' found on $Device`: (ID: $SessionId). Terminating..." "Warning"
            
            # Execute Logoff
            $LogoffResult = logoff $SessionId /server:$Device 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Log "User '$User' successfully logged off from '$Device'."
            } else {
                Write-Log "Logoff failed for '$User' on $Device`: $LogoffResult" "Error"
            }
        }

    } catch {
        Write-Log "Critical error on $Device`: $($_.Exception.Message)" "Error"
    }
}

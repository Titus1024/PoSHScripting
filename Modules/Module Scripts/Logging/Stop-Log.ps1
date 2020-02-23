function Stop-Log {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Stops the log file for the script it is run in.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Stop-Log -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)][string]$ScriptName,    
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    Write-Output "$(Get-LogTime) ========== $ScriptName finished. ==========" >> $Log
}

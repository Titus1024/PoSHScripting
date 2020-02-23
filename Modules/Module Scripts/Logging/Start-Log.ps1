function Start-Log {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Starts the log file for the script it is run in.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Start-Log -Help
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

    $Date = (Get-Date).ToString('yyyy-MM-dd')
    $Script:Log = "\\$env:USERDNSDOMAIN\IT\PowerShell\Logs\$ScriptName\$env:COMPUTERNAME`_$Date.txt"
    $TestPath = Test-Path $Log
    if ($TestPath -eq $false) {
        New-Item -Path $Log -Force | Out-Null
        Write-Output "$(Get-LogTime) ========== $ScriptName started. ==========" >> $Log
    }
    else {
        Write-Output "$(Get-LogTime) ========== $ScriptName started. ==========" >> $Log
    }
}

function Write-LogWarning {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Used to store the warning messages that will be passed to the log file. 
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER WarningMessage
    Warning messages that you wish to pass to the log file goes here.
.PARAMETER ShowOutput
    If this switch is used the WarningMessage information will also be printed to the console.
.EXAMPLE
    Write-LogWarning -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues

#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)]$WarningMessage,
        [Parameter(ParameterSetName)][switch]$ShowOutput,    
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($ShowOutput) {
        "$(Get-LogTime) $WarningMessage" >> $Log
        Write-Warning "$(Get-LogTime) $WarningMessage"
    }
    else {
        "$(Get-LogTime) $WarningMessage" >> $Log
    }
}

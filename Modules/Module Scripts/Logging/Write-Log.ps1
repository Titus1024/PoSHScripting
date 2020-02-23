function Write-Log {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Used to store the information that will be passed to the log file.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER LogMessage
    Information you wish to pass to the log file goes here.
.PARAMETER ShowOutput
    If this switch is used the LogMessage information will also be printed to the console.
.EXAMPLE
    Write-Log -Help
.EXAMPLE
    Write-Log -LogMessage 'Disabled some users and moved them to a different OU'
.EXAMPLE
    Write-Log -LogMessage "Disabled $($User.Name) and moved them to the $($DestinationOU.DistinguishedName) OU."
.EXAMPLE
    Write-Log -LogMessage "Disabled $($User.Name) and moved them to the $($DestinationOU.DistinguishedName) OU." -ShowOutput
    
    2018-12-12 04:45:59 PM - Disabled John Doe and moved them to the Disabled OU.
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)]$LogMessage,
        [Parameter(ParameterSetName)][switch]$ShowOutput,    
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($ShowOutput) {
        "$(Get-LogTime) $LogMessage" >> $Log
        Write-Output "$(Get-LogTime) $LogMessage"
    }
    else {
        "$(Get-LogTime) $LogMessage" >> $Log
    }
}

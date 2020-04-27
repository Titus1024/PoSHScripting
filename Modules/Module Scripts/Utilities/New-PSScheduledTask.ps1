function New-PSScheduledTask {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Creates a new scheduled task on local or remote machines
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    New-PSScheduledTask -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Recurring")]
        [Parameter(ParameterSetName = "Once")]$TaskName,
        [Parameter(ParameterSetName = "Recurring")]
        [Parameter(ParameterSetName = "Once")]$ComputerName,
        [Parameter(ParameterSetName = "Recurring")]

        [Parameter(ParameterSetName = "Once")]$Script,
        [Parameter(ParameterSetName = "Once")]$RunTime,

        [Parameter(ParameterSetName = "Recurring")]$StartTime,
        [Parameter(ParameterSetName = "Recurring")]$Interval,
        
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    
}

function Get-LogTime {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Is used to pass a current time stamp whenever output is generated.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Get-LogTime -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    (Get-Date).ToString('yyyy-MM-dd, hh:mm:ss tt,')
}

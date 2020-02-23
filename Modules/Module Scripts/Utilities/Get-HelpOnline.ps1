
function Get-HelpOnline {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Opens the official Microsoft help page for a PowerShell cmdlet.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Command
    Specifies the command you are getting help on.
.EXAMPLE
    Get-HelpOnline -Help
.EXAMPLE
    Get-HelpOnline -Command Get-ADUser
.EXAMPLE
    h Get-ADUser
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [Alias("h")]
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Command,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name | more
        break
    }
    
    try {
        Get-Help $Command -Online -ErrorAction Stop
    }
    catch {
        Write-Warning "The command $Command was either not found or does not have the built in forwarder.`nTry searching for the command online."
    }
}

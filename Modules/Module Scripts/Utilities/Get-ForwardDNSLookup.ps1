
function Get-ForwardDNSLookup {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER FQDN
    Enter the FQDN you wish to perform a forward DNS lookup on.
.EXAMPLE
    Get-ReverseDNSLookup -Help
.EXAMPLE
    Get-ReverseDNSLookup -FQDN google.com
.EXAMPLE
    rdns google.com
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    [Alias("fdns")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$FQDN,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    try {
        Resolve-DnsName $FQDN -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress -ErrorAction Stop
    }
    catch {
    Write-Warning $PSItem.Exception.Message
    }
}

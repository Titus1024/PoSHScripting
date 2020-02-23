function Get-ReverseDNSLookup {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Performs a reverse DNS lookup.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER IP
    Enter the IP you wish to perform a reverse DNS lookup on.
.EXAMPLE
    Get-ReverseDNSLookup -Help
.EXAMPLE
    Get-ReverseDNSLookup -IP 8.8.8.8
.EXAMPLE
    rdns 8.8.8.8
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    [Alias("rdns")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][IPAddress]$IP,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    try {
        Resolve-DnsName $IP -ErrorAction Stop | Select-Object -ExpandProperty NameHost
    }
    catch {
    Write-Warning $PSItem.Exception.Message
    }
}

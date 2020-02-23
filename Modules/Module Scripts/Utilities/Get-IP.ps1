function Get-IP {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Has multiple uses:
                1. Display your IP address in a clean format.
                2. Display your DNS Server(s).
                3. Display your Default Gateway.
                4. Display your Mac Address.
                5. Get the IP address(es) of other computers.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER DNS
    Outputs your DNS server(s).
.PARAMETER DefaultGateway
    Outputs your Default Gateway.
.PARAMETER MacAddress
    Outputs your Mac Address.
.PARAMETER Computer
    Gets the IP address(es) of a remote computer.
.EXAMPLE
    IP -Help
.EXAMPLE
    Get-IP -DNS -DefaultGateway -MacAddress
.EXAMPLE
    Get-IP -Computer 'LT-Computer'
.EXAMPLE
    IP -DNS -DefaultGateway -MacAddress
.EXAMPLE
    IP -DNS
.EXAMPLE
    IP -DefaultGateway
.EXAMPLE
    IP -MacAddress
.EXAMPLE
    IP -Computer 'LT-Computer'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    [Alias("IP")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0)][switch]$DNS,
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$DefaultGateway,
        [Parameter(ParameterSetName = "Primary", Position = 2)][switch]$MacAddress,
        [Parameter(ParameterSetName = "Computer", Position = 0)][string]$Computer,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($Computer) {
        $Records = Get-DnsServerResourceRecord -ZoneName ad.REDACTED.org -ComputerName REDACTED -Name $Computer |
        Select-Object RecordData -ExpandProperty RecordData |
        Select-Object IPv4Address -ExpandProperty IPv4Address
        Write-Output "IP Address(es): $Records"
        #TODO: Get mac address of other computers?
        break
    }

    $IP = Get-NetIPAddress | Where-Object { $PSItem.PrefixOrigin -eq 'DHCP' -or $PSItem.PrefixOrigin -eq 'Static' } |
    Select-Object IPAddress -ExpandProperty IPAddress
    Write-Output "IP: $IP"
    if ($DNS) {
        $GetDNS = Get-NetIPConfiguration |
        Where-Object {$PSItem.NetAdapter.Status -eq 'Up'} |
        Select-Object DNSServer -ExpandProperty DNSServer |
        Select-Object ServerAddresses |
        Where-Object {$null -ne $PSItem.ServerAddresses} |
        Select-Object ServerAddresses -ExpandProperty ServerAddresses
        Write-Output "DNS: $GetDns"
    }
    if ($DefaultGateway) {
        $GetDefaultGateway = Get-NetIPConfiguration |
        Select-Object IPv4DefaultGateway -ExpandProperty IPv4DefaultGateway |
        Select-Object NextHop -ExpandProperty NextHop
        Write-Output "Default Gateway: $GetDefaultGateway"
    }
    if ($MacAddress) {
        $GetMacAddress = Get-NetIPConfiguration |
        Where-Object {$PSItem.NetAdapter.Status -eq 'Up'} |
        Select-Object NetAdapter -ExpandProperty NetAdapter |
        Select-Object Name, MacAddress
        Write-Output $GetMacAddress
    }
}

$ComputerBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-IP -ParameterName Computer -ScriptBlock $ComputerBlock

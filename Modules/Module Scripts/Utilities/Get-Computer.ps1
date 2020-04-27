function Get-Computer {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Returns useful information about a specific computer.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the computer you wish to query.
.PARAMETER BitLockerKey
    Outputs the BitLocker recovery key.
.EXAMPLE
    Get-Computer -Help
.EXAMPLE
    Get-Computer -Identity LT-MPOLSELLI
.EXAMPLE
    Get-Computer -Identity LT-MPOLSELLI -BitLockerKey
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$BitLockerKey,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $Computer = Get-ADComputer -Identity $Identity -Properties DistinguishedName
    if ($BitLockerKey -eq $true) {
        Write-Output 'hi 3'
        $Credential = Use-PSCred PSADAcctMgmt
        $Properties = @{
            Filter     = { ObjectClass -eq 'msFVE-RecoveryInformation' }
            SearchBase = $Computer.DistinguishedName
            Properties = 'msFVE-RecoveryPassword'
            Credential = $Credential
        }
        $BitLocker_Object = Get-ADObject @Properties | Select-Object @{n = 'Recovery Key'; e = { $PSItem.'msFVE-RecoveryPassword' } }
        
    }
    $Computer = Get-ADComputer -Identity $Identity -Properties * |
    Select-Object 'Created', 'Description', 'DistinguishedName', 'DNSHostName',
    'Enabled', 'IPv4Address', 'isDeleted', 'LastLogonDate', 'Location', 'LockedOut',
    'logonCount', 'Modified', 'Name', 'ObjectGUID', 'objectSid', 'OperatingSystem'
    Write-Output $Computer | Format-List
    Write-Output $BitLocker_Object
    Write-Output 'hi'
    
    $TestConnection = Test-Connection $Computer.Name -Quiet -Count 1
    if ($TestConnection) {
        $LastBootUp = Get-CimInstance -ComputerName $Computer.Name -ClassName Win32_OperatingSystem |
        Select-Object LastBootUpTime
        Write-Output $LastBootUp
    }
    else {
        Write-Output "Unable to get last boot-up time.`nDevice is currently offline or unavailable."
    }
    #>
    Write-Output 'hi 2'

    Write-Output 'hi 4'
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-Computer -ParameterName Identity -ScriptBlock $IdentityBlock

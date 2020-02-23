function Enter-SSPSSession {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Enters a new PSSession on the target machine.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER ComputerName
    Enters a PSSession on the target computer.
.PARAMETER ServerName
    Enters a PSSession on the target server.
.EXAMPLE
    Enter-SSPSSession -Help
.EXAMPLE
    Enter-SSPSSession -ComputerName DT-ComputerName
.EXAMPLE
    Enter-SSPSSession -ServerName Server1
.EXAMPLE
    pss -ComputerName DT-ComputerName
.EXAMPLE
    pss -ServerName Server1
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    [Alias('pss')]
    param (
        [Parameter(ParameterSetName = "Endpoint", Position = 0, Mandatory = $true)][string]$ComputerName,
        [Parameter(ParameterSetName = "Server", Position = 0, Mandatory = $true)][string]$ServerName,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
    }
    
    if ($ServerName) {
        $Username = Read-Host -Prompt 'Enter Admin Username'
        Enter-PSSession -ComputerName $ServerName -Credential $env:USERDOMAIN\$Username
    }
    else {
        $TestConnection = Test-Connection $ComputerName -Quiet -Count 1
        if ($TestConnection) {
            Enter-PSSession -ComputerName $ComputerName
        }
        else {
            Write-Output "$ComputerName is currently offline or unavailable."
        }
    }
}

$ComputerNameBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Enter-SSPSSession -ParameterName ComputerName -ScriptBlock $ComputerNameBlock

$ServerNameBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Enter-SSPSSession -ParameterName ServerName -ScriptBlock $ServerNameBlock

function Restart-Server {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Restarts a server.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies a server you wish to restart.
.EXAMPLE
    Restart-Server -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Identity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    $TestConnection = Test-Connection $Identity -Quiet -Count 1
    if (!$TestConnection) {
        Write-Output "The computer $Identity is currently offline or unavailable."
        break
    }

    $Credential = Use-PSCred -Identity PSADAcctMgmt
    $Prompt = Read-Host -Prompt "Restarting $Identity.`nContinue? [Y][N] (Default: Y)"
    if ($Prompt -eq 'N') {
        Write-Output "Cancelling restart of $Identity."
    }
    else {
        Write-Output "Restarting $Identity."
        Restart-Computer -ComputerName $Identity -Credential $Credential
        do {
            $Connection = Test-Connection $Identity -Quiet
            Write-Output "Testing connection to $Identity..."
        }
        until ($Connection -eq $true)
        Write-Output "Successful connection to $Identity."
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Servers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Restart-Server -ParameterName Identity -ScriptBlock $IdentityBlock

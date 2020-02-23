function Rename-ADComputer {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Renames a computer.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the computer you are renaming.
.PARAMETER NewName
    Sets the new name for the computer you are renaming.
.EXAMPLE
    Rename-Computer -Help
.EXAMPLE
    Rename-Computer -Identity LT-Computer -NewName LT-NewComputer
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$NewName,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $Credential = Use-PSCred -Identity PSADAcctMgmt
    $Ping = Test-Connection $Identity -Quiet -Count 1
    if (!$Ping) {
        Write-Warning "$Identity is offline or unavailable. Try again later."
        break
    }
    try {
        $CheckDuplicate = Get-ADComputer -Identity $NewName
        if ($CheckDuplicate) {
            Remove-ADComputer -Identity $NewName -Credential $Credential -Confirm:$false
            Start-Sleep -Seconds 30
            Rename-Computer -ComputerName $Identity -NewName $NewName -DomainCredential $Credential -Restart:$false -ErrorAction Stop
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Rename-Computer -ComputerName $Identity -NewName $NewName -DomainCredential $Credential -Restart:$false -ErrorAction Stop
    }
    catch {
        Write-Output $PSItem.Exception.Message
    }
    else {
        Write-Output 'Stopping action.'
        break
    }
}
    
$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Rename-ADComputer -ParameterName Identity -ScriptBlock $IdentityBlock

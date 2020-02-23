function Unlock-Account {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Unlocks a user account.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user account you wish to unlock.
.EXAMPLE
    Unlock-Account -Help
.EXAMPLE
    Unlock-Account -Identity 'Mike Polselli'
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
        Get-Help MyInvocation.MyCommand.Name -Full | more
        break
    }
    #TODO: Add output for previous lockouts. Include amount in last day or week or something if possible?
    #TODO: Add confirmation if the account has been locked out multiple times.
    $Credential = Use-PSCred -Identity PSADAcctMgmt
    $User = Get-ADUser -Filter {Name -eq $Identity}
    Unlock-ADAccount -Identity $User.SamAccountName -Credential $Credential
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Unlock-Account -ParameterName Identity -ScriptBlock $IdentityBlock

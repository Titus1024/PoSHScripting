function Reset-UserPassword {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Reset the password of a specific user to the company default as
                well as flagging the account for password reset on next log on.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user you wish you reset the password on.
.EXAMPLE
    Reset-UserPassword -Help
.EXAMPLE
    Reset-UserPassword -Identity 'Mike Polselli'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$NoPasswordResetOnLogon,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    $Credential = Use-PSCred -Identity PSADAcctMgmt
    $User = Get-ADUser -Filter { DisplayName -eq $Identity }
    Set-ADAccountPassword -Identity $User.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText 'REDACTED001' -Force) -Credential $Credential
    if (!$NoPasswordResetOnLogon) {
        Set-ADUser -Identity $User.SamAccountName -ChangePasswordAtLogon:$true -Credential $Credential
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Reset-UserPassword -ParameterName Identity -ScriptBlock $IdentityBlock

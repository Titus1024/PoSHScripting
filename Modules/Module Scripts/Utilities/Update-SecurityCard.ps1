function Update-SecurityCard {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.1
    Language:   PowerShell
    Purpose:    Is used to update all related fields when a user needs an updated security card.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Update-SecurityCard -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$CardNumber,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $ADCredential = Use-PSCred -Identity PSADAcctMgmt
    $User = Get-ADUser -Filter {Name -eq $Identity}
    Set-ADUser -Identity $User -Fax $CardNumber -Credential $ADCredential
    # This doesn't look like it will work until REDACTED is migrated/rebuilt on the REDACTED.
    #\\REDACTED\PCServerCommand\server\bin\win\server-command.exe /?
    Start-Process http://REDACTED:9191/app?service=page/Dashboard
    Start-Process https://acs.brivo.com/login/Login.do
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org' -SearchScope OneLevel).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Update-SecurityCard -ParameterName Identity -ScriptBlock $IdentityBlock

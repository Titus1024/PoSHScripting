function Add-GroupMember {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Adds a user to a specified group.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the group you wish to add the user to.
.PARAMETER Member
    Specifies the user you wish to add to the group.
.EXAMPLE
    Add-GroupMember -Help
.EXAMPLE
    Add-GroupMember -Identity 'Archive' -Member 'Mike Polselli'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)]$Identity,
        [Parameter(ParameterSetName, Position = 1, Mandatory = $true)]$Member,
        [Parameter(ParameterSetName = "Help", Position = 2)][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $Credential = Use-PSCred -Identity PSADAcctMgmt

    try {
        $Username = Get-ADUser -Filter { DisplayName -eq $Member } -ErrorAction Stop
        Add-ADGroupMember -Identity $Identity -Members $Username.SamAccountName -Credential $Credential -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Warning "$Member not found in AD. Check accounts and try again."
    }
    catch {
        Write-Warning $PSItem.Exception.Message
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADGroup -Filter * -SearchBase 'OU=Security Groups,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Add-GroupMember -ParameterName Identity -ScriptBlock $IdentityBlock

$MemberBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Add-GroupMember -ParameterName Member -ScriptBlock $MemberBlock

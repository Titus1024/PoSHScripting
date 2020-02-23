function Get-GroupMembership {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Outputs a list of the specified users group memberships.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user you wish to query.
.EXAMPLE
    Get-GroupMembership -Help
.EXAMPLE
    Get-GroupMembership -Identity 'Mike Polselli'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)]$Identity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    $User = Get-ADUser -Filter { DisplayName -eq $Identity }
    Get-ADPrincipalGroupMembership -Identity $User.SamAccountName |
    Select-Object  Name, GroupCategory, GroupScope |
    Sort-Object -Property @{e = "GroupCategory"; Descending = $false }, @{e = "Name" } |
    Format-Table -AutoSize | more
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-GroupMembership -ParameterName Identity -ScriptBlock $IdentityBlock

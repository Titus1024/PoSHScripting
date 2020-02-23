function Get-GroupMembers {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Queries a group in AD and outputs the members.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user you wish to query.
.EXAMPLE
    Get-GroupMembers -Help
.EXAMPLE
    Get-GroupMembers -Identity 'Mike Polselli'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary",Position = 0, Mandatory = $true)][string[]]$Identity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        foreach ($ID in $Identity) {
            $GroupMembers = Get-ADGroupMember -Identity $ID -ErrorAction Stop |
            Select-Object Name |
            Sort-Object -Property Name |
            Format-Wide -Column 3
            Write-Output "Group Name: $ID"
            Write-Output "Members:"
            Write-Output $GroupMembers | more
        }
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

Register-ArgumentCompleter -CommandName Get-GroupMembers -ParameterName Identity -ScriptBlock $IdentityBlock

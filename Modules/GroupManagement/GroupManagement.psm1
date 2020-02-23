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


function Copy-GroupMembership {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Copies the group membership from the source and adds them to target user.
                Can either add or replace groups.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the target user, this user will have their groups modified.
.PARAMETER UserToCopy
    Specifies the source user, this user will NOT have their groups modified.
.PARAMETER Template
    Selects a template user and applies its groups to the target user.
    TODO:NOTE: No tempalte accounts have been created yet.
.PARAMETER Overwrite
    Removes all of the target user's groups and applies the groups from the target user.
.EXAMPLE
    Copy-GroupMembership -Help
.EXAMPLE
    Copy-GroupMembership -Identity 'Mike Polselli' -UserToCopy 'Bob Dole'
.EXAMPLE
    Copy-GroupMembership -Identity 'Mike Polselli' -Template 'Accounting'
.EXAMPLE
    Copy-GroupMembership -Identity 'Mike Polselli' -UserToCopy 'Bob Dole' -Overwrite
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]
        [Parameter(ParameterSetName = "Template", Position = 0, Mandatory = $true)]
        [string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)]$UserToCopy,
        [Parameter(ParameterSetName = "Template", Position = 1, Mandatory = $true)]$Template,
        [Parameter(ParameterSetName = "Primary", Position = 2)]
        [Parameter(ParameterSetName = "Template", Position = 2)][switch]$Overwrite,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    $Credential = Use-PSCred -Identity PSADAcctMgmt
    if ($Template) {
        Write-Warning 'Template accounts have not been set up yet.'
        exit 1
        try {
            $Identity = Get-ADUser -Filter { Name -eq $Identity } -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "$Identity not found in AD. Check accounts and try again."
        }
    
        try {
            $Template = Get-ADUser -Filter { Name -eq $Template } -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "$Template not found in AD. Check accounts and try again."
        }
                
        $CopyGroups = Get-ADPrincipalGroupMembership -Identity $Template.SamAccountName -ErrorAction Stop

        if ($Overwrite) {
            $Prompt = Read-Host -Prompt "Overwrite and replace all groups for $Identity? [Y][N] Default:[N]"
            if ($Prompt -eq 'Y') {
                $OverwriteGroups = Get-ADPrincipalGroupMembership -Identity $Identity -ErrorAction Stop
                foreach ($Group in $OverwriteGroups) {
                    try {
                        Remove-ADGroupMember -Identity $Group.Name -Members $Identity -Credential $Credential -Confirm:$false -ErrorAction SilentlyContinue   
                    }
                    catch {
                        continue
                    }
                }
                foreach ($Group in $CopyGroups) {
                    try {
                        Add-ADGroupMember -Identity $Group.Name -Members $Identity -Credential $Credential -ErrorAction SilentlyContinue
                    }
                    catch {
                        continue
                    }
                }
            }
            else {
                Write-Output 'Stopping operation.'
                exit
            }
            
        }
        else {
            foreach ($Group in $CopyGroups) {
                try {
                    Add-ADGroupMember -Identity $Group.Name -Members $Identity -Credential $Credential -ErrorAction SilentlyContinue
                }
                catch {
                    continue
                }
            }
        }
    }
    else {
        try {
            $Identity = Get-ADUser -Filter { DisplayName -eq $Identity } -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "$Identity not found in AD. Check accounts and try again."
        }
    
        try {
            $UserToCopy = Get-ADUser -Filter { DisplayName -eq $UserToCopy } -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "$UserToCopy not found in AD. Check accounts and try again."
        }
        
        $CopyGroups = Get-ADPrincipalGroupMembership -Identity $UserToCopy.SamAccountName -ErrorAction Stop
                
        if ($Overwrite) {
            $Prompt = Read-Host -Prompt "Overwrite and replace all groups for $Identity? [Y][N] Default:[N]"
            if ($Prompt -eq 'Y') {
                $OverwriteGroups = Get-ADPrincipalGroupMembership -Identity $Identity -ErrorAction Stop
                foreach ($Group in $OverwriteGroups) {
                    try {
                        Remove-ADGroupMember -Identity $Group.Name -Members $Identity -Credential $Credential -Confirm:$false -ErrorAction SilentlyContinue   
                    }
                    catch {
                        continue
                    }
                }
                foreach ($Group in $CopyGroups) {
                    try {
                        Add-ADGroupMember -Identity $Group.Name -Members $Identity -Credential $Credential -ErrorAction SilentlyContinue
                    }
                    catch {
                        continue
                    }
                }
            }
            else {
                Write-Output 'Stopping operation.'
                exit
            }
        }
        else {
            foreach ($Group in $CopyGroups) {
                try {
                    Add-ADGroupMember -Identity $Group.Name -Members $Identity -Credential $Credential -ErrorAction SilentlyContinue
                }
                catch {
                    continue
                }
            }
        }
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

Register-ArgumentCompleter -CommandName Copy-GroupMembership -ParameterName Identity -ScriptBlock $IdentityBlock

$UserToCopyBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    ((Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name) | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Copy-GroupMembership -ParameterName UserToCopy -ScriptBlock $UserToCopyBlock

$TemplateBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    ((Get-ADUser -Filter * -SearchBase 'OU=TemplateUsers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name) | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Copy-GroupMembership -ParameterName Template -ScriptBlock $TemplateBlock


function Get-GroupMembers {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Queries a group in AD and ouputs the members.
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


function Rename-Group {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Renames a group in AD.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the group you wish to rename.
.PARAMETER NewName
    Will become the new name of the group you have specified.
.EXAMPLE
    Rename-Group -Help
.EXAMPLE
    Rename-Group -Identity 'ArchiveReadOnly' -NewName 'Archive_ReadOnly'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,    
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$NewName,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    $Credential = Use-PSCred -Identity PSADAcctMgmt
    Get-ADGroup -Filter { Name -eq $Identity } | Rename-ADObject -NewName $NewName -Credential $Credential -Confirm:$false
    Get-ADGroup -Filter { Name -eq $Identity } | Set-ADGroup -SamAccountName $NewName -Credential $Credential -Confirm:$false
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADGroup -Filter * -SearchBase 'OU=Security Groups,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Rename-Group -ParameterName Identity -ScriptBlock $IdentityBlock



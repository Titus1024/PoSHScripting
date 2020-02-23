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
    TODO:NOTE: No template accounts have been created yet.
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

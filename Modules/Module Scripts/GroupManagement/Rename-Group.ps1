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

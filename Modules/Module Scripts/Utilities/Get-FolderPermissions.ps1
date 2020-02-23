function Get-FolderPermissions {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Outputs the permissions of a folder in a clear format.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Path
    Specifies the path you want to query.
.EXAMPLE
    Get-FolderPermissions -Help
.EXAMPLE
    Get-FolderPermissions -Path \\ad.REDACTED.org\IT\Software
.EXAMPLE
    Get-FolderPermissions -Path 'S:\Client Invoices'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]
        [ValidateScript( {
                if (-Not ($PSItem | Test-Path ) ) {
                    throw 'Invalid Path.'
                }
                return $true
            })][System.IO.FileInfo]$Path,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    try {
        Get-Acl -Path $Path | Select-Object -ExpandProperty Access |
        Select-Object IdentityReference, FileSystemRights, IsInherited |
        Where-Object {$PSItem.IdentityReference -like "REDACTED\*" -or $PSItem.IdentityReference -eq 'Everyone'}
    }
    catch [System.UnauthorizedAccessException] {
        Write-Warning 'You do not have access to this folder, run as admin.'
    }
    catch {
        Write-Warning $PSItem.Exception.Message
    }
}

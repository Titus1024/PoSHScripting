function Update-Profile {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Updates the PowerShell profile.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Update-Profile -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory)]
        [ValidateSet('Systems', 'Dev')]$Profile,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    switch ($Profile) {
        'Systems' {
            #TODO: Add check for user to see if they are in the systems department.
            # Command to run to get the systems profile.
            Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -Confirm:$false
            if (-Not (Test-Path -Path $profile)) {
                New-Item -Path (Split-Path $PROFILE -Parent) -ItemType Directory -Force
                Copy-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\Scripts\Profile\Systems_Microsoft.PowerShell_profile.ps1 -Destination $profile -Force
            }
            else {
                Copy-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\Scripts\Profile\Systems_Microsoft.PowerShell_profile.ps1 -Destination $profile -Force
            }
            break
        }
        'Dev' {
            #TODO: Add check for user to see if they are in the dev department.
            # Command to run to get the dev team profile.
            Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -Confirm:$false
            if (-Not (Test-Path -Path $profile)) {
                New-Item -Path (Split-Path $PROFILE -Parent) -ItemType Directory -Force
                Copy-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\Scripts\Profile\Dev_Microsoft.PowerShell_profile.ps1 -Destination $profile -Force
            }
            else {
                Copy-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\Scripts\Profile\Dev_Microsoft.PowerShell_profile.ps1 -Destination $profile -Force
            }
            break
        }
    }
}

function Get-SSRandomPassword {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Generates a random password.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER PasswordLength
    Defines the length of the randomly generated password. The default value is 12.
.EXAMPLE
    Get-RandomPassword -Help
.EXAMPLE
    Get-RandomPassword
.EXAMPLE
    Get-RandomPassword -PasswordLength 15
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0)][int]$PasswordLength = 12,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    if ($PasswordLength -le 8) {
        Write-Warning 'Minimum Password length is nine (9).'
        break
    }
    [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    do {
        $RandomPW = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, 4)
    }
    Until ($RandomPW -match "^(?=.*[A-Z].*[A-Z])(?=.*[!@#$%^&*()_])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{$PasswordLength}$")
    $RandomPW | clip
    Write-Output "Randomly Generated Password: $RandomPW"
    Write-Output "Password copied to clipboard."
    Remove-Variable RandomPW
}

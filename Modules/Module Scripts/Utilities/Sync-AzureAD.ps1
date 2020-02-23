function Sync-AzureAD {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Forces a sync between the local AD environment and the AzureAD environment.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Sync-AzureAD -Help
.EXAMPLE
    Sync-AzureAD
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [CmdletBinding()]
        param (
            [switch]$Help
        )
    if ($Help) {
        Get-Help MyInvocation.MyCommand.Name -Full | more
        break
    }
    $Username = Read-Host -Prompt 'Enter Username'
    do {
        try {
            $Session = New-PSSession -ComputerName 'REDACTED' -Credential $env:USERDOMAIN\$Username -ErrorAction Stop
        }
        catch {
            Write-Warning 'Incorrect Password!'
        }
    }
    until ($null -ne $Session)
    Import-Module (Import-PSSession -Session $Session -CommandName 'Start-ADSyncSyncCycle' -AllowClobber)
    try {
        Start-ADSyncSyncCycle -ErrorAction Stop
    }
    catch {
        Write-Output $PSItem.Exception.Message
    }
    Disconnect-PSSession -Session $Session
}

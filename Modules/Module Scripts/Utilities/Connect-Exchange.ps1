function Connect-Exchange {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Commands
    Specifies the commands you wish to import when connecting to Exchange Online.
.EXAMPLE
    Connect-Exchange -Help
.EXAMPLE
    Connect-Exchange -Commands Get-Mailbox
.EXAMPLE
    Connect-Exchange -Commands Get-Mailbox, Get-MailboxPermissions
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [Cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(Position = 0, ParameterSetName = "Primary")][string[]]$Commands,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    Import-Module Utilities
    $Credential = Use-PSCred -Identity PSExchangeAdmin -Email

    if ($Commands) {
        $ExchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri 'https://outlook.office365.com/powershell-liveid/' -Credential $Credential -Authentication Basic -AllowRedirection
        Import-Module (Import-PSSession -Session $ExchangeSession -AllowClobber -CommandName $Commands) -Global
        # Temporary Logging
        Start-Log -ScriptName "Connect-Exchange - $env:USERNAME"
        Write-Log -LogMessage "$env:USERNAME connected to Exchange."
        Stop-Log -ScriptName "Connect-Exchange - $env:USERNAME"
    }
    else {
        $ExchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri 'https://outlook.office365.com/powershell-liveid/' -Credential $Credential -Authentication Basic -AllowRedirection
        Import-Module (Import-PSSession -Session $ExchangeSession -AllowClobber) -Global
        # Temporary Logging
        Start-Log -ScriptName "Connect-Exchange - $env:USERNAME"
        Write-Log -LogMessage "$env:USERNAME connected to Exchange."
        Stop-Log -ScriptName "Connect-Exchange - $env:USERNAME"
    }
}

function Connect-ExchangeMFA {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER EmailAddress
    Enter your Office365 admin email address.
.PARAMETER Commands
    Specifies the commands you wish to import when connecting to Exchange Online.
.EXAMPLE
    Connect-ExchangeMFA -Help
.EXAMPLE
    Connect-ExchangeMFA -EmailAddress O365Admin@REDACTED.org
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$EmailAddress,
        #[Parameter(ParameterSetName = "Primary", Position = 1)][string[]]$Commands,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        $EXOCheck = Get-Module ExchangeOnlineManagement -ListAvailable
        if (!$EXOCheck) {
            Write-Output "Exchange Online Module is not present. Installing."
            Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser
            Write-Output 'Done.'
        }
        Connect-ExchangeOnline -UserPrincipalName $EmailAddress -ShowProgress:$true
        <#
        if ($Commands) {
            Import-Module (Import-PSSession -Session $ExchangeSession -AllowClobber -CommandName $Commands) -Global
        }
        else {
            $Warning = $null
            Import-Module (Import-PSSession -Session $ExchangeSession -AllowClobber) -Global -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable $Warning
        }
        #>
    }
    catch {
        Write-Warning $PSItem.Exception.Message
    }
    
}

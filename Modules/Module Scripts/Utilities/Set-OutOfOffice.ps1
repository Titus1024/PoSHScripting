function Set-OutOfOffice {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Configures Out of Office for Outlook.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Set-OutOfOffice -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)]
        [ValidateSet('Template', 'Custom')]$MessageType,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)]
        [ValidateSet('1 Day', '2 Days', '3 Days', '4 Days', '5 Days', '1 Week', '2 Weeks')]$Duration,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    Connect-Exchange -Commands Set-MailboxAutoReplyConfiguration

    $User = Get-ADUser -Filter { Name -eq $Identity }

    $StartDate = (Get-Date)
    switch ($Duration) {
        '1 Day' { $EndDate = (Get-Date).AddDays(1); break }
        '2 Days' { $EndDate = (Get-Date).AddDays(2); break }
        '3 Days' { $EndDate = (Get-Date).AddDays(3); break }
        '4 Days' { $EndDate = (Get-Date).AddDays(4); break }
        '5 Days' { $EndDate = (Get-Date).AddDays(5); break }
        '1 Week' { $EndDate = (Get-Date).AddDays(7); break }
        '2 Weeks' { $EndDate = (Get-Date).AddDays(14); break }
    }

    if ($MessageType -eq 'Template') {
        $Message = "
        I am out of the office from $StartDate to $EndDate, if you need immediate
        help please contact helpdesk at helpdesk@REDACTED.org
        "
    }
    else {
        $Message = Read-Host -Prompt 'Enter your message here.'
    }
}

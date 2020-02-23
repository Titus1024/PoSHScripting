function Get-SharedMailbox {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Displays useful information about the shared mailbox.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the shared mailbox you would like to query.
.EXAMPLE
    Get-SharedMailbox -Help
.EXAMPLE
    Get-SharedMailbox -Identity 'Archive'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary",Position = 0,Mandatory = $true)]$Identity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        Connect-Exchange -Commands 'Get-Mailbox' -ErrorAction Stop

        #Properties to add to the output
        $Properties = 'ExchangeGuid','ForwardingAddress','ForwardingSmtpAddress','IsMailboxEnabled','ProhibitSendQuota',
        'ProhibitSendReceiveQuota','RecoverableItemsQuota','CalendarLoggingQuota','RecipientLimits','IsShared',
        'ServerName','RulesQuota','UserPrincipalName','AuditEnabled','AuditLogAgeLimit',
        'UsageLocation','Alias','MaxSendSize','MaxReceiveSize','PrimarySmtpAddress',
        'WhenChanged','WhenCreated','Guid'

        $Mailbox = Get-Mailbox -Identity $Identity | Select-Object $Properties
        return $Mailbox

        Get-PSSession | Remove-PSSession
    }
    catch {
        Write-Warning $PSItem.Exception.Message
        Get-PSSession | Remove-PSSession
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\SharedMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-SharedMailbox -ParameterName Identity -ScriptBlock $IdentityBlock

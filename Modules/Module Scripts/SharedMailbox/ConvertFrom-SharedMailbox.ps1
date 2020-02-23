function ConvertFrom-SharedMailbox {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Converts a shared mailbox to a regular mailbox.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the shared mailbox you wish to convert into a regular mailbox.
.EXAMPLE
    ConvertFrom-SharedMailbox -Help
.EXAMPLE
    ConvertFrom-SharedMailbox -Identity 'Archive'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary",Position = 0, Mandatory = $true)]$Identity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        Connect-Exchange -Commands 'Set-Mailbox','Get-Mailbox' -ErrorAction Stop
        $CheckMailbox = Get-Mailbox -Identity $Identity
        if ($CheckMailbox.IsShared -eq $false) {
            Write-Output "$Identity is already a regular mailbox!`nCheck spelling and try again."
        }
        else {
            Set-Mailbox -Identity $Identity -Type Regular -ErrorAction Stop
            Get-PSSession | Remove-PSSession
        }
    }
    catch {
        Write-Output $PSItem.Exception.Message
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\SharedMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName ConvertFrom-SharedMailbox -ParameterName Identity -ScriptBlock $IdentityBlock

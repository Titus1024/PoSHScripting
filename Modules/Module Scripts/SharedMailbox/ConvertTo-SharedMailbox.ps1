function ConvertTo-SharedMailbox {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Converts a regular mailbox to a shared mailbox.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the regular mailbox you wish to convert to a shared mailbox.
.EXAMPLE
    ConvertTo-SharedMailbox -Help
.EXAMPLE
    ConvertTo-SharedMailbox -Identity 'Bob Dole'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Identity,    
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        Connect-Exchange -Commands 'Set-Mailbox','Get-Mailbox' -ErrorAction Stop
        $CheckMailbox = Get-Mailbox -Identity $Identity
        if ($CheckMailbox.IsShared -eq $true) {
            Write-Output "$Identity is already a shared mailbox!`nCheck spelling and try again."
            Get-PSSession | Remove-PSSession
        }
        else {
            Set-Mailbox -Identity $Identity -Type Shared -ErrorAction Stop
            Get-PSSession | Remove-PSSession
        }
    }
    catch {
        Write-Output $PSItem.Exception.Message
        Get-PSSession | Remove-PSSession
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\AllMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName ConvertTo-SharedMailbox -ParameterName Identity -ScriptBlock $IdentityBlock

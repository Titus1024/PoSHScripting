function Remove-SharedMailbox {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the shared mailbox(es) you with to remove.
.EXAMPLE
    Remove-SharedMailbox -Help
.EXAMPLE
    Remove-SharedMailbox -Identity 'Shared Mailbox'
.EXAMPLE
    Remove-SharedMailbox -Identity 'Shared Mailbox', 'Shared Mailbox Two'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string[]]$Identity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    Connect-Exchange -Commands Remove-Mailbox -ErrorAction Stop

    foreach ($ID in $Identity) {
        $Prompt = Read-Host -Prompt "Perform removal on $ID`? [Y][N] Default [N]"
        if ($Prompt -eq 'Y') {
            try {
                Remove-Mailbox -Identity $ID -ErrorAction Stop -Confirm:$false
                Write-Output "Shared Mailbox - $ID has been removed."
            }
            catch {
                Write-Warning $PSItem.Exception.Message
            }
        }
        else {
            Write-Output "No action taken on $ID."
            continue
        }
    }
    Get-PSSession | Remove-PSSession
    
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\SharedMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Remove-SharedMailbox -ParameterName Identity -ScriptBlock $IdentityBlock

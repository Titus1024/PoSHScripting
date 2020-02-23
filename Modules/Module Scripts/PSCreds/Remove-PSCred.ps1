function Remove-PSCred {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Removes a PSCredential.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the PSCredential you wish to remove.
.EXAMPLE
    Remove-PSCred -Help
.EXAMPLE
    Remove-PSCred -Identity PSADAcctMgmt
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
    
    $Prompt = Read-Host "Removing $Identity. Is this correct? [Y][N] Default:[N]"
    if ($Prompt -eq 'Y') {
        try {
            Remove-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\$Identity -Force -Recurse -ErrorAction Stop
            Write-Host "$Identity has been removed."
        }
        catch {
            Write-Output $PSItem.Exception.Message
        }
    }
    else {
        Write-Output "Action has been cancelled. $Identity has not been removed."
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ChildItem -Path \\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds) | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Remove-PSCred -ParameterName Identity -ScriptBlock $IdentityBlock

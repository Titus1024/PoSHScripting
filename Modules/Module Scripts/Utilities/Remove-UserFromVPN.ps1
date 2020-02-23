function Remove-UserFromVPN {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Removes a user(s) from the VPN.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Used to specify the user(s) you wish to remove from the VPN group.
.EXAMPLE
    Remove-UserFromVPN -Help
.EXAMPLE
    Remove-UserFromVPN -Identity 'Bob Dole'
.EXAMPLE
    Remove-UserFromVPN -Identity 'Mike Polselli', 'Bob Dole'
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
    
    $Credential = Use-PSCred -Identity PSADAcctMgmt
    
    try {
        foreach ($ID in $Identity) {
            $Username = Get-ADUser -Filter {Name -eq $ID}
            Remove-ADGroupMember -Identity VPN -Members $Username.SamAccountName -Credential $Credential -ErrorAction Stop -Confirm:$false
        }
    }
    catch {
        Write-Warning $PSItem.Exception.Message 
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Remove-UserFromVPN -ParameterName Identity -ScriptBlock $IdentityBlock 

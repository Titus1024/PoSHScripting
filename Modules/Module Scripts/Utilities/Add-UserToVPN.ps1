function Add-UserToVPN {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Adds a user to the VPN group.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user(s) to be added to the VPN group.
.EXAMPLE
    Add-UserToVPN -Help
.EXAMPLE
    Add-UserToVPN -Identity 'Mike Polselli'
.EXAMPLE
    Add-UserToVPN -Identity 'Mike Polselli','Bob Dole'
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
        $Credential = Use-PSCred -Identity PSADAcctMgmt
        foreach ($ID in $Identity) {
            $Username = Get-ADUser -Filter {Name -eq $ID}
            Add-ADGroupMember -Identity VPN -Members $Username.SamAccountName -Credential $Credential -ErrorAction Stop
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

Register-ArgumentCompleter -CommandName Add-UserToVPN -ParameterName Identity -ScriptBlock $IdentityBlock 

function Update-PSCred {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Updates a PSCredential and the associated AD Account.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the PSCredential you wish to update.
.PARAMETER UpdatePSADAcctMgmtPW
    Switch for updating the PSADAccountMgmtPW account, must provide alternative
    admin credentials.
.EXAMPLE
    Update-PSCred -Help
.EXAMPLE
    Update-PSCred -Identity PSExchangeAdmin
.EXAMPLE
    Update-PSCred -Identity PSADAcctMgmt -UpdatePSADAcctMgmtPW
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$UpdatePSADAcctMgmtPW,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($Identity -eq 'PSADAcctMgmt' -and !$UpdatePSADAcctMgmtPW) {
        Write-Warning "$Identity can only be updated while using the UpdatePSADAcctMgmtPW switch."
        break
    }

    try {
        $Email = Get-ADUser -Identity $Identity | Select-Object UserPrincipalName -ExpandProperty UserPrincipalName
    }
    catch {
        Write-Warning "$Identity was not found in AD, the account may no longer exist or was renamed."
        Write-Warning $PSItem.Exception.Message
        break
    }
    
    try {
        [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
            do {
                $RandomPW = [System.Web.Security.Membership]::GeneratePassword(30, 10)
            }
            Until ($RandomPW -match '^(?=.*[A-Z].*[A-Z])(?=.*[!@#$%^&*()_])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{30}$')
        $Credential = (ConvertTo-SecureString $RandomPW -AsPlainText -Force)
    
        if ($UpdatePSADAcctMgmtPW) {
            $Prompt = Read-Host 'Enter Admin Username'
            $UseCredential = Get-Credential -Credential $env:USERDOMAIN\$Prompt
        }
        else {
            $UseCredential = Use-PSCred -Identity PSADAcctMgmt
        }
        Set-ADAccountPassword -Identity $Identity -Reset -NewPassword $Credential -Credential $UseCredential
    
        $Path = "\\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\$Identity\"
        $AESKey = New-Object byte[] 32
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
        Set-Content -Path "$Path$($Identity)_AdminKey.txt" -Value $AESKey
    
        Set-Content -Path "$Path$($Identity)_AdminUser.txt" -Value "REDACTED\$Identity"
            
        $PW = $Credential | ConvertFrom-SecureString -Key $AESKey
        Set-Content -Path "$Path$($Identity)_AdminPW.txt" -Value $PW
            
        Set-Content -Path "$Path$($Identity)_AdminEmail.txt" -Value $Email
    }
    catch {
        Write-Warning $PSItem.Exception.Message
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ChildItem -Path \\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Update-PSCred -ParameterName Identity -ScriptBlock $IdentityBlock

function New-PSCred {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    This function is used to generate new PowerShell AD account and credentials to be used in scripts.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER FirstName
    Enter the first name of the account you wish to create a PSCredential for.
.PARAMETER LastName
    Enter the last name of the account you wish to create a PSCredential for.
.PARAMETER Username
    Enter the username of the account you wish to create a PSCredential for.
.EXAMPLE
    New-PSCred -Help
.EXAMPLE
    New-PSCred -FirstName 'PowerShell Exchange Admin' -LastName 'Account' -Username 'PSExchangeAdmin'
    Required files are then generated and placed in the PSCred folder.
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(Mandatory, Position = 0, ParameterSetName = "Primary")][string]$FirstName,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "Primary")][string]$LastName,
        [Parameter(Mandatory, Position = 2, ParameterSetName = "Primary")][string]$Username,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    # Checks if file exists.
    $TestPath = Test-Path -Path "\\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\$($Username)\"
    if ($TestPath) {
        Write-Warning "PSCredential $Username already exists. Use Update-PSCred to update."
        break
    }

    # Creates the new user account in AD.
    $GetUser = Read-Host -Prompt 'Enter Admin Username'
    $ADCredential = Get-Credential $env:USERDOMAIN\$GetUser -ErrorAction Stop
    $Properties = @{
        Confirm           = $false
        Credential        = $ADCredential
        DisplayName       = ($FirstName + ' ' + $LastName)
        ErrorAction       = 'Stop'
        GivenName         = $FirstName
        Name              = ($FirstName + ' ' + $LastName)
        SamAccountName    = $Username
        Surname           = $LastName
        UserPrincipalName = $Username + '@REDACTED.org'
    }
    try {
        New-ADUser @Properties
        $User = Get-ADUser $Username
        Move-ADObject -Identity $User -TargetPath 'OU=PowerShell,OU=Administrative,OU=REDACTED,DC=AD,DC=REDACTED,DC=org' -Credential $ADCredential -Confirm:$false
        # Generates a random password and assigns it to the new user
        [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
        do {
            $RandomPW = [System.Web.Security.Membership]::GeneratePassword(30, 10)
        }
        Until ($RandomPW -match '^(?=.*[A-Z].*[A-Z])(?=.*[!@#$%^&*()_])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{30}$')
        $Credential = (ConvertTo-SecureString $RandomPW -AsPlainText -Force)
        Set-ADAccountPassword -Identity $Username -NewPassword $Credential -Credential $ADCredential
        Set-ADUser -Identity $Username -Enabled:$true -Credential $ADCredential
    }
    catch {
        Write-LogError $PSItem.Exception -ShowOutput
        break
    }

    # Checks for a valid username.
    try {
        $Email = Get-ADUser -Identity $Username -ErrorAction Stop | Select-Object UserPrincipalName -ExpandProperty UserPrincipalName
    }
    catch {
        Write-Warning "$Username was not found. Please check the spelling and try again."
        break;
    }

    # Creates the AES key for securing the password file and sets relevant information into their files.
    $Path = "\\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\$($Username)\"
    $UserFile = New-Item -Path "$Path\$($Username)_AdminUser.txt" -Force
    $EmailFile = New-Item -Path "$Path\$($Username)_AdminEmail.txt" -Force
    $PWFile = New-Item -Path "$Path\$($Username)_AdminPW.txt" -Force
    $KeyFile = New-Item -Path "$Path\$($Username)_AdminKey.txt" -Force

    # Creates the secure key.
    $AESKey = New-Object byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
    Set-Content -Path $KeyFile.FullName -Value $AESKey

    Set-Content -Path $UserFile.FullName -Value "$env:USERDOMAIN\$($Username)"
    
    $SecuredPassword = $Credential | ConvertFrom-SecureString -Key $AESKey
    Set-Content -Path $PWFile.FullName -Value $SecuredPassword

    Set-Content -Path $EmailFile.FullName -Value $Email
}

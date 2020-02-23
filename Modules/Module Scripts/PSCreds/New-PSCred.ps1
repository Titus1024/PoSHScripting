function New-PSCred {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    This function is used to generate new PowerShell credentials to be used in scripts.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Username
    Enter the name of the account you wish to create a PSCredential for.
.EXAMPLE
    New-PSCred -Help
.EXAMPLE
    New-PSCred -Username PSExchangeAdmin
    Password for user PSExchangeAdmin: **********
    Required files are then generated and placed in the PSCred folder.
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Primary")]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Username,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    # Checks for a valid username.
    try {
        $Email = Get-ADUser -Identity $Username.UserName -ErrorAction Stop | Select-Object UserPrincipalName -ExpandProperty UserPrincipalName
    }
    catch {
        Write-Warning "$($Username.Username) was not found. Please check the spelling and try again."
        break;
    }

    # Checks if file exists.
    $TestPath = Test-Path -Path "\\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\$($Username.UserName)\"
    if ($TestPath) {
        Write-Warning "PSCredential $($Username.UserName) already exists. Use Update-PSCred to update."
        break
    }

    # Creates the AES key for securing the password file and sets relevant information into their files.
    $Path = "\\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\$($Username.UserName)\"
    $UserFile = New-Item -Path "$Path\$($Username.UserName)_AdminUser.txt" -Force
    $EmailFile = New-Item -Path "$Path\$($Username.UserName)_AdminEmail.txt" -Force
    $PWFile = New-Item -Path "$Path\$($Username.UserName)_AdminPW.txt" -Force
    $KeyFile = New-Item -Path "$Path\$($Username.UserName)_AdminKey.txt" -Force

    # Creates the secure key.
    $AESKey = New-Object byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
    Set-Content -Path $KeyFile.FullName -Value $AESKey

    Set-Content -Path $UserFile.FullName -Value "$env:USERDOMAIN\$($Username.UserName)"
    
    $SecuredPassword = $Username.Password | ConvertFrom-SecureString -Key $AESKey
    Set-Content -Path $PWFile.FullName -Value $SecuredPassword

    Set-Content -Path $EmailFile.FullName -Value $Email
}

$UsernameBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=PowerShell,OU=Administrative,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName New-PSCred -ParameterName Username -ScriptBlock $UsernameBlock

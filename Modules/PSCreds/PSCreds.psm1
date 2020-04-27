function Get-PSCred {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Displays information about a PSCredential.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the PSCredential you wish to query.
.EXAMPLE
    Get-PSCred -Help
.EXAMPLE
    Get-PSCred -Identity PSADAcctMgmt
    Displays useful information about the PSCredential PSADAcctMgmt
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

    $Path = "\\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\"
    $Info = Get-ChildItem -Path $Path\$Identity
    $Access = Get-Acl -Path $Path\$Identity | Select-Object -ExpandProperty Access |
    Where-Object { $PSItem.IdentityReference.Value -like "$env:USERDOMAIN*" } |
    Select-Object @{n = 'Identity'; e = { $PSItem.IdentityReference } }, @{n = 'Access'; e = { $PSItem.FileSystemRights } }
    
    #Builds and formats the table
    $TableName = "$Identity Information"
    $Table = New-Object System.Data.DAtaTable $TableName
    $Columns = ('File Name', 'Permissions', 'Permissions Type', 'Creation Date', 'Last Modified Date')
    foreach ($Column in $Columns) {
        $NewColumn = New-Object System.Data.DataColumn $Column
        $Table.Columns.Add($NewColumn)
    }

    for ($i = 0; $i -lt $Info.Count; $i++) {
        New-Variable -Name Row$i -Force
        $Row = $Table.NewRow()
        $Row.'File Name' = $Info[$i].Name.Replace('.txt', '')
        $Row.Permissions = ($Access.Identity -join ',').Replace("$env:USERDOMAIN\", '')
        $Row.'Permissions Type' = 'Still in development.'
        #TODO: Figure out how to format the table to include the different user permissions.
        #$Row.'Permissions Type' = ($Access.Access -join ',')
        $Row.'Creation Date' = $Info[$i].CreationTime
        $Row.'Last Modified Date' = $Info[$i].LastWriteTime
        $Table.Rows.Add($Row)
    }
    return $Table
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ChildItem -Path \\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Get-PSCred -ParameterName Identity -ScriptBlock $IdentityBlock


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
#TODO: Troubleshoot the connection issue with vCenter/Sphere
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


function Use-PSCred {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Creates and passes a PSCredential to a function, module, etc.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the PSCredential you wish to use.
.PARAMETER Email
    Creates the PSCredential with the email address, instead of the username.
.EXAMPLE
    Use-PSCred -Help
.EXAMPLE
    $Credential = Use-PSCred -Identity PSADAcctMgmt
.EXAMPLE
    $Credential = Use-PSCred -Identity PSExchangeAdmin -Email
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$Email,
        [Parameter(ParameterSetName = "Help", Position = 2)][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    $Path = "\\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\$Identity\"

    $UserFile = "$Path$($Identity)_AdminUser.txt"
    $EmailFile = "$Path$($Identity)_AdminEmail.txt"
    $PWFile = "$Path$($Identity)_AdminPW.txt"
    $KeyFile = "$Path$($Identity)_AdminKey.txt"
        
    if ($Email) {
        $Key = Get-Content $KeyFile
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential `
            -ArgumentList (Get-Content $EmailFile), (Get-Content $PWFile | ConvertTo-SecureString -Key $Key)
        $Credential
    }
    else {
        $Key = Get-Content $KeyFile
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential `
            -ArgumentList (Get-Content $UserFile), (Get-Content $PWFile | ConvertTo-SecureString -Key $Key)
        $Credential
    }
    # Logging purposes
    Start-Log -ScriptName "Use-PSCred - $Identity"
    Write-Log "$env:USERNAME used $Identity."
    Stop-Log -ScriptName "Use-PSCred - $Identity"
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ChildItem -Path \\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Use-PSCred -ParameterName Identity -ScriptBlock $IdentityBlock



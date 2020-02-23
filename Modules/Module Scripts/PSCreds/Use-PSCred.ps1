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

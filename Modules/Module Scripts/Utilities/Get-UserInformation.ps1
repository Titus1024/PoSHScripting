function Get-UserInformation {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Displays useful information about a specific user or users.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user(s) you wish to query.
.EXAMPLE
    Get-UserInformation -Help
.EXAMPLE
    Get-UserInformation -Identity 'Mike Polselli'
.EXAMPLE
    Get-UserInformation -Identity 'Mike Polselli', 'Bob Dole'
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
    $Properties = ('AccountExpirationDate', 'AccountLockoutTime', 'BadLogonCount', 'badPwdCount',
        'CannotChangePassword', 'Deleted', 'Department', 'Description',
        'DisplayName', 'EmailAddress', 'Enabled', 'Fax',
        'LastBadPasswordAttempt', 'LastLogonDate', 'LockedOut',
        'lockoutTime', 'logonCount', 'LogonWorkstations', 'mail',
        'Manager', 'Modified', 'Name', 'ObjectGUID', 'objectSid',
        'Office', 'OfficePhone', 'PasswordExpired', 'PasswordLastSet',
        'PasswordNeverExpires', 'SamAccountName', 'SID', 'targetAddress',
        'telephoneNumber', 'Title', 'whenChanged', 'whenCreated'
    )
    $UserInfo = Get-ADUser -Filter {Name -eq $Identity} -Properties $Properties |
    Select-Object 'AccountExpirationDate', 'AccountLockoutTime', 'BadLogonCount', 'badPwdCount',
    'CannotChangePassword', 'Deleted', 'Department', 'Description',
    'EmailAddress', 'Enabled', 'LastBadPasswordAttempt',
    'LastLogonDate', 'LockedOut', 'lockoutTime', 'logonCount', 'mail', 
    @{n = 'Manager'; e = { $PSItem.Manager -replace "(CN=)(.*?),.*", '$2' } }, 'Modified', 'ObjectGUID',
    'Office', @{n = 'PaperCutID'; e = { $PSItem.Fax } },
    'PasswordExpired', 'PasswordLastSet',
    'PasswordNeverExpires', @{n = 'Username'; e = { $PSItem.SamAccountName } }, 'SID', 'targetAddress',
    'telephoneNumber', 'Title', 'whenChanged', 'whenCreated' |
    Sort-Object
    
    $Dashes = ('-' * $Identity.Length)

    # Prints data to the console.
    Write-Output $Identity
    Write-Output $Dashes
    return $UserInfo
}
$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}
Register-ArgumentCompleter -CommandName Get-UserInformation -ParameterName Identity -ScriptBlock $IdentityBlock

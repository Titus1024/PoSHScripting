function Update-Username {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Update-Username -Help
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Mandatory = $true, Position = 0)][string]$Identity,
        [Parameter(ParameterSetName, Mandatory = $true, Position = 1)][string]$NewUsername,
        [Parameter(ParameterSetName, Position = 2)][string]$NewName,
        [Parameter(ParameterSetName = "Help", Position = 3)][switch]$Help
    )
    if ($Help) {
        Get-Help MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    #TODO: Replace this with a variable using the mail property of the AD user
    $EmailDomain = '@REDACTED.org'
    
    try {
        $User = Get-ADUser -Identity $Identity -ErrorAction Stop
        Set-ADUser -Identity $User.SamAccountName -Replace @{
            TargetAddress                 = ($NewUsername + $EmailDomain)
            mail                          = ($NewUsername + $EmailDomain)
            mailNickName                  = ($NewUsername)
            'msRTCSIP-PrimaryUserAddress' = ($NewUsername + $EmailDomain)
        }
        Set-ADUser -Identity $User.SamAccountName -Remove @{
            proxyAddresses = 'sip:' + $Username + $EmailDomain
        }
        Set-ADUser -Identity $User.SamAccountName -Remove @{
            proxyAddresses = 'SMTP:' + $Username + $EmailDomain
        }
        Set-ADUser -Identity $User.SamAccountName -Add @{
            proxyAddresses = 'sip:' + $NewUsername + $EmailDomain
        }
        Set-ADUser -Identity $User.SamAccountName -Add @{
            proxyAddresses = 'SMTP:' + $NewUsername + $EmailDomain
        }
        Set-ADUser -Identity $User.SamAccountName -Add @{
            proxyAddresses = 'smtp:' + $Username + $EmailDomain
        }

        if ($NewName) {
            $FirstName = $NewName.Split(' ')[0]
            $LastName = $NewName.Split(' ')[1]
            Set-ADUser -Identity $Identity -GivenName $FirstName -Surname $LastName -DisplayName $NewName
            Rename-ADObject -Identity $User.DistinguishedName -NewName $NewName
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Warning "$Identity not found in Active Directory. Check the spelling and try again."
    }
    catch {
        Write-Warning $PSItem.Exception.Message
    }
}


function Add-SharedMailboxPermission {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Gives a specified user FullControl access of a shared mailbox(es).
                Can also add SendAs access.
                Additionally an email will be sent to the user and an update will be added to the ticket.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user(s) you wish to give shared mailbox access to.
.PARAMETER Mailbox
    Specifies the shared mailbox(es) you wish update access on.
.PARAMETER TicketNumber
    Enter the ticket number of the request for shared mailbox acces. 
.PARAMETER SendAs
    Grants SendAs access to the user specified on the shared mailbox specified.
.EXAMPLE
    Add-SharedMailboxPermission -Help
.EXAMPLE
    Add-SharedMailboxPermission -Identity 'Mike Polselli' -Mailbox 'REDACTED' -TicketNumber 12345
.EXAMPLE
    Add-SharedMailboxPermission -Identity 'Mike Polselli' -Mailbox 'REDACTED','REDACTED' -TicketNumber 12345 -SendAs
.Example
    Add-SharedMailboxPermissions -Identity 'Mike Polselli','Bob Dole' -Mailbox 'REDACTED' -TicketNumber 12345 -SendAs
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
    
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]    
    param (
        [Parameter(ParameterSetName = "Primary", Mandatory = $true, Position = 0)][string[]]$Identity,
        [Parameter(ParameterSetName = "Primary", Mandatory = $true, Position = 1)][string[]]$Mailbox,
        [Parameter(ParameterSetName = "Primary", Mandatory = $true, Position = 2)][string]$TicketNumber,
        [Parameter(ParameterSetName = "Primary", Mandatory = $false, Position = 3)][switch]$SendAs,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    try {
        $Mailboxes = @()
        Connect-Exchange -Commands 'Add-MailboxPermission', 'Add-RecipientPermission' -ErrorAction Stop
        foreach ($Id in $Identity) {
            foreach ($MB in $Mailbox) {
                Write-Output "Adding $Id to $MB."
                $UserName = Get-ADUser -Filter { DisplayName -eq $Id } -ErrorAction Stop
                $Properties = @{
                    Identity     = $MB
                    User         = $UserName.SamAccountName
                    AccessRights = 'FullAccess'
                    Confirm      = $false
                    ErrorAction  = 'Stop'
                }
                Add-MailboxPermission @Properties | Out-Null
                if ($SendAs) {
                    $Properties = @{
                        Identity     = $MB
                        AccessRights = 'SendAs'
                        Trustee      = $UserName.SamAccountName
                        Confirm      = $false
                        ErrorAction  = 'Stop'
                    }
                    Add-RecipientPermission @Properties | Out-Null
                }

                # Capitalizes the mailbox name.
                $TextInfo = (Get-Culture).TextInfo
                $MailboxCap = $TextInfo.ToTitleCase($MB)
                $Mailboxes += $MailboxCap
            }
            $HelpDeskURL = "http://helpdesk.REDACTED.org/portal/view-help-request/$TicketNumber"
            $BodyAsHTML = "
                <p>Hello $($UserName.Name),</p>
                <p>You have been given access to the shared mailbox(es) $($Mailboxes), 
                it will show up in roughly 30-45 minutes. 
                If it has not shown up in your Outlook by that time, 
                restart your Outlook and give it another 5-10 minutes.</p>
                <br>
                <p>Do not reply to this email.</p>
                <p>If you have any questions or concerns direct them <a href=`"$HelpDeskURL`">here</a>.</p>
                "
            $Properties = @{
                To          = 'helpdesk@REDACTED.org'
                Cc          = $UserName.UserPrincipalName
                From        = 'autoreply@REDACTED.org'
                Subject     = "[Ticket #$TicketNumber]"
                Body        = $BodyAsHTML
                BodyAsHTML  = $true
                SMTPServer  = 'REDACTED'
                UseSSL      = $true
                ErrorAction = 'Stop'
            }
            Send-MailMessage @Properties
            Write-Output "Email sent to $Id. Ticket #$TicketNumber updated."
        }
        Get-PSSession | Remove-PSSession
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Warning "$Identity not found in AD. Please check AD."
        Get-PSSession | Remove-PSSession
    }
    catch {
        Write-Warning $PSItem.Exception.Message
        Get-PSSession | Remove-PSSession
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

Register-ArgumentCompleter -CommandName Add-SharedMailboxPermission -ParameterName Identity -ScriptBlock $IdentityBlock

$MailboxBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\AllMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Add-SharedMailboxPermission -ParameterName Mailbox -ScriptBlock $MailboxBlock


function ConvertFrom-SharedMailbox {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Converts a shared mailbox to a regular mailbox.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the shared mailbox you wish to convert into a regular mailbox.
.EXAMPLE
    ConvertFrom-SharedMailbox -Help
.EXAMPLE
    ConvertFrom-SharedMailbox -Identity 'Archive'
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

    try {
        Connect-Exchange -Commands 'Set-Mailbox','Get-Mailbox' -ErrorAction Stop
        $CheckMailbox = Get-Mailbox -Identity $Identity
        if ($CheckMailbox.IsShared -eq $false) {
            Write-Output "$Identity is already a regular mailbox!`nCheck spelling and try again."
        }
        else {
            Set-Mailbox -Identity $Identity -Type Regular -ErrorAction Stop
            Get-PSSession | Remove-PSSession
        }
    }
    catch {
        Write-Output $PSItem.Exception.Message
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\SharedMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName ConvertFrom-SharedMailbox -ParameterName Identity -ScriptBlock $IdentityBlock


function ConvertTo-SharedMailbox {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Converts a regular mailbox to a shared mailbox.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the regular mailbox you wish to convert to a shared mailbox.
.EXAMPLE
    ConvertTo-SharedMailbox -Help
.EXAMPLE
    ConvertTo-SharedMailbox -Identity 'Bob Dole'
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
        Connect-Exchange -Commands 'Set-Mailbox','Get-Mailbox' -ErrorAction Stop
        $CheckMailbox = Get-Mailbox -Identity $Identity
        if ($CheckMailbox.IsShared -eq $true) {
            Write-Output "$Identity is already a shared mailbox!`nCheck spelling and try again."
            Get-PSSession | Remove-PSSession
        }
        else {
            Set-Mailbox -Identity $Identity -Type Shared -ErrorAction Stop
            Get-PSSession | Remove-PSSession
        }
    }
    catch {
        Write-Output $PSItem.Exception.Message
        Get-PSSession | Remove-PSSession
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\AllMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName ConvertTo-SharedMailbox -ParameterName Identity -ScriptBlock $IdentityBlock


function Get-SharedMailbox {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Displays useful information about the shared mailbox.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the shared mailbox you would like to query.
.EXAMPLE
    Get-SharedMailbox -Help
.EXAMPLE
    Get-SharedMailbox -Identity 'Archive'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary",Position = 0,Mandatory = $true)]$Identity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        Connect-Exchange -Commands 'Get-Mailbox' -ErrorAction Stop

        #Properties to add to the output
        $Properties = 'ExchangeGuid','ForwardingAddress','ForwardingSmtpAddress','IsMailboxEnabled','ProhibitSendQuota',
        'ProhibitSendReceiveQuota','RecoverableItemsQuota','CalendarLoggingQuota','RecipientLimits','IsShared',
        'ServerName','RulesQuota','UserPrincipalName','AuditEnabled','AuditLogAgeLimit',
        'UsageLocation','Alias','MaxSendSize','MaxReceiveSize','PrimarySmtpAddress',
        'WhenChanged','WhenCreated','Guid'

        $Mailbox = Get-Mailbox -Identity $Identity | Select-Object $Properties
        return $Mailbox

        Get-PSSession | Remove-PSSession
    }
    catch {
        Write-Warning $PSItem.Exception.Message
        Get-PSSession | Remove-PSSession
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\SharedMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-SharedMailbox -ParameterName Identity -ScriptBlock $IdentityBlock


function Get-SharedMailboxPermissions {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Pulls the permissions of a shared mailbox and formats them into a table.
                Can be used to query multiple mailboxes at one time.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Mailbox
    Specify the mailbox(es) you wish to query.
.EXAMPLE
    Get-SharedMailboxPermissions -Help
.EXAMPLE
    Get-SharedMailboxPermissions -Mailbox 'Shared Mailbox'
.EXAMPLE
    Get-SharedMailboxPermissions -Mailbox 'Shared Mailbox','Shared Mailbox Two'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string[]]$Mailbox,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        # Connects to Exchange and gathers the permissions.
        Connect-Exchange -Commands Get-MailboxPermission -ErrorAction Stop
        foreach ($Identity in $Mailbox) {
            $Permissions = Get-MailboxPermission -Identity $Identity | Where-Object { $PSItem.User -like "*@REDACTED.org" -or $PSItem.User -like "*@REDACTED.org" } |
            Select-Object User, AccessRIghts
            
            # Capitalizes the mailbox name.
            $TextInfo = (Get-Culture).TextInfo
            $IdentityCap = $TextInfo.ToTitleCase($Identity)
            # Builds the table and formats it.
            $TableName = "$IdentityCap Permissions"
            $Table = New-Object System.Data.DataTable $TableName
            $ColumnOne = New-Object System.Data.DataColumn Name, ([string])
            $ColumnTwo = New-Object System.Data.DataColumn AccessRights, ([string])
            $Table.Columns.Add($ColumnOne)
            $Table.Columns.Add($ColumnTwo)
            for ($i = 0; $i -lt $Permissions.User.Count; $i++) {
                $UPN = $Permissions[$i].User
                $Username = Get-ADUser -Filter { UserPrincipalName -eq $UPN } | Select-Object -ExpandProperty Name
                New-Variable -Name Row$i -Force
                $Row = $Table.NewRow()
                $Row.Name = $Username
                $Row.AccessRights = $Permissions.AccessRights[$i]
                $Table.Rows.Add($Row)
            }
            $Lines = ('-' * $TableName.Length)
            $Table.TableName
            $Lines
            $Table | Format-Table -AutoSize
        }
        Get-PSSession | Remove-PSSession
    }
    catch {
        Write-Warning $PSItem.Exception.Message
        Get-PSSession | Remove-PSSession
    }
}

$MailboxBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\SharedMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-SharedMailboxPermissions -ParameterName Mailbox -ScriptBlock $MailboxBlock


function New-SharedMailbox {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Creates a new shared mailbox. Can also be used to add FullAccess and SendAs permissions to the new shared mailbox.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the name of the new shared mailbox.
.PARAMETER TicketNumber
    The ticket you are updating.
.PARAMETER Members
    User(s) to be added to the new shared mailbox.
.PARAMETER SendAs
    Adds SendAs permission to the user added to the new shared mailbox.
.EXAMPLE
    New-SharedMailbox -Help
.EXAMPLE
    New-SharedMailbox -Identity NewMailbox
.EXAMPLE
    New-SharedMailbox -Identity 'New Mailbox' -Members 'Mike Polselli'
.EXAMPLE
    New-SharedMailbox -Identity NewMailbox -Members 'Mike Polselli' -SendAs
.EXAMPLE
    New-SharedMailbox -Identity NewMailbox -Members 'Mike Polselli','Bob Dole' -SendAs
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$TicketNumber,
        [Parameter(ParameterSetName = "Primary", Position = 2)][string[]]$Members,
        [Parameter(ParameterSetName = "Primary", Position = 3)][switch]$SendAs,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        Write-Output 'Connecting to Exchange.'
        Connect-Exchange -Commands 'New-Mailbox', 'Add-MailboxPermission', 'Add-RecipientPermission'
        
        Write-Output "Creating new shared mailbox: $Identity"
        New-Mailbox -Shared -Name $Identity -DisplayName $Identity -Alias $Identity.Replace(' ', '') | Out-Null
    
        if ($Members) {
            $CC = @()
            foreach ($Member in $Members) {
                $UserName = Get-ADUser -Filter { DisplayName -eq $Member } -ErrorAction Stop
                $Properties = @{
                    Identity     = $Identity
                    User         = $UserName.SamAccountName
                    AccessRights = 'FullAccess'
                    Confirm      = $false
                    ErrorAction  = 'Stop'
                }
                Add-MailboxPermission @Properties | Out-Null
                Write-Output "Adding $Member to $Identity."
                $CC += $UserName.UserPrincipalName
            }

            if ($SendAs) {
                $Properties = @{
                    Identity     = $Identity
                    AccessRights = 'SendAs'
                    Trustee      = $UserName.SamAccountName
                    Confirm      = $false
                    ErrorAction  = 'Stop'
                }
                Add-RecipientPermission @Properties | Out-Null
                Write-Output "Adding SendAs to $Member on $Identity."
            }

            # Capitalizes the mailbox name.
            $TextInfo = (Get-Culture).TextInfo
            $MailboxCap = $TextInfo.ToTitleCase($Identity)
            $BodyAsHTML = "
            <p>Hello,</p>
            <p>You have been given access to the shared mailbox $($MailboxCap), 
            it will show up in roughly 30-45 minutes. 
            If it has not shown up in your Outlook by that time, 
            restart your Outlook and give it another 5-10 minutes.</p>
            "
            $Properties = @{
                To          = 'helpdesk@REDACTED.org'
                Cc          = $CC
                From        = 'autoreply@REDACTED.org'
                Subject     = "[Ticket #$TicketNumber]"
                Body        = $BodyAsHTML
                BodyAsHTML  = $true
                SMTPServer  = 'REDACTED'
                UseSSL      = $true
                ErrorAction = 'Stop'
            }
            Send-MailMessage @Properties
            Write-Output "Email sent to users. Ticket #$TicketNumber updated."
        }
        Get-PSSession | Remove-PSSession
    }
    catch {
        Write-Warning $PSItem.Exception.Message
        Get-PSSession | Remove-PSSession
    }   
}

$MembersBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName New-SharedMailbox -ParameterName Members -ScriptBlock $MembersBlock


function Remove-SharedMailbox {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the shared mailbox(es) you with to remove.
.EXAMPLE
    Remove-SharedMailbox -Help
.EXAMPLE
    Remove-SharedMailbox -Identity 'Shared Mailbox'
.EXAMPLE
    Remove-SharedMailbox -Identity 'Shared Mailbox', 'Shared Mailbox Two'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string[]]$Identity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    Connect-Exchange -Commands Remove-Mailbox -ErrorAction Stop

    foreach ($ID in $Identity) {
        $Prompt = Read-Host -Prompt "Perform removal on $ID`? [Y][N] Default [N]"
        if ($Prompt -eq 'Y') {
            try {
                Remove-Mailbox -Identity $ID -ErrorAction Stop -Confirm:$false
                Write-Output "Shared Mailbox - $ID has been removed."
            }
            catch {
                Write-Warning $PSItem.Exception.Message
            }
        }
        else {
            Write-Output "No action taken on $ID."
            continue
        }
    }
    Get-PSSession | Remove-PSSession
    
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\SharedMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Remove-SharedMailbox -ParameterName Identity -ScriptBlock $IdentityBlock


function Remove-SharedMailboxPermissions {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Remove-SharedMailboxPermissions -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    #TODO: Determine if this is needed.
    Write-Warning 'This is still under development and going into further consideration.'
}



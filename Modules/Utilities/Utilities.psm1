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


function Connect-Exchange {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Commands
    Specifies the commands you wish to import when connecting to Exchange Online.
.EXAMPLE
    Connect-Exchange -Help
.EXAMPLE
    Connect-Exchange -Commands Get-Mailbox
.EXAMPLE
    Connect-Exchange -Commands Get-Mailbox, Get-MailboxPermissions
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [Cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(Position = 0, ParameterSetName = "Primary")][string[]]$Commands,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    Import-Module Utilities
    $Credential = Use-PSCred -Identity PSExchangeAdmin -Email

    if ($Commands) {
        $ExchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri 'https://outlook.office365.com/powershell-liveid/' -Credential $Credential -Authentication Basic -AllowRedirection
        Import-Module (Import-PSSession -Session $ExchangeSession -AllowClobber -CommandName $Commands) -Global
        # Temporary Logging
        Start-Log -ScriptName "Connect-Exchange - $env:USERNAME"
        Write-Log -LogMessage "$env:USERNAME connected to Exchange."
        Stop-Log -ScriptName "Connect-Exchange - $env:USERNAME"
    }
    else {
        $ExchangeSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri 'https://outlook.office365.com/powershell-liveid/' -Credential $Credential -Authentication Basic -AllowRedirection
        Import-Module (Import-PSSession -Session $ExchangeSession -AllowClobber) -Global
        # Temporary Logging
        Start-Log -ScriptName "Connect-Exchange - $env:USERNAME"
        Write-Log -LogMessage "$env:USERNAME connected to Exchange."
        Stop-Log -ScriptName "Connect-Exchange - $env:USERNAME"
    }
}


function Connect-ExchangeMFA {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER EmailAddress
    Enter your Office365 admin email address.
.PARAMETER Commands
    Specifies the commands you wish to import when connecting to Exchange Online.
.EXAMPLE
    Connect-ExchangeMFA -Help
.EXAMPLE
    Connect-ExchangeMFA -EmailAddress O365Admin@REDACTED.org
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$EmailAddress,
        #[Parameter(ParameterSetName = "Primary", Position = 1)][string[]]$Commands,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        $EXOCheck = Get-Module ExchangeOnlineManagement -ListAvailable
        if (!$EXOCheck) {
            Write-Output "Exchange Online Module is not present. Installing."
            Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser
            Write-Output 'Done.'
        }
        Connect-ExchangeOnline -UserPrincipalName $EmailAddress -ShowProgress:$true
        <#
        if ($Commands) {
            Import-Module (Import-PSSession -Session $ExchangeSession -AllowClobber -CommandName $Commands) -Global
        }
        else {
            $Warning = $null
            Import-Module (Import-PSSession -Session $ExchangeSession -AllowClobber) -Global -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable $Warning
        }
        #>
    }
    catch {
        Write-Warning $PSItem.Exception.Message
    }
    
}


function Disable-User {
    <#
.SYNOPSIS
    Function used to streamline the process of disabling an ADUser.
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    This function will be used to streamline the process of disabling an ADUser.
                Tasks that this function does.
                AD Account
	                1. Removes user from all groups
	                2. Resets password to a randomly generated one
	                3. Disables account
	                4. Moves to disabled OU
	                5. Syncs changes with Azure
	                6. Logs all activities

                Exchange/Email
                    1. Converts mailbox to shared mailbox
                    2. Gives the manager access to the shared mailbox
                    3. Reminder is created in Outlook to disable the sharing after 6 months
                    4. Disables/Removes all Outlook rules
                    5. Sets up auto reply for 180 days
                    6. Removes user from distribution groups
                
                O365
                    1. Removes licenses
                    2. Disables MFA (After the account has been disabled)
                
                Phone
                    1. Removes phone licensing and logs the number, unless the KeepPhone parameter is used
                
                OneDrive
                    1. Gives manager access to the users OneDrive
                    2. Reminder is created in Outlook to disable the sharing after 6 months
                
                Notifications/Information
                    1. Sends an email template to the user's manager and helpdesk with a detailed message about the work that has been performed.
                
.PARAMETER Help
    Displays helpful information about the function.
.PARAMETER Identity
    Enter the name of the account you wish to disable.
.PARAMETER KeepPhone
    Use this parameter if you wish to keep the phone number on the users ADAccount.
.EXAMPLE
    Disable-User -Help
.EXAMPLE
    Disable-User -Identity 'John Doe'
    This example disables the ADAccount for the user John Doe.
.EXAMPLE
    Disable-User -Identity 'John Doe' -KeepPhone
    This example disables the ADAccount for the user John Doe and keeps their phone number.
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>

    #REQUIRES -Modules Logging, PSCreds

    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Primary")][string]$Identity,
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "Primary")][string]$TicketNumber,
        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = "Primary")][switch]$KeepPhone,
        [Parameter(ParameterSetName = "Help", Position = 3)][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    #Write-Warning 'Still in development.'
    #break
    # Logging purposes.
    $ADCredential = Use-PSCred -Identity PSADAcctMgmt
    $LicenseCredential = Use-PSCred -Identity PSLicenseAdmin -Email
    $SPOAdmin = Use-PSCred -Identity PSSPOAdmin -Email
    try {
        $Commands = @('Set-Mailbox', 'Get-Mailbox', 'Add-MailboxPermission',
            'Set-MailboxAutoReplyConfiguration', 'Get-InboxRule', 'Remove-InboxRule',
            'Remove-DistributionGroupMember')
        Connect-Exchange -Commands $Commands -ErrorAction Stop
    }
    catch {
        Write-LogError $PSItem.Exception.Message -ShowOutput
        Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
        break
    }
    Start-Log -ScriptName "Disable-User - $Identity"
    Write-Log -LogMessage "Disable-User is being run against $Identity by $env:USERNAME."

    # Ensures the events won't be created on a weekend.
    $SetEventDateMonths = (Get-Date).AddMonths(6)
    if ($SetEventDateMonths.DayOfWeek -eq 'Saturday' -or $SetEventDateMonths.DayOfWeek -eq 'Sunday') {
        do {
            $SetEventDateMonths = $SetEventDateMonths.AddDays(1)
        } until ($SetEventDateMonths.DayOfWeek -ne 'Saturday' -and $SetEventDateMonths.DayOfWeek -ne 'Sunday');
    }

    # Ensures the events won't be created on a weekend.
    $SetEventDateDays = (Get-Date).AddDays(180)
    if ($SetEventDateDays.DayOfWeek -eq 'Saturday' -or $SetEventDateDays.DayOfWeek -eq 'Sunday') {
        do {
            $SetEventDateDays = $SetEventDateDays.AddDays(1)
        } until ($SetEventDateDays.DayOfWeek -ne 'Saturday' -and $SetEventDateDays.DayOfWeek -ne 'Sunday');
    }

    try {
        # Gets relevant user information.
        $User = Get-ADUser -Filter { Name -eq $Identity } -Properties Mail, Manager, MemberOf, OfficePhone -ErrorAction Stop
        $Manager = Get-ADUser -Identity $User.Manager -Properties Mail, OfficePhone -ErrorAction Stop
        $CheckUser = Read-Host -Prompt "Offboarding $($User.Name). Is this correct? [Y]es/[N]o (Default: [N])"

        if ($CheckUser -eq 'Y') {
            # Disables the user's AD account.
            Disable-ADAccount -Identity $User.SamAccountName -Credential $ADCredential -ErrorAction Stop
            Write-Log "Disabling user $($User.Name)." -ShowOutput
            [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
            do {
                $RandomPW = [System.Web.Security.Membership]::GeneratePassword(20, 8)
            }
            Until ($RandomPW -match '\d')
            $Properties = @{
                Identity    = $User.SamAccountName
                Reset       = $true
                NewPassword = ($RandomPW | ConvertTo-SecureString -AsPlainText -Force)
                Credential  = $ADCredential
                ErrorAction = 'Stop'
            }
            # Resets the user's password to a randomly generated one.
            Set-ADAccountPassword @Properties
            Set-ADUser -Identity $User.SamAccountName -ChangePasswordAtLogon:$true -Credential $ADCredential
            Write-Log "Reset $($User.Name)'s password to a randomly generated password." -ShowOutput
            
            # Removes user from all AD groups.
            Write-Log "Removing $($User.Name) from AD Groups..." -ShowOutput
            $Groups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName
            foreach ($Group in $Groups) {
                try {
                    $Properties = @{
                        Identity    = $Group.Name
                        Members     = $User.SamAccountName
                        Credential  = $ADCredential
                        Confirm     = $false
                        ErrorAction = 'Continue'
                    }
                    Write-Log "Removed $($User.Name) from $($Group.Name)."
                    Remove-ADGroupMember @Properties
                }
                catch {
                    continue
                }
            }

            # Moves the user's AD account to the disabled OU.
            $Properties = @{
                Identity    = $User.DistinguishedName
                TargetPath  = 'OU=Disabled,OU=REDACTED,DC=AD,DC=REDACTED,DC=org'
                Credential  = $ADCredential
                Confirm     = $false
                ErrorAction = 'Continue'
            }
            try {
                Move-ADObject @Properties
                Write-Log "Moved $($User.Name) to the Disabled OU in AD." -ShowOutput
                Write-Log "$($User.Name) will be archived and marked for deletion in 7 years." -ShowOutput
            }
            catch {
                Write-LogError $PSItem.Exception.Message -ShowOutput
            }

            # Logs the users phone number.
            Write-Log "Phone Number: $($User.OfficePhone)."

            # Syncs local AD with Azure AD.
            Write-Output "Syncing Azure AD.`nEnter admin credentials."
            Sync-AzureAD
        }
        else {
            Write-Log 'Halting action.' -ShowOutput
            Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
            break
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-LogWarning "$Identity not found in AD. Check account and try again." -ShowOutput
    }
    catch {
        Write-LogError $PSItem.Exception.Message -ShowOutput
    }

    # Auto reply
    $Message = "
    <p>Hello,</p>
    <p><br /> As of $(Get-Date -Format "dddd MMMM d'th', yyyy") $($User.Name) has left the company.</p>
    <p><br /> Please send future communications to their manager, $($Manager.Name).
    <br /> You can reach them via Email or Phone.<br /> 
    Email: $($Manager.UserPrincipalName)<br /> 
    Phone: $($Manager.OfficePhone)</p>
    "

    $Properties = @{
        Identity                        = $User.SamAccountName
        AutoReplyState                  = 'Scheduled'
        StartTime                       = (Get-Date)
        EndTime                         = $SetEventDateDays
        InternalMessage                 = $Message
        ExternalMessage                 = $Message
        DeclineAllEventsForScheduledOOF = $true
    }
    Set-MailboxAutoReplyConfiguration @Properties
    Write-Log "Set auto reply on $($User.Name)'s mailbox until $SetEventDateDays." -ShowOutput

    # Remove Outlook rules.
    Get-InboxRule -Mailbox $User.SamAccountName | Remove-InboxRule -Force -Confirm:$false
    Write-Log -LogMessage "Removed Outlook rules from $($User.Name)'s mailbox." -ShowOutput

    # Remove user from distribution groups.
    $Groups = Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\DistributionGroupPermissions.csv |
    Where-Object { $PSitem.Name -eq $User.Name }
    foreach ($Group in $Groups) {
        try {
            Remove-DistributionGroupMember -Identity $Group.GroupName -Member $User.SamAccountName -ErrorAction Continue -Confirm:$false
            Write-Log "Removed $($User.Name) from $($Group.GroupName)." -ShowOutput
        }
        catch {
            Write-LogError $PSItem.Exception.Message -ShowOutput
        }
    }
    # Converts the user's mailbox into a shared mailbox.
    try {
        $CheckMailbox = Get-Mailbox -Identity $Identity | Select-Object IsShared
        if ($CheckMailbox.IsShared -eq $true) {
            Write-LogWarning "$Identity is already a shared mailbox!" -ShowOutput
            Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
        }
        else {
            Set-Mailbox -Identity $Identity -Type Shared -ErrorAction Stop
            Write-Log "Converting $($User.Name)'s mailbox into a shared mailbox." -ShowOutput
            Write-Output 'Processing changes...'
            # Should prevent any weird issues from the mailbox being converted.
            Start-Sleep -Seconds 5
            $Properties = @{
                Identity     = $Identity
                User         = $Manager.SamAccountName
                AccessRights = 'FullAccess'
                Confirm      = $false
                ErrorAction  = 'Stop'
            }
            Add-MailboxPermission @Properties | Out-Null
            Write-Log "$($Manager.Name) has been given access to $($User.Name)'s mailbox." -ShowOutput

            $Properties = @{
                Identity                   = $User.SamAccountName
                DeliverToMailboxAndForward = $true
                ForwardingSMTPAddress      = $Manager.UserPrincipalName
                ErrorAction                = 'SilentlyContinue'
            }
            Set-Mailbox @Properties
            Write-Log 'Email forward enabled.' -ShowOutput

            Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-LogError $PSItem.Exception.Message -ShowOutput
        Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
    }
    
    $StartDate = $SetEventDateMonths
    $Body = "$($User.Name) was off-boarded 6 months ago. We will now remove sharing permissions on the mailbox, OneDrive, and disable the email and forwarding.
Call forwarding will also be disabled if that was enabled.
If you have any questions please direct them to the organizer of this meeting or reference the helpdesk ticket #$TicketNumber.
    
Regards,
REDACTED IT
"
    # Adds calendar meeting in Outlook to stop sharing the mailbox and disable email forwarding.
    $CreateApp = New-Object -ComObject 'Outlook.Application'
    $CreateEvent = $CreateApp.CreateItem('olAppointmentItem')
    $CreateEvent.MeetingStatus = [Microsoft.Office.Interop.Outlook.OlMeetingStatus]::olMeeting
    $CreateEvent.Subject = "Update mailbox settings for $($User.Name)"
    $CreateEvent.Body = $Body
    $CreateEvent.Location = 'REDACTED'
    $CreateEvent.ReminderSet = $true
    $CreateEvent.Importance = 2
    $CreateEvent.Start = $StartDate
    $CreateEvent.Duration = 30
    $CreateEvent.ReminderMinutesBeforeStart = 15
    $CreateEvent.BusyStatus = 0
    $CreateEvent.Recipients.Add($Manager.UserPrincipalName) | Out-Null
    $CreateEvent.Send()
    $CreateEvent.Save()
    Remove-Variable CreateApp
    Write-Output "Reminder created in Outlook on $StartDate."
    
    # Connects to Microsoft Online.
    # Installs module for current user if they don't have it.
    $MSOnlineCheck = Get-Module -Name MSOnline -ListAvailable
    if (!$MSOnlineCheck) {
        Write-Log 'Microsoft Online Module not installed.' -ShowOutput
        Write-Log 'Installing Microsoft Online Module...' -ShowOutput
        Install-Module -Name MSOnline -Scope CurrentUser
        Write-Log 'Done.' -ShowOutput
    }
    Connect-MsolService -Credential $LicenseCredential
    
    # Disables MFA on the user's account.
    $ClearMFA = @()
    try {
        Set-MsolUser -UserPrincipalName $User.UserPrincipalName -StrongAuthenticationRequirements $ClearMFA -ErrorAction Continue
        Write-Log "Disabling MFA on $($User.Name). MFA has been disabled AFTER the account was disabled." -ShowOutput   
    }
    catch [Microsoft.Online.Administration.Automation.InvalidLicenseConfigurationException] {
        Write-LogWarning 'MFA may already be disabled. Check this manually.' -ShowOutput
    }
    catch [Microsoft.Online.Administration.Automation.SetUserLicense] {
        Write-LogWarning 'MFA may already be disabled. Check this manually.' -ShowOutput
    }
    catch {
        Write-LogError $PSItem.Exception.Message -ShowOutput
    }

    # Removes licenses from the user.
    $Licenses = Get-MsolUser -UserPrincipalName $User.UserPrincipalName
    for ($i = 0; $i -lt $Licenses.Licenses.Count; $i++) {
        # Excludes phone licenses if the phone parameter is used.
        switch ($Licenses.Licenses.AccountSkuId[$i]) {
            'REDACTED2:ATP_ENTERPRISE' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:ATP_ENTERPRISE', 'Advanced Threat Protection') }
            'REDACTED2:EMS' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:EMS', 'Enterprise Mobile Security E3') }
            'REDACTED2:ENTERPRISEPACK' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:ENTERPRISEPACK', 'Office 365 E3') }
            'REDACTED2:FLOW_FREE' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:FLOW_FREE', 'Flow (Free)') }
            'REDACTED2:MCOEV' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:MCOEV', 'Phone System') }
            'REDACTED2:MCOMEETADV' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:MCOMEETADV', 'Audio Conferencing') }
            'REDACTED2:MCOPSTN1' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:MCOPSTN1', 'Domestic Calling') }
            'REDACTED2:PROJECTPROFESSIONAL' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:PROJECTPROFESSIONAL', 'Project Pro') }
            'REDACTED2:STANDARDPACK' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:STANDARDPACK', 'Office 365 E1 (Free)') }
            'REDACTED2:VISIOCLIENT' { $RenamedLicense = $Licenses.Licenses.AccountSkuId[$i].Replace('REDACTED2:VISIOCLIENT', 'Visio Pro') }
        }
        if ($KeepPhone) {
            # Converts the license names into something meaningful.
            if ($Licenses.Licenses.AccountSkuID[$i] -eq 'REDACTED2:MCOEV' -or
                $Licenses.Licenses.AccountSkuID[$i] -eq 'REDACTED2:MCOPSTN1' -or
                $Licenses.Licenses.AccountSkuID[$i] -eq 'REDACTED2:ENTERPRISEPACK'
            ) {
                Write-Log "Phone parameter used, $RenamedLicense for $($User.Name) have not been removed."
                continue
            }
        }
        if ($Licenses.Licenses.AccountSkuID[$i] -eq 'REDACTED2:MCOEV') {
            # The Phone System license must be removed after other licenses but before Office 365 E3.
            continue
        }
        $Properties = @{
            UserPrincipalName = $User.UserPrincipalName
            RemoveLicenses    = $Licenses.Licenses.AccountSkuID[$i]
        }
        if ($Licenses.Licenses.AccountSkuID[$i] -eq 'REDACTED2:ENTERPRISEPACK') {
            continue
        }
        Set-MsolUserLicense @Properties
        Write-Log "Removed $RenamedLicense from $($User.Name)." -ShowOutput
    }
    if ($KeepPhone) {
        Write-Log "Phone parameter used, phone licenses have not been removed." -ShowOutput
    }
    else {
        # These licenses must be removed last and in this order or it will error out due to dependencies.
        Set-MsolUserLicense -UserPrincipalName $User.UserPrincipalName -RemoveLicenses 'REDACTED2:MCOEV'
        Write-Log "Removed Phone System from $($User.Name)." -ShowOutput
        Set-MsolUserLicense -UserPrincipalName $User.UserPrincipalName -RemoveLicenses 'REDACTED2:ENTERPRISEPACK'
        Write-Log "Removed Office 365 E3 from $($User.Name)." -ShowOutput
    }
    
    # Gives the user's manager access to the user's OneDrive.
    # Connects to Microsoft SharePoint Online.
    # Installs module for current user if they don't have it.
    $SPOCheck = Get-Module -Name Microsoft.Online.SharePoint.PowerShell -ListAvailable
    if (!$SPOCheck) {
        Write-Log 'SharePoint Online Module not installed.' -ShowOutput
        Write-Log 'Installing SharePoint Online Module...' -ShowOutput
        Install-Module -Name Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
        Write-Log 'Done.' -ShowOutput
    }
    $URL = 'https://REDACTED2-admin.sharepoint.com'
    $UserURL = "https://REDACTED2-my.sharepoint.com/personal/$($User.SamAccountName)_REDACTED_org"
    Connect-SPOService -Url $URL -Credential $SPOAdmin
    try {
        Set-SPOUser -Site $UserURL -LoginName $Manager.UserPrincipalName -IsSiteCollectionAdmin:$true -ErrorAction Stop | Out-Null
        Write-Log "Gave $($Manager.Name) access to $($User.Name)'s OneDrive." -ShowOutput
        Disconnect-SPOService
    }
    catch {
        Write-LogError $PSItem.Exception.Message -ShowOutput
        Disconnect-SPOService
    }
    #}

    $HelpDeskURL = "http://helpdesk.REDACTED.org/portal/view-help-request/$TicketNumber"
    
    $Body = @"
    <head>
    <style type='text/css'>
        p#Note {
            font-weight: bold;
            font-size: 0.8em;
        }

        span.Bold {
            font-weight: bold;
        }

        ol.Letters {
            list-style-type: lower-alpha
        }
    </style>
</head>

    <body>
        Hello $($Manager.Name),<br />
        Your employee, $($User.Name) has been off-boarded.<br />
        The following actions have been taken against their account.<br /><br />
        
        
        <ol>
            <li>Removed from all groups.</li>
            <li>Password reset to a randomly generated one. For security purposes this password has not been recorded.</li>
            <ol class="Letters">
                <li>If the account needs to be logged into you will need to contact IT.</li>
            </ol>
            <li>Account disabled.</li>
            <li>Phone number recorded - $($User.OfficePhone)</li>
            <li>Mailbox converted into a shared mailbox.</li>
            <li>$($Manager.Name) has been given access to $($User.Name)'s mailbox for 6 months.</li>
            <li>Outlook rules have been removed.</li>
            <li>Auto reply enabled on $($User.Name)'s mailbox.</li>
            <ol class="Letters">
                <li>$($User.Name)'s email will be forwarded to $($Manager.Name) for 6 months.</li>
            </ol>
            <li>All licenses have been removed.</li>
            <li>MFA (Multi Factor Authentication) has been disabled. (This is done AFTER the account has been disabled.)
            </li>
            <li>$($Manager.Name) has been given access to $($User.Name)'s OneDrive.</li>
            <ol class="Letters">
                <li>You can access it <a title="$($User.Name)'s" href="$UserURL">here</a>.
            </ol>
        </ol>
        <br />
        
        All tasks performed against $($User.Name)'s account have been logged and recorded.<br />
        Please send all questions, comments and concerns <a title="" href="$HelpDeskURL">here</a>.<br /><br />
        Regards,<br />
        REDACTED IT
        <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
    </body>
"@

    $Properties = @{
        To         = $Manager.UserPrincipalName
        From       = 'noreply@REDACTED.org'
        CC         = 'helpdesk@REDACTED.org'
        Subject    = "[Ticket #$TicketNumber]"
        Body       = $Body
        BodyAsHtml = $true
        SMTPServer = 'REDACTED'
        UseSSL     = $true
        Priority   = 'High'
    }
    Send-MailMessage @Properties
    Write-Log 'Email sent.' -ShowOutput
    Write-Log "$($User.Name) has been offboarded. Don't forget to remove their card info in ADT." -ShowOutput
    Stop-Log -ScriptName "Disable-User - $Identity"
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Disable-User -ParameterName Identity -ScriptBlock $IdentityBlock


function Enter-SSPSSession {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Enters a new PSSession on the target machine.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER ComputerName
    Enters a PSSession on the target computer.
.PARAMETER ServerName
    Enters a PSSession on the target server.
.EXAMPLE
    Enter-SSPSSession -Help
.EXAMPLE
    Enter-SSPSSession -ComputerName DT-ComputerName
.EXAMPLE
    Enter-SSPSSession -ServerName Server1
.EXAMPLE
    pss -ComputerName DT-ComputerName
.EXAMPLE
    pss -ServerName Server1
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    [Alias('pss')]
    param (
        [Parameter(ParameterSetName = "Endpoint", Position = 0, Mandatory = $true)][string]$ComputerName,
        [Parameter(ParameterSetName = "Server", Position = 0, Mandatory = $true)][string]$ServerName,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
    }
    
    if ($ServerName) {
        $Username = Read-Host -Prompt 'Enter Admin Username'
        Enter-PSSession -ComputerName $ServerName -Credential $env:USERDOMAIN\$Username
    }
    else {
        $TestConnection = Test-Connection $ComputerName -Quiet -Count 1
        if ($TestConnection) {
            Enter-PSSession -ComputerName $ComputerName
        }
        else {
            Write-Output "$ComputerName is currently offline or unavailable."
        }
    }
}

$ComputerNameBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Enter-SSPSSession -ParameterName ComputerName -ScriptBlock $ComputerNameBlock

$ServerNameBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Enter-SSPSSession -ParameterName ServerName -ScriptBlock $ServerNameBlock


function Get-Computer {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Returns useful information about a specific computer.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the computer you wish to query.
.PARAMETER BitLockerKey
    Outputs the BitLocker recovery key.
.EXAMPLE
    Get-Computer -Help
.EXAMPLE
    Get-Computer -Identity LT-MPOLSELLI
.EXAMPLE
    Get-Computer -Identity LT-MPOLSELLI -BitLockerKey
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$BitLockerKey,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    
    $Computer = Get-ADComputer -Identity $Identity -Properties * |
    Select-Object 'Created', 'Description', 'DistinguishedName', 'DNSHostName',
    'Enabled', 'IPv4Address', 'isDeleted', 'LastLogonDate', 'Location', 'LockedOut',
    'logonCount', 'Modified', 'Name', 'ObjectGUID', 'objectSid', 'OperatingSystem'
    Write-Output $Computer | Format-List
    
    $TestConnection = Test-Connection $Identity -Quiet -Count 1
    if ($TestConnection) {
        $LastBootUp = Get-CimInstance -ComputerName $Identity -ClassName Win32_OperatingSystem |
        Select-Object LastBootUpTime
        Write-Output $LastBootUp
    }
    else {
        Write-Output "Unable to get last boot-up time.`nDevice is currently offline or unavailable."
    }

    if ($BitLockerKey) {
        $Credential = Use-PSCred PSADAcctMgmt
        $Properties = @{
            Filter     = { ObjectClass -eq 'msFVE-RecoveryInformation' }
            SearchBase = $Computer.DistinguishedName
            Properties = 'msFVE-RecoveryPassword'
            Credential = $Credential
        }
        $BitLocker_Object = Get-ADObject @Properties | Select-Object @{n = 'Recovery Key'; e = { $PSItem.'msFVE-RecoveryPassword' } }
        Write-Output $BitLocker_Object
    }    
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-Computer -ParameterName Identity -ScriptBlock $IdentityBlock


function Get-FolderPermissions {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Outputs the permissions of a folder in a clear format.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Path
    Specifies the path you want to query.
.EXAMPLE
    Get-FolderPermissions -Help
.EXAMPLE
    Get-FolderPermissions -Path \\ad.REDACTED.org\IT\Software
.EXAMPLE
    Get-FolderPermissions -Path 'S:\Client Invoices'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]
        [ValidateScript( {
                if (-Not ($PSItem | Test-Path ) ) {
                    throw 'Invalid Path.'
                }
                return $true
            })][System.IO.FileInfo]$Path,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    try {
        Get-Acl -Path $Path | Select-Object -ExpandProperty Access |
        Select-Object IdentityReference, FileSystemRights, IsInherited |
        Where-Object {$PSItem.IdentityReference -like "REDACTED\*" -or $PSItem.IdentityReference -eq 'Everyone'}
    }
    catch [System.UnauthorizedAccessException] {
        Write-Warning 'You do not have access to this folder, run as admin.'
    }
    catch {
        Write-Warning $PSItem.Exception.Message
    }
}



function Get-ForwardDNSLookup {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER FQDN
    Enter the FQDN you wish to perform a forward DNS lookup on.
.EXAMPLE
    Get-ReverseDNSLookup -Help
.EXAMPLE
    Get-ReverseDNSLookup -FQDN google.com
.EXAMPLE
    rdns google.com
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    [Alias("fdns")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$FQDN,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    try {
        Resolve-DnsName $FQDN -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress -ErrorAction Stop
    }
    catch {
    Write-Warning $PSItem.Exception.Message
    }
}



function Get-HelpOnline {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Opens the official Microsoft help page for a PowerShell cmdlet.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Command
    Specifies the command you are getting help on.
.EXAMPLE
    Get-HelpOnline -Help
.EXAMPLE
    Get-HelpOnline -Command Get-ADUser
.EXAMPLE
    h Get-ADUser
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [Alias("h")]
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Command,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name | more
        break
    }
    
    try {
        Get-Help $Command -Online -ErrorAction Stop
    }
    catch {
        Write-Warning "The command $Command was either not found or does not have the built in forwarder.`nTry searching for the command online."
    }
}


function Get-IP {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Has multiple uses:
                1. Display your IP address in a clean format.
                2. Display your DNS Server(s).
                3. Display your Default Gateway.
                4. Display your Mac Address.
                5. Get the IP address(es) of other computers.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER DNS
    Outputs your DNS server(s).
.PARAMETER DefaultGateway
    Outputs your Default Gateway.
.PARAMETER MacAddress
    Outputs your Mac Address.
.PARAMETER Computer
    Gets the IP address(es) of a remote computer.
.EXAMPLE
    IP -Help
.EXAMPLE
    Get-IP -DNS -DefaultGateway -MacAddress
.EXAMPLE
    Get-IP -Computer 'LT-Computer'
.EXAMPLE
    IP -DNS -DefaultGateway -MacAddress
.EXAMPLE
    IP -DNS
.EXAMPLE
    IP -DefaultGateway
.EXAMPLE
    IP -MacAddress
.EXAMPLE
    IP -Computer 'LT-Computer'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    [Alias("IP")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0)][switch]$DNS,
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$DefaultGateway,
        [Parameter(ParameterSetName = "Primary", Position = 2)][switch]$MacAddress,
        [Parameter(ParameterSetName = "Computer", Position = 0)][string]$Computer,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($Computer) {
        $Records = Get-DnsServerResourceRecord -ZoneName ad.REDACTED.org -ComputerName REDACTED -Name $Computer |
        Select-Object RecordData -ExpandProperty RecordData |
        Select-Object IPv4Address -ExpandProperty IPv4Address
        Write-Output "IP Address(es): $Records"
        #TODO: Get mac address of other computers?
        break
    }

    $IP = Get-NetIPAddress | Where-Object { $PSItem.PrefixOrigin -eq 'DHCP' -or $PSItem.PrefixOrigin -eq 'Static' } |
    Select-Object IPAddress -ExpandProperty IPAddress
    Write-Output "IP: $IP"
    if ($DNS) {
        $GetDNS = Get-NetIPConfiguration |
        Where-Object {$PSItem.NetAdapter.Status -eq 'Up'} |
        Select-Object DNSServer -ExpandProperty DNSServer |
        Select-Object ServerAddresses |
        Where-Object {$null -ne $PSItem.ServerAddresses} |
        Select-Object ServerAddresses -ExpandProperty ServerAddresses
        Write-Output "DNS: $GetDns"
    }
    if ($DefaultGateway) {
        $GetDefaultGateway = Get-NetIPConfiguration |
        Select-Object IPv4DefaultGateway -ExpandProperty IPv4DefaultGateway |
        Select-Object NextHop -ExpandProperty NextHop
        Write-Output "Default Gateway: $GetDefaultGateway"
    }
    if ($MacAddress) {
        $GetMacAddress = Get-NetIPConfiguration |
        Where-Object {$PSItem.NetAdapter.Status -eq 'Up'} |
        Select-Object NetAdapter -ExpandProperty NetAdapter |
        Select-Object Name, MacAddress
        Write-Output $GetMacAddress
    }
}

$ComputerBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-IP -ParameterName Computer -ScriptBlock $ComputerBlock


function Get-Office365Licenses {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Outputs the licenses from Office365, uses and unused.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Get-Office365Licenses -Help
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

    try {
        # Installs module for current user if they don't have it.
        $MSOnlineCheck = Get-Module -Name MSOnline -ListAvailable
        if (!$MSOnlineCheck) {
            Write-Log 'Microsoft Online Module not installed.' -ShowOutput
            Write-Log 'Installing Microsoft Online Module...' -ShowOutput
            Install-Module -Name MSOnline -Scope CurrentUser
            Write-Log 'Done.' -ShowOutput
        }
        $Credential = Use-PSCred -Identity PSLicenseAdmin -Email
        Connect-MsolService -Credential $Credential
        $Licenses = Get-MsolAccountSku | Sort-Object -Property AccountSkuID
        $RenamedLicenses = @()
        foreach ($License in $Licenses) {
            switch ($License.AccountSkuId) {
                'REDACTED2:ATP_ENTERPRISE' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:ATP_ENTERPRISE', 'Advanced Threat Protection') }
                'REDACTED2:EMS' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:EMS', 'Enterprise Mobile Security E3') }
                'REDACTED2:ENTERPRISEPACK' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:ENTERPRISEPACK', 'Office 365 E3') }
                'REDACTED2:FLOW_FREE' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:FLOW_FREE', 'Flow (Free)') }
                'REDACTED2:MCOEV' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MCOEV', 'Phone System') }
                'REDACTED2:MCOMEETADV' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MCOMEETADV', 'Audio Conferencing') }
                'REDACTED2:MCOPSTN1' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MCOPSTN1', 'Domestic Calling') }
                'REDACTED2:MEETING_ROOM' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MEETING_ROOM', 'Meeting Room') }
                'REDACTED2:MS_TEAMS_IW' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MS_TEAMS_IW', 'Teams Trial (Free)') }
                'REDACTED2:NONPROFIT_PORTAL' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:NONPROFIT_PORTAL', 'Non-profit Portal (Free)') }
                'REDACTED2:POWER_BI_STANDARD' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:POWER_BI_STANDARD', 'PowerBI Standard (Free)') }
                'REDACTED2:PROJECTPROFESSIONAL' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:PROJECTPROFESSIONAL', 'Project Pro') }
                'REDACTED2:STANDARDPACK' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:STANDARDPACK', 'Office 365 E1 (Free)') }
                'REDACTED2:VISIOCLIENT' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:VISIOCLIENT', 'Visio Pro') }
                'REDACTED2:WINDOWS_STORE' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:WINDOWS_STORE', 'Windows Store (Free?)') }
            }
        }
    
        $TableName = 'Office365 Licenses'
        $Table = New-Object System.Data.DataTable $TableName
        $ColumnNames = @('License Name', 'Active', 'Total', 'Unused')
        foreach ($Name in $ColumnNames) {
            $Column = New-Object System.Data.DataColumn $Name
            $Table.Columns.Add($Column)
        }
    
        for ($i = 0; $i -lt $RenamedLicenses.Count; $i++) {
            New-Variable -Name Row$i -Force
            $Row = $Table.NewRow()
            $Row.'License Name' = $RenamedLicenses[$i]
            $Row.Active = $Licenses.ConsumedUnits[$i]
            $Row.Total = $Licenses.ActiveUnits[$i]
            $Row.Unused = $Licenses.ActiveUnits[$i] - $Licenses.ConsumedUnits[$i]
            $Table.Rows.Add($Row)
        }
        Get-PSSession | Remove-PSSession
        return $Table
    }
    catch {
        Write-Warning $PSITem.Exception.Message
        Get-PSSession | Remove-PSSession
    }
}


function Get-ReverseDNSLookup {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Performs a reverse DNS lookup.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER IP
    Enter the IP you wish to perform a reverse DNS lookup on.
.EXAMPLE
    Get-ReverseDNSLookup -Help
.EXAMPLE
    Get-ReverseDNSLookup -IP 8.8.8.8
.EXAMPLE
    rdns 8.8.8.8
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    [Alias("rdns")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][IPAddress]$IP,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    try {
        Resolve-DnsName $IP -ErrorAction Stop | Select-Object -ExpandProperty NameHost
    }
    catch {
    Write-Warning $PSItem.Exception.Message
    }
}


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


function New-List {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
     -Help
#>
    New-Object System.Collections.Generic.List[System.Object]
}


function New-User {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.1
    Language:   PowerShell
    Purpose:    Function used for onboarding a new user.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER EmployeeFile
    Used to specify the file that contains the information needed to onboard the new user.
.PARAMETER TicketNumber
    Ticket that references the new hire job order.
.EXAMPLE
    New-User -Help
.EXAMPLE
    New-User -EmployeeFile C:\Path\To\File.xlsx -TicketNumber 12345
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    #REQUIRES -Modules PSCreds,Logging
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$EmployeeFile,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$TicketNumber,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    #Write-Warning 'Still in development.'
    #break

    # Gets the credentials we need.
    $ADCredential = Use-PSCred -Identity PSADAcctMgmt
    $LicenseCredential = Use-PSCred -Identity PSLicenseAdmin -Email
    $TeamsCredential = Use-PSCred -Identity PSTeamsAdmin -Email

    # Logging
    $FileName = ($EmployeeFile | Split-Path -Leaf).Replace('.xlsx', '')
    Start-Log -ScriptName $FileName
    Write-Log "$FileName is being run by $env:USERNAME"
    
    # Checks for the ImportExcel module.
    $ExcelCheck = Get-Module -Name ImportExcel -ListAvailable
    try {
        if (!$ExcelCheck) {
            Write-Output "ImportExcel module is not installed.`nInstalling."
            Install-Module ImportExcel -Scope CurrentUser -ErrorAction Stop
            Write-Output 'Done.'
        }
    }
    catch {
        Write-Warning 'Failed to install ImportExcel module!'
        break
    }

    # Checks for the export macro.
    $MacroCheck = Test-Path "$env:APPDATA\Microsoft\Word\Startup\*.dotm"
    if (!$MacroCheck) {
        Write-Output 'Missing export macro.'
        Copy-Item \\$env:USERDNSDOMAIN\IT\PowerShell\Modules\Utilities\*.dotm -Destination "$env:APPDATA\Microsoft\Word\Startup\"
        Write-Output 'Copied macro to word startup folder.'
    }

    # Get and imports the employee data.
    try {
        $UserData = Import-Excel -Path $EmployeeFile -ErrorAction Stop
        $UserData = $UserData[1]
    }
    catch {
        Write-LogError "Failed to import data, stopping."
        Write-LogError $PSItem.Exception.Message
    }

    # Gets the managers AD Account info.
    try {
        $Manager = $UserData.Manager
        $Manager = Get-ADUser -Filter { Name -eq $Manager } -ErrorAction Stop
    }
    catch {
        Write-LogError "Failed to get manager info. $($UserData.Manager) was not found."
        Write-LogError $PSItem.Exception.Message
    }

    # Builds the users account.
    $Properties = @{
        Company           = 'REDACTED'
        Confirm           = $false
        Credential        = $ADCredential
        Department        = $UserData.Department
        Description       = $UserData.Title
        DisplayName       = $UserData.PreferredName
        EmailAddress      = "$(($UserData.PreferredName).Split(" ")[0][0]+($UserData.PreferredName).Split(" ")[1])"+'@REDACTED.org'
        EmployeeID        = $UserData.EmployeeID
        ErrorAction       = 'Stop'
        Fax               = $UserData.SecurityCard
        GivenName         = "$(($UserData.PreferredName).Split(" ")[0])"
        Manager           = $Manager.SamAccountName
        Name              = $UserData.PreferredName
        Office            = $UserData.OfficeLocation
        Organization      = 'REDACTED'
        SamAccountName    = "$(($UserData.PreferredName).Split(" ")[0][0]+($UserData.PreferredName).Split(" ")[1])"
        Surname           = "$(($UserData.PreferredName).Split(" ")[1])"
        Title             = $UserData.Title
        UserPrincipalName = "$(($UserData.PreferredName).Split(" ")[0][0]+($UserData.PreferredName).Split(" ")[1])"+'@REDACTED.org'
    }
    try {
        New-ADUser @Properties
    }
    catch {
        Write-LogError $PSItem.Exception.Message -ShowOutput
        break
    }
    
    # Gets the new users data, used in other spots.
    $Name = $UserData.PreferredName
    $Prop = @(
        'Manager', 'Department', 'Title', 'Fax',
        'EmployeeID', 'OfficePhone', 'Office'
    )
    $Properties = @{
        Filter     = { Name -eq $Name }
        Properties = $Prop
    }
    try {
        $NewUser = Get-ADUser @Properties -ErrorAction Stop
    }
    catch {
        Write-LogError 'Failed to create user! Stopping.'
        Write-LogError $PSItem.Exception.Message
    }
    
    # Creates a randomly generated password.
    [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
    do {
        $RandomPW = [System.Web.Security.Membership]::GeneratePassword(12, 4)
    }
    Until ($RandomPW -match '^(?=.*[A-Z].*[A-Z])(?=.*[!@#$%^&*()_])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{12}$')

    # Sets the account password and flags the account for password reset on login, also enables the account
    $Properties = @{
        Identity    = $NewUser.SamAccountName
        Reset       = $true
        NewPassword = ($RandomPW | ConvertTo-SecureString -AsPlainText -Force)
        Credential  = $ADCredential
        ErrorAction = 'Stop'
    }
    Set-ADAccountPassword @Properties
    Set-ADUser -Identity $NewUser.SamAccountName -ChangePasswordAtLogon:$true -Credential $ADCredential
    Enable-ADAccount -Identity $NewUser.SamAccountName -Credential $ADCredential -Confirm:$false

    # Sets the account to expire if an end date is specified.
    if ($UserData.EndDate) {
        Set-ADAccountExpiration -Identity $NewUser -DateTime $UserData.EndDate -Credential $ADCredential
    }

    # Sets information in the user accounts notes and other attributes.
    $IT = "IT Notes = $($UserData.ITNotes)"
    $HR = "HR Notes = $($UserData.HRNotes)"
    $MN = "Manager Notes = $($UserData.ManagerNotes)"
    $TN = "New Hire Ticket Number = $TicketNumber"
    Get-ADUser -Identity $NewUser.SamAccountName -Properties Info | 
    Foreach-Object { Set-ADUser -Identity $PSItem.SamAccountName -Replace @{Info = "$($PSItem.Info)$IT,$HR,$MN,$TN" } -Credential $ADCredential }
    Set-ADUser -Identity $NewUser.SamAccountName -Replace @{
        EmployeeType        = $UserData.EmploymentType
        EmployeeNumber      = $UserData.DeskLocation
        ExtensionAttribute1 = $UserData.ComputerType
        ExtensionAttribute2 = $UserData.StartDate
    } -Credential $ADCredential

    # Add direct reports, if any.
    if ($null -ne $UserData.DirectReports) {
        foreach ($Report in $UserData.DirectReports.Split(',')) {
            $UserToAdd = $Report.TrimEnd().TrimStart()
            try {
                $UserToAdd = Get-ADUser -Filter { Name -eq $UserToAdd } -ErrorAction Continue
                $Properties = @{
                    Identity   = $UserToAdd.SamAccountName
                    Manager    = $NewUser.SamAccountName
                    Credential = $ADCredential
                }
                Set-ADUser @Properties
            }
            catch {
                Write-LogWarning "$UserToAdd not found." -ShowOutput
            }
        }
    }

    # Adds groups copied from another user.
    $UserToCopy = $UserData.UserToCopy.TrimEnd().TrimStart()
    $GroupsToCopy = Get-ADUser -Filter { Name -eq $UserToCopy }
    $GroupsToCopy = Get-ADPrincipalGroupMembership -Identity $GroupsToCopy.SamAccountName
    foreach ($Group in $GroupsToCopy) {
        try {
            $Properties = @{
                Identity    = $Group.Name
                Members     = $NewUser.SamAccountName
                Credential  = $ADCredential
                Confirm     = $false
                ErrorAction = 'Continue'
            }
            Add-ADGroupMember @Properties
        }
        catch {
            continue
        }
    }

    # Adds the user to the VPN group if specified.
    if ($UserData.VPN -eq 'Yes') {
        Add-UserToVPN -Identity $NewUser.Name
    }

    # Syncs with Azure AD. This part will take a few minutes.
    Write-Output "Syncing Azure AD.`nEnter admin credentials."
    Sync-AzureAD
    $Seconds = 120
    for ($i = 0; $i -lt $Seconds; $i++) {
        $Percent = [System.Math]::Round($i * 100 / $Seconds)
        Write-Progress -Activity 'Syncing with Azure AD. This will take a few minutes.' -Status "$Percent%" -PercentComplete $Percent
        Start-Sleep 1
    }

    # Connects to Exchange.
    $Commands = @('Add-MailboxPermission', 'Set-MailboxFolderPermission', 'Set-CasMailbox')
    Connect-Exchange -Commands $Commands

    # Installs module for current user if they don't have it.
    $MSOnlineCheck = Get-Module -Name MSOnline -ListAvailable
    if (!$MSOnlineCheck) {
        Write-Log 'Microsoft Online Module not installed.' -ShowOutput
        Write-Log 'Installing Microsoft Online Module...' -ShowOutput
        Install-Module -Name MSOnline -Scope CurrentUser
        Write-Log 'Done.' -ShowOutput
    }
    # Tries to avoid having to manually assign licenses.
    do {
        $LicenseCheck = Read-Host -Prompt "Have you added the required licenses to our O365 subscription yet? [Y][N]"
    } until ($LicenseCheck -eq 'Y');
    # Assigns the default licenses.
    Connect-MsolService -Credential $LicenseCredential
    $Licenses = @{
        'Office 365 E3'              = 'REDACTED2:ENTERPRISEPACK'
        'Phone System'               = 'REDACTED2:MCOEV'
        'Advanced Threat Protection' = 'REDACTED2:ATP_ENTERPRISE'
        'Enterprise Mobile Security' = 'REDACTED2:EMS'
        'Audio Conferencing'         = 'REDACTED2:MCOMEETADV'
        'Domestic Calling'           = 'REDACTED2:MCOPSTN1'
    }
    # Sets the user's location. Required to set licenses.
    Set-MSolUser -UserPrincipalName $NewUser.UserPrincipalName -UsageLocation US
    $Licenses = @(
        'REDACTED2:ENTERPRISEPACK',
        'REDACTED2:MCOEV',
        'REDACTED2:ATP_ENTERPRISE',
        'REDACTED2:EMS',
        'REDACTED2:MCOMEETADV',
        'REDACTED2:MCOPSTN1'
    )
    for ($i = 0; $i -lt $Licenses.Count; $i++) {
        Set-MsolUserLicense -UserPrincipalName $NewUser.UserPrincipalName -AddLicenses $Licenses[$i] -ErrorAction Continue
        if ($Licenses[$i] -eq 'REDACTED2:ENTERPRISEPACK') {
            $Seconds = 210
            for ($d = 0; $d -lt $Seconds; $d++) {
                $Percent = [System.Math]::Round($d * 100 / $Seconds)
                Write-Progress -Activity 'Applying licenses. This will take a few minutes.' -Status "$Percent%" -PercentComplete $Percent
                Start-Sleep -Seconds 1
            }
            $Properties = @{
                Identity     = ($($NewUser.SamAccountName) + ':\Calendar')
                User         = 'Default'
                AccessRights = 'Reviewer'
            }
            # Shares the calendar.
            Set-MailboxFolderPermission @Properties
            # Disables OWA by default.
            Set-CasMailbox -Identity $NewUser.SamAccountName -OWAEnabled $false
        }
        Write-Log "License Applied:$($Licenses[$i])" -ShowOutput
    }

    if ($UserData.Visio -eq 'Yes') {
        $VisioSKU = 'REDACTED2:VISIOCLIENT'
        try {
            Set-MsolUserLicense -UserPrincipalName $NewUser.UserPrincipalName -AddLicenses $VisioSKU -ErrorAction Continue
            Write-Log "Visio license applied." -ShowOutput
        }
        catch {
            Write-LogWarning "Unable to assign the $Value license! Please assign $Value to $($NewUser.Name) manually." -ShowOutput
        }
    }
    if ($UserData.Project -eq 'Yes') {
        $ProjectSKU = 'REDACTED2:PROJECTPROFESSIONAL'
        try {
            Set-MsolUserLicense -UserPrincipalName $NewUser.UserPrincipalName -AddLicenses $ProjectSKU -ErrorAction Continue
            Write-Log "Project license applied." -ShowOutput
        }
        catch {
            Write-LogWarning "Unable to assign the $Value license! Please assign $Value to $($NewUser.Name) manually." -ShowOutput
        }
    }

    # Enables MFA
    $MFA = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
    $MFA.RelyingParty = "*"
    $MFA.State = 'Enabled'
    $EnableMFA = @($MFA)
    try {
        Set-MsolUser -UserPrincipalName $NewUser.UserPrincipalName -StrongAuthenticationRequirements $EnableMFA -ErrorAction Continue
        Write-Log "Enabling MFA on $($NewUser.Name)." -ShowOutput   
    }
    catch [Microsoft.Online.Administration.Automation.InvalidLicenseConfigurationException] {
        Write-LogWarning 'Error Encountered. Check this manually.' -ShowOutput
    }
    catch [Microsoft.Online.Administration.Automation.SetUserLicense] {
        Write-LogWarning 'Error Encountered. Check this manually.' -ShowOutput
    }
    catch {
        Write-LogWarning 'Error Encountered. Check this manually.' -ShowOutput
        Write-LogError $PSItem.Exception.Message -ShowOutput
    }
    
    # Test this and make sure the data is sent as an array and not a string
    if ($null -ne $UserData.SharedMailboxes) {
        $SharedMailboxes = @($UserData.SharedMailboxes -replace ' ', '' -split ',')
        foreach ($Mailbox in $SharedMailboxes) {
            $Properties = @{
                Identity     = $Mailbox
                User         = $NewUser.SamAccountName
                AccessRights = 'FullAccess'
                Confirm      = $false
            }
            Add-MailboxPermission @Properties | Out-Null
            Write-Log "Added $($NewUser.Name) to $Mailbox." -ShowOutput
        }
    }

    # Installs module for current user if they don't have it.
    $TeamsModuleCheck = Get-Module -Name MicrosoftTeams -ListAvailable
    if (!$TeamsModuleCheck) {
        Write-Log 'Microsoft Teams Module not installed.' -ShowOutput
        Write-Log 'Installing Microsoft Teams Module...' -ShowOutput
        Install-Module -Name MicrosoftTeams -Scope CurrentUser
        Write-Log 'Done.' -ShowOutput
    }
    # Connects to Teams and adds the user to the standard Team's.
    Connect-MicrosoftTeams -Credential $TeamsCredential
    Get-Team -DisplayName 'REDACTED General' | Add-TeamUser -User $NewUser.UserPrincipalName
    switch ($NewUser.Office) {
        'REDACTED' { Get-Team -DisplayName 'Office Announcements' | Add-TeamUser -User $NewUser.UserPrincipalName; break }
        'Chicago' { Get-Team -DisplayName 'Chicago' | Add-TeamUser -User $NewUser.UserPrincipalName; break }
    }

    # Notifies Grant of SharePoint sites to give the user access to.
    if ($null -ne $UserData.SharePointSites) {
        $SharePointSites = @($UserData.SharePointSites -replace ' ', '' -split ',')
    }
    if ($UserData.SharePointSites) {
        $Body = @"
        <head>
        <style type='text/css'>
            ul {
                list-style-type: square;
            }
    
            span.Bold {
                font-weight: bold;
            }
        </style>
    </head>
    
    <body>
        Hello,<br /><br />
        Please add $($NewUser.Name) to the below SharePoint sites.<br />
        $SharePointSites
    </body>
"@
    }
    $Properties = @{
        To         = 'helpdesk@REDACTED.org'
        CC         = 'REDACTED@REDACTED.org'
        From       = 'noreply@REDACTED.org'
        Subject    = "New Hire SharePoint Access - $($NewUser.Name)"
        Body       = $Body
        BodyAsHTML = $true
        SMTPServer = 'REDACTED'
        UseSSL     = $true
    }
    Send-MailMessage @Properties

    # Gives the licenses some time to activate, this should avoid errors when assigning a phone number
    $Seconds = 300
    for ($d = 0; $d -lt $Seconds; $d++) {
        $Percent = [System.Math]::Round($d * 100 / $Seconds)
        Write-Progress -Activity 'Activating licenses. This will take a few minutes.' -Status "$Percent%" -PercentComplete $Percent
        Start-Sleep -Seconds 1
    }

    # Connects to O365 and assigns a number to the user
    $TeamsModuleCheck = Get-Module -Name SkypeOnlineConnector -ListAvailable
    if (!$TeamsModuleCheck) {
        Write-Log 'Microsoft Teams Module not installed.' -ShowOutput
        Write-Log 'Installing Microsoft Teams Module...' -ShowOutput
        Set-Location \\$env:USERDNSDOMAIN\IT\PowerShell\Modules\Utilities\
        .\SkypeOnlinePowerShell.exe /install /quiet /norestart
        Write-Log 'Done.' -ShowOutput
    }
    $Session = New-CsOnlineSession -Credential $TeamsCredential
    $Commands = @(
        'Set-CsOnlineVoiceUser', 'Get-CsOnlineLisLocation',
        'Get-CsOnlineTelephoneNumber'
    )
    Import-PSSession $Session -CommandName $Commands -AllowClobber
    $UnassignedNumber = Get-CsOnlineTelephoneNumber -IsNotAssigned | Select-Object -First 1
    if ($NewUser.Office -eq 'Remote') {
        $LocationID = Get-CsOnlineLisLocation -City REDACTED    
    }
    else {
        $LocationID = Get-CsOnlineLisLocation -City $NewUser.Office
    }
    Set-CsOnlineVoiceUser -Identity $NewUser.UserPrincipalName -TelephoneNumber $UnassignedNumber.ID -LocationID $LocationID.LocationID
    Set-ADUser -Identity $NewUser.SamAccountName -OfficePhone $('+' + $UnassignedNumber.ID) -Credential $ADCredential
    Get-PSSession | Remove-PSSession
    # Allows the phone number to be set in AD.
    Start-Sleep -Seconds 10
    
    # Creates the Word object and modifies the document
    $Template = "\\$env:USERDNSDOMAIN\IT\PowerShell\Modules\Utilities\REDACTED Letterhead REDACTED.docx"
    $App = New-Object -ComObject Word.Application
    $App.Visible = $false
    $Word = $App.Documents.Open($Template)
    $Doc = $App.Selection
    $DocName = "C:\Temp\New Hire - $($NewUser.Name).docx"

    # Formats the word doc
    $Doc.Font.Name = 'Microsoft JhengHei UI'
    function Title {
        $Doc.Font.Italic = 1
        $Doc.Font.Bold = 1
        $Doc.Font.TextColor.RGB = -738131969 # Blue
        $Doc.Paragraphs.Alignment = 1 # Centers the text
        $Doc.ParagraphFormat.SpaceAfter = 0
        $Doc.Font.Size = 22
    }
    function Title2 {
        $Doc.Font.Italic = 0
        $Doc.Font.Bold = 0
        $Doc.Paragraphs.Alignment = 1 # Centers the text
        $Doc.Font.TextColor.RGB = -16777216 # Black
        $Doc.Font.Size = 12
    }
    function Heading {
        $Doc.Font.Bold = 1
        $Doc.Font.Italic = 1
        $Doc.Paragraphs.Alignment = 0 # Aligns text to the left
        $Doc.Font.TextColor.RGB = -16777216 # Black
        $Doc.Font.Name = 'Microsoft JhengHei UI'
        $Doc.Font.Size = 18
    }
    function Paragraph {
        $Doc.Font.Italic = 0
        $Doc.Font.Bold = 0
        $Doc.Paragraphs.Alignment = 0 # Aligns text to the left
        $Doc.Font.TextColor.RGB = -16777216 # Black
        $Doc.Font.Name = 'Microsoft JhengHei UI'
        $Doc.Font.Size = 12
    }
    function BulletParagraph {
        $Doc.Font.Italic = 0
        $Doc.Font.Bold = 1
        $Doc.Paragraphs.Alignment = 0 # Aligns text to the left
        $Doc.Font.TextColor.RGB = -16777216 # Black
        $Doc.Font.Name = 'Microsoft JhengHei UI'
        $Doc.Font.Size = 12
        $Doc.Range.ListFormat.ApplyListTemplate($Word.Application.ListGalleries[1].ListTemplates[3])
    }
    function NewBulletLine {
        param (
            $BulletHeader,
            $BulletText,
            $BulletHyperLink,
            $BulletHyperLinkText
        )
        BulletParagraph
        $Doc.TypeText("$BulletHeader`:  ")
        Paragraph
        $Doc.TypeText($BulletText)
        if ($BulletHyperLink) {
            $Doc.Hyperlinks.Add($Doc.Range, $BulletHyperLink, $null, $null, $BulletHyperLinkText)
        }
        $Doc.TypeParagraph()
    }

    Title
    $Doc.TypeText("Welcome $($NewUser.Name)")
    $Doc.TypeParagraph()
    Title2
    $Doc.TypeText('We have put together some information that will help you get started.')
    $Doc.TypeParagraph()
    Heading
    $Doc.TypeText('General Information')
    $Doc.TypeParagraph()
    NewBulletLine -BulletHeader 'Username' -BulletText $NewUser.SamAccountName
    NewBulletLine -BulletHeader 'Password' -BulletText $RandomPW
    NewBulletLine -BulletHeader 'Email Address' -BulletText $NewUser.UserPrincipalName
    NewBulletLine -BulletHeader 'Phone Number' -BulletText $NewUser.TelephoneNumber
    NewBulletLine -BulletHeader 'Employee ID' -BulletText $NewUser.EmployeeID
    NewBulletLine -BulletHeader 'Security Card Number' -BulletText $NewUser.Fax
    NewBulletLine -BulletHeader 'Manager' -BulletText $Manager.Name
    NewBulletLine -BulletHeader 'Department' -BulletText $NewUser.Department
    NewBulletLine -BulletHeader 'Title' -BulletText $NewUser.Title
    $Doc.Style = 'Normal'
    Heading
    $Doc.TypeText('Contact People')
    $Doc.TypeParagraph()
    NewBulletLine -BulletHeader 'HR Contact' -BulletText 'Kerri Hall - ' -BulletHyperLink 'mailto:REDACTED@REDACTED.org' -BulletHyperLinkText 'REDACTED@REDACTED.org'
    NewBulletLine -BulletHeader 'Payroll Contact' -BulletText 'Lyra Trapp - ' -BulletHyperLink 'mailto:REDACTED@REDACTED.org' -BulletHyperLinkText 'REDACTED@REDACTED.org'
    NewBulletLine -BulletHeader 'Manager Contact' -BulletText "$($Manager.Name) - " -BulletHyperLink "mailto:$($Manager.UserPrincipalName)" -BulletHyperLinkText ($Manager.UserPrincipalName)
    NewBulletLine -BulletHeader 'REDACTED Main Number' -BulletHyperLink 'tel:REDACTED' -BulletHyperLinkText 'REDACTED'
    $Doc.Style = 'Normal'
    Heading
    $Doc.TypeText('Useful Links')
    $Doc.TypeParagraph()
    NewBulletLine -BulletHeader 'Time Entry' -BulletHyperLink 'https://REDACTED.REDACTED.org/' -BulletHyperLinkText 'REDACTED.REDACTED.org'
    NewBulletLine -BulletHeader 'REDACTED Central (Intranet)' -BulletHyperLink 'https://intranet.REDACTED.org:444/SitePages/Home.aspx' -BulletHyperLinkText 'intranet.REDACTED.org'
    NewBulletLine -BulletHeader 'Helpdesk Ticket Submission' -BulletHyperLink 'http://helpdesk.REDACTED.org/portal' -BulletHyperLinkText 'helpdesk.REDACTED.org/portal'
    NewBulletLine -BulletHeader 'Floor Plan' -BulletHyperLink 'https://intranet.REDACTED.org:444/aboutus/SitePages/Office%20Floor%20Plan.aspx' -BulletHyperLinkText 'intranet.REDACTED.org'
    $Doc.Style = 'Normal'
    $Word.SaveAs($DocName)
    $Word.Close()
    $App.Application.Quit()
    
    # Prints the document to the print anywhere printer.
    try {
        $DefaultPrinter = (Get-WmiObject -ClassName Win32_Printer -Filter "Default=$true").Name
        if ($DefaultPrinter -notlike "*Print Anywhere*") {
            $null = (Get-WmiObject -ClassName Win32_Printer -Filter "Name='Print Anywhere'").SetDefaultPrinter()
        }
        Start-Process -FilePath $DocName -Verb Print
        $null = (Get-WmiObject -ClassName Win32_Printer -Filter "Name='$DefaultPrinter'").SetDefaultPrinter()
    }
    catch {
        Write-Output "Print settings were not set properly, confirm that the document has been printed."
    }
    
    # Emails the document to the new user.
    $Body = @"
    <head>
    <style type='text/css'>
        p#Note {
            font-weight: bold;
            font-size: 0.8em;
        }

        ul {
            list-style-type: square;
        }

        span.Bold {
            font-weight: bold;
        }
    </style>
    </head>

    <body>
        Hello $($NewUser.Name),<br />
        Welcome to REDACTED!<br /><br />
        Please see the attached document for useful information!<br /><br />
        Best Regards,<br />
        REDACTED IT
        <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
    </body>
"@
    $Properties = @{
        To         = $NewUser.UserPrincipalName
        From       = 'noreply@REDACTED.org'
        Subject    = 'Welcome to REDACTED!'
        Body       = $Body
        BodyAsHTML = $true
        UseSSL     = $true
        SMTPServer = 'REDACTED'
        Attachment = $DocName
        Priority   = 'High'
    }
    Send-MailMessage @Properties
    # Builds template that gets emailed to manager, HR and IT
    $Body = @"
    <head>
    <style type='text/css'>
        p#Note {
            font-weight: bold;
            font-size: 0.8em;
        }

        ul {
            list-style-type: square;
        }

        span.Bold {
            font-weight: bold;
        }
    </style>
    </head>

    <body>
        Hello $($Manager.Name),<br />
        Your new employee, $($NewUser.Name) has been onboarded.<br /><br />
        Best Regards,<br />
        REDACTED IT
        <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
    </body>
"@
    $Properties = @{
        To         = 'helpdesk@REDACTED.org'
        CC         = $Manager.UserPrincipalName, 'REDACTED@REDACTED.org'
        From       = 'noreply@REDACTED.org'
        Subject    = "[Ticket #$TicketNumber]"
        Body       = $Body
        BodyAsHTML = $true
        UseSSL     = $true
        SMTPServer = 'REDACTED'
        Attachment = $DocName
        Priority   = 'High'
    }
    Send-MailMessage @Properties
    
    # Cleans up the file that gets created.
    Remove-Item -Path $DocName -Force
}


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


function Rename-ADComputer {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Renames a computer.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the computer you are renaming.
.PARAMETER NewName
    Sets the new name for the computer you are renaming.
.EXAMPLE
    Rename-Computer -Help
.EXAMPLE
    Rename-Computer -Identity LT-Computer -NewName LT-NewComputer
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$NewName,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $Credential = Use-PSCred -Identity PSADAcctMgmt
    $Ping = Test-Connection $Identity -Quiet -Count 1
    if (!$Ping) {
        Write-Warning "$Identity is offline or unavailable. Try again later."
        break
    }
    try {
        $CheckDuplicate = Get-ADComputer -Identity $NewName
        if ($CheckDuplicate) {
            Remove-ADComputer -Identity $NewName -Credential $Credential -Confirm:$false
            Start-Sleep -Seconds 30
            Rename-Computer -ComputerName $Identity -NewName $NewName -DomainCredential $Credential -Restart:$false -ErrorAction Stop
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Rename-Computer -ComputerName $Identity -NewName $NewName -DomainCredential $Credential -Restart:$false -ErrorAction Stop
    }
    catch {
        Write-Output $PSItem.Exception.Message
    }
    else {
        Write-Output 'Stopping action.'
        break
    }
}
    
$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Rename-ADComputer -ParameterName Identity -ScriptBlock $IdentityBlock


function Reset-UserPassword {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Reset the password of a specific user to the company default as
                well as flagging the account for password reset on next log on.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user you wish you reset the password on.
.EXAMPLE
    Reset-UserPassword -Help
.EXAMPLE
    Reset-UserPassword -Identity 'Mike Polselli'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$NoPasswordResetOnLogon,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    $Credential = Use-PSCred -Identity PSADAcctMgmt
    $User = Get-ADUser -Filter { DisplayName -eq $Identity }
    Set-ADAccountPassword -Identity $User.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText 'REDACTED001' -Force) -Credential $Credential
    if (!$NoPasswordResetOnLogon) {
        Set-ADUser -Identity $User.SamAccountName -ChangePasswordAtLogon:$true -Credential $Credential
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

Register-ArgumentCompleter -CommandName Reset-UserPassword -ParameterName Identity -ScriptBlock $IdentityBlock


function Restart-ADComputer {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Restarts a computer.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Restart-ADComputer -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
    #>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Identity,
        #TODO: Add Shutdown switch.
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$Shutdown,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    $TestConnection = Test-Connection $Identity -Quiet -Count 1
    if (!$TestConnection) {
        Write-Output "The computer $Identity is currently offline or unavailable."
        break
    }

    $Credential = Use-PSCred -Identity PSADAcctMgmt
    if ($Shutdown) {
        $Prompt = Read-Host -Prompt "Shutting down $Identity.`nContinue? [Y][N] (Default: Y)"
        if ($Prompt -eq 'N') {
            Write-Output "Cancelling shutdown of $Identity."
        }
        else {
            Write-Output "Shutting down $Identity."
            Stop-Computer -ComputerName $Identity -Credential $Credential -Confirm:$false
        }
    }
    else {
        $Prompt = Read-Host -Prompt "Restarting $Identity.`nContinue? [Y][N] (Default: Y)"
        if ($Prompt -eq 'N') {
            Write-Output "Cancelling restart of $Identity."
        }
        else {
            Write-Output "Restarting $Identity."
            Restart-Computer -ComputerName $Identity -Credential $Credential
            do {
                $Connection = Test-Connection $Identity -Quiet
                Write-Output "Testing connection to $Identity..."
            }
            until ($Connection -eq $true)
            Write-Output "Successful connection to $Identity."
        }
    }
}
    
$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)
    
    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}
    
Register-ArgumentCompleter -CommandName Restart-ADComputer -ParameterName Identity -ScriptBlock $IdentityBlock


function Restart-Server {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Restarts a server.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies a server you wish to restart.
.EXAMPLE
    Restart-Server -Help
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
    
    $TestConnection = Test-Connection $Identity -Quiet -Count 1
    if (!$TestConnection) {
        Write-Output "The computer $Identity is currently offline or unavailable."
        break
    }

    $Credential = Use-PSCred -Identity PSADAcctMgmt
    $Prompt = Read-Host -Prompt "Restarting $Identity.`nContinue? [Y][N] (Default: Y)"
    if ($Prompt -eq 'N') {
        Write-Output "Cancelling restart of $Identity."
    }
    else {
        Write-Output "Restarting $Identity."
        Restart-Computer -ComputerName $Identity -Credential $Credential
        do {
            $Connection = Test-Connection $Identity -Quiet
            Write-Output "Testing connection to $Identity..."
        }
        until ($Connection -eq $true)
        Write-Output "Successful connection to $Identity."
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Servers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Restart-Server -ParameterName Identity -ScriptBlock $IdentityBlock


function Send-Notification {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.1
    Language:   PowerShell
    Purpose:    Used to send a downtime or outage notification to a distribution group and a Teams channel.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Send-DowntimeNotification -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Purpose,
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Topic,
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]
        [ValidateSet('15m','30m','45m','1h','2h','5h','1d')]$Duration,
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Impact,
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Affected,
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]
        [ValidateSet('Low','Medium','High')]$Severity,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $SSAnnouncementsURI = 'https://outlook.office.com/webhook/3eb21bda-4d5d-44da-a384-d0d7b3849c7d@14e9186d-b92e-4c6d-b3d6-54b54c168413/IncomingWebhook/182df3bd41564147ae8e0a31ed48ff6a/91226e72-fec4-4a80-9975-5cda2244a7e0'
    

    $Body = @"
<head>
<style type='text/css'>
table {
    border-style: 0.15em solid black;
    border-bottom-color: red;
}

table, th, td {
    border: 0.15em solid darkslategray;
    border-collapse: collapse;
    width: 40em;
}

th {
    width: 10em;
    font-size: 1.1em;
}

td {
    padding: 0.5em 1em 0.5em 1em;
    font-size: 1.1em;
}

td.advisory {
    text-align: left;
    border: 0em ridge black;
}

span.boldMe {
    font-weight: bold;
}

tbody {
    border: 0.25em ridge #cc000b;
}
</style>
</head>
<body>
    <table>
    <tbody>

    <tr>
    <th>TOPIC</th>
    <td>$Topic</td>
    </tr>

    <tr>
    <th>PURPOSE</th>
    <td>$Purpose</td>
    </tr>

    <tr>
    <th>SEVERITY</th>
    <td id="severityLevel">$Severity</td>
    </tr>

    <tr>
    <th rowspan=3>ADVISORY</th>
    <td class="advisory"><span class="boldMe">Duration: </span>$Duration</td>
    </tr>
    
    <tr>
    <td class="advisory"><span class="boldMe">Impact: </span>$Impact</td>
    </tr>
    <tr>
    <td class="advisory"><span class="boldMe">Affected: </span>$Affected</td>
    </tr>

    <tr>
    <th id="contact">CONTACT</th>
    <td>Please direct any questions to: $Contact</td>
    </tr>

    </tbody>
    </table>
</body>
"@

    $Properties = @{
        To         = $Email
        From       = 'noreply@REDACTED.org'
        Subject    = "Password Expiration Reminder - $PasswordExpiration Days"
        Body       = $Body
        BodyAsHTML = $true
        UseSSL     = $true
        SMTPServer = 'REDACTED'
    }
    Send-MailMessage @Properties


    $URI = 'https://outlook.office.com/webhook/e1e4ce51-80ec-444d-892d-8ed3ce043af1@14e9186d-b92e-4c6d-b3d6-54b54c168413/IncomingWebhook/c320ade702ba4c18be97d6968f9b37d4/91226e72-fec4-4a80-9975-5cda2244a7e0'
    $PurposeMsg = New-TeamsFact -Name 'Purpose' -Value $Purpose
    $SeverityMsg = New-TeamsFact -Name 'Severity' -Value $Severity
    $DurationMsg = New-TeamsFact -Name 'Duration' -Value $Duration
    $ImpactMsg = New-TeamsFact -Name 'Impact' -Value $Impact
    $AffectedMsg = New-TeamsFact -Name 'Affected' -Value $Affected
    $ContactMsg = New-TeamsFact -Name 'Contact' -Value $Contact

    $Section = @{
        ActivityTitle    = $Purpose
        ActivitySubTitle = $When
        ActivityText     = $Topic
        ActivityDetails  = $PurposeMsg, $SeverityMsg, $DurationMsg, $ImpactMsg, $AffectedMsg, $ContactMsg
    }
    $Sections = New-TeamsSection @Section

    switch ($Severity) {
        Low { $SeverityColor = 'Yellow'; break }
        Medium { $SeverityColor = 'Orange'; break }
        High { $SeverityColor = 'Red'; break }
    }

    $Message = @{
        URI          = $URI
        MessageTitle = $Title
        Color        = $SeverityColor
        Sections     = $Sections
    }
    Send-TeamsMessage @Message

}


function Set-OutOfOffice {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Configures Out of Office for Outlook.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Set-OutOfOffice -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)]
        [ValidateSet('Template', 'Custom')]$MessageType,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)]
        [ValidateSet('1 Day', '2 Days', '3 Days', '4 Days', '5 Days', '1 Week', '2 Weeks')]$Duration,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    Connect-Exchange -Commands Set-MailboxAutoReplyConfiguration

    $User = Get-ADUser -Filter { Name -eq $Identity }

    $StartDate = (Get-Date)
    switch ($Duration) {
        '1 Day' { $EndDate = (Get-Date).AddDays(1); break }
        '2 Days' { $EndDate = (Get-Date).AddDays(2); break }
        '3 Days' { $EndDate = (Get-Date).AddDays(3); break }
        '4 Days' { $EndDate = (Get-Date).AddDays(4); break }
        '5 Days' { $EndDate = (Get-Date).AddDays(5); break }
        '1 Week' { $EndDate = (Get-Date).AddDays(7); break }
        '2 Weeks' { $EndDate = (Get-Date).AddDays(14); break }
    }

    if ($MessageType -eq 'Template') {
        $Message = "
        I am out of the office from $StartDate to $EndDate, if you need immediate
        help please contact helpdesk at helpdesk@REDACTED.org
        "
    }
    else {
        $Message = Read-Host -Prompt 'Enter your message here.'
    }
}


function Sync-AzureAD {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Forces a sync between the local AD environment and the AzureAD environment.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Sync-AzureAD -Help
.EXAMPLE
    Sync-AzureAD
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [CmdletBinding()]
        param (
            [switch]$Help
        )
    if ($Help) {
        Get-Help MyInvocation.MyCommand.Name -Full | more
        break
    }
    $Username = Read-Host -Prompt 'Enter Username'
    do {
        try {
            $Session = New-PSSession -ComputerName 'REDACTED' -Credential $env:USERDOMAIN\$Username -ErrorAction Stop
        }
        catch {
            Write-Warning 'Incorrect Password!'
        }
    }
    until ($null -ne $Session)
    Import-Module (Import-PSSession -Session $Session -CommandName 'Start-ADSyncSyncCycle' -AllowClobber)
    try {
        Start-ADSyncSyncCycle -ErrorAction Stop
    }
    catch {
        Write-Output $PSItem.Exception.Message
    }
    Disconnect-PSSession -Session $Session
}


function Test-Administrator {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    VARIABLE
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
     -Help
#>
    $User = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}


function Unlock-Account {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Unlocks a user account.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the user account you wish to unlock.
.EXAMPLE
    Unlock-Account -Help
.EXAMPLE
    Unlock-Account -Identity 'Mike Polselli'
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
        Get-Help MyInvocation.MyCommand.Name -Full | more
        break
    }
    #TODO: Add output for previous lockouts. Include amount in last day or week or something if possible?
    #TODO: Add confirmation if the account has been locked out multiple times.
    $Credential = Use-PSCred -Identity PSADAcctMgmt
    $User = Get-ADUser -Filter {Name -eq $Identity}
    Unlock-ADAccount -Identity $User.SamAccountName -Credential $Credential
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Unlock-Account -ParameterName Identity -ScriptBlock $IdentityBlock


function Update-Profile {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Updates the PowerShell profile.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Update-Profile -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory)]
        [ValidateSet('Systems', 'Dev')]$Profile,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    switch ($Profile) {
        'Systems' {
            #TODO: Add check for user to see if they are in the systems department.
            # Command to run to get the systems profile.
            Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -Confirm:$false
            if (-Not (Test-Path -Path $profile)) {
                New-Item -Path (Split-Path $PROFILE -Parent) -ItemType Directory -Force
                Copy-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\Scripts\Profile\Systems_Microsoft.PowerShell_profile.ps1 -Destination $profile -Force
            }
            else {
                Copy-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\Scripts\Profile\Systems_Microsoft.PowerShell_profile.ps1 -Destination $profile -Force
            }
            break
        }
        'Dev' {
            #TODO: Add check for user to see if they are in the dev department.
            # Command to run to get the dev team profile.
            Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -Confirm:$false
            if (-Not (Test-Path -Path $profile)) {
                New-Item -Path (Split-Path $PROFILE -Parent) -ItemType Directory -Force
                Copy-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\Scripts\Profile\Dev_Microsoft.PowerShell_profile.ps1 -Destination $profile -Force
            }
            else {
                Copy-Item -Path \\$env:USERDNSDOMAIN\IT\PowerShell\Scripts\Profile\Dev_Microsoft.PowerShell_profile.ps1 -Destination $profile -Force
            }
            break
        }
    }
}


function Update-SecurityCard {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.1
    Language:   PowerShell
    Purpose:    Is used to update all related fields when a user needs an updated security card.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Update-SecurityCard -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string]$Identity,
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$CardNumber,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $ADCredential = Use-PSCred -Identity PSADAcctMgmt
    $User = Get-ADUser -Filter {Name -eq $Identity}
    Set-ADUser -Identity $User -Fax $CardNumber -Credential $ADCredential
    # This doesn't look like it will work until REDACTED is migrated/rebuilt on the REDACTED.
    #\\REDACTED\PCServerCommand\server\bin\win\server-command.exe /?
    Start-Process http://REDACTED:9191/app?service=page/Dashboard
    Start-Process https://acs.brivo.com/login/Login.do
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADUser -Filter * -SearchBase 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org' -SearchScope OneLevel).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Update-SecurityCard -ParameterName Identity -ScriptBlock $IdentityBlock


function Update-SSModule {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Used to easily update modules.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Name
    Used to update a single module, supports tab completion.
.PARAMETER All
    Used to update all available modules.
.EXAMPLE
    Update-SSModule -Help
.EXAMPLE
    Update-SSModule -Name Utilities
.EXAMPLE
    Update-SSModule -All
#>
    [cmdletbinding()]
    param (
    [Parameter(ParameterSetName = "Name",Position = 0, Mandatory = $true)][string]$Name,
    [Parameter(ParameterSetName = "All",Position = 0)][switch]$All,
    [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($All) {
        $Modules = Find-Module -Repository REDACTED
        foreach ($Module in $Modules) {
            try {
                Update-Module $Module.Name -ErrorAction Stop
                Write-Output "Updating $($Module.Name)."
            }
            catch {
                continue
            }
        }
    }
    elseif ($Name) {
        try {
            Update-Module $Name -ErrorAction Stop
            Write-Output "Updating $($Module.Name)."
        }
        catch [Microsoft.PowerShell.Commands.WriteErrorException] {
            Write-Warning "$Name is not installed."
            Write-Output "Run `"Install-Module $Name -Scope CurrentUser`" to install."
        }
    }

}

$NameBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Find-Module -Repository REDACTED).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Update-SSModule -ParameterName Name -ScriptBlock $NameBlock


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



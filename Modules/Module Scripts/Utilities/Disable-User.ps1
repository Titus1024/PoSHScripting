function Disable-User {
    <#
.SYNOPSIS
    Function used to streamline the process of disabling an ADUser.
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.1
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
            Until ($RandomPW -match '^(?=.*[A-Z].*[A-Z])(?=.*[!@#$%^&*()_])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{20}$')
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

            # Removes the user from manager's direct report list
            try {
                Set-ADUser -Identity $User.SamAccountName -Manager $null -Credential $ADCredential -ErrorAction Stop
                Write-Log "Removed $($User.Name) from $($Manager.Name)'s list of direct reports." -ShowOutput
            }
            catch {
                Write-LogError $PSItem.Exception.Message -ShowOutput
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
    Where-Object { $PSItem.Name -eq $User.Name }
    foreach ($Group in $Groups) {
        try {
            Remove-DistributionGroupMember -Identity $Group.GroupName -Member $User.SamAccountName -ErrorAction SilentlyContinue -Confirm:$false
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
            Start-Sleep -Seconds 10
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
    #TODO: Add token removal for all active logins.
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

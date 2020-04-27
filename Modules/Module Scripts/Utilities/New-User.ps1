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
        Department        = $UserData.Department.TrimEnd()
        Description       = $UserData.Title.TrimEnd()
        DisplayName       = $UserData.PreferredName.TrimEnd()
        EmailAddress      = "$(($UserData.PreferredName.TrimEnd()).Split(" ")[0][0]+($UserData.PreferredName.TrimEnd()).Split(" ")[1])" + '@REDACTED.org'
        EmployeeID        = $UserData.EmployeeID.TrimEnd()
        ErrorAction       = 'Stop'
        Fax               = $UserData.SecurityCard
        GivenName         = "$(($UserData.PreferredName.TrimEnd()).Split(" ")[0])"
        Manager           = $Manager.SamAccountName
        Name              = $UserData.PreferredName.TrimEnd()
        Office            = $UserData.OfficeLocation.TrimEnd()
        Organization      = 'REDACTED'
        SamAccountName    = "$(($UserData.PreferredName.TrimEnd()).Split(" ")[0][0]+($UserData.PreferredName.TrimEnd()).Split(" ")[1])"
        Surname           = "$(($UserData.PreferredName.TrimEnd()).Split(" ")[1])"
        Title             = $UserData.Title.TrimEnd()
        UserPrincipalName = "$(($UserData.PreferredName.TrimEnd()).Split(" ")[0][0]+($UserData.PreferredName.TrimEnd()).Split(" ")[1])" + '@REDACTED.org'
    }
    try {
        New-ADUser @Properties
    }
    catch {
        Write-LogError $PSItem.Exception.Message -ShowOutput
        break
    }
    
    # Gets the new users data, used in other spots.
    $Name = $UserData.PreferredName.TrimEnd()
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
        break
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
        EmployeeNumber      = "$(if($null -eq $UserData.DeskLocation) {'Remote'} else {$UserData.DeskLocation})"
        ExtensionAttribute1 = $UserData.ComputerType
        ExtensionAttribute2 = $UserData.StartDate
    } -Credential $ADCredential

    # Add direct reports, if any.
    if ($null -ne $UserData.DirectReports) {
        foreach ($Report in $UserData.DirectReports.Split(',')) {
            $UserToAdd = $Report.TrimEnd()
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
    $UserToCopy = $UserData.UserToCopy.TrimEnd()
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
        Hello Admin,<br /><br />
        $($Manager.Name) has a new user starting on $($UserData.StartDate).<br/>
        Please add $($NewUser.Name) to the below SharePoint sites per $($Manager.GivenName)'s request.<br />
        If you believe this is in error please contact <a title="" href="mailto:$($Manager.UserPrincipalName)">$($Manager.Name)</a>
        $SharePointSites
    </body>
"@
    }
    $Properties = @{
        To         = 'mpolselli@REDACTED.org'
        From       = 'noreply@REDACTED.org'
        Subject    = "New Hire SharePoint Access - $($NewUser.Name)"
        Body       = $Body
        BodyAsHTML = $true
        SMTPServer = 'REDACTED'
        UseSSL     = $true
        Priority   = 'High'
    }
    Send-MailMessage @Properties

    # Gives the licenses some time to activate, this should avoid errors when assigning a phone number
    $Seconds = 480
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
    $Doc.TypeText('Contact Info')
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
            $null = (Get-WmiObject -ClassName Win32_Printer -Filter "Name='Print Anywhere'").SetDefaultPrinter() | Out-Null
        }
        #Start-Process -FilePath $DocName -Verb Print
        $null = (Get-WmiObject -ClassName Win32_Printer -Filter "Name='$DefaultPrinter'").SetDefaultPrinter() | Out-Null
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
        Your new employee, $($NewUser.Name) has been onboarded.<br />
        Please see attached document that has been provided to $($NewUser.Name).<br /><br/>
        Best Regards,<br />
        REDACTED IT
        <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
    </body>
"@
    $Properties = @{
        To         = 'helpdesk@REDACTED.org'
        CC         = $Manager.UserPrincipalName, 'REDACTED@REDACTED.org'
        From       = 'noreply@REDACTED.org'
        Subject    = "[Ticket #$TicketNumber] New Hire Onboarding - $($NewUser.Name)"
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

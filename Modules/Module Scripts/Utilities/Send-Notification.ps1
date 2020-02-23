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

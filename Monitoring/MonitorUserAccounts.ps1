<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.1
    Language:   PowerShell
    Purpose:    Generates a report of user and password events.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    .MonitorUserAccounts.ps1 -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
### Parameters ###
param (
    [switch]$Help
)
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Definition -Full | more
    exit 0
}
### Parameters ###

### Functions ###
function MonitorUserAccounts {
    Begin {
        Import-Module Logging
        $ScriptName = 'MonitorUserAccounts'
        Start-Log -ScriptName $ScriptName
    }
    Process {
        $PDC = (Get-ADDomain).PDCEmulator
        # Gets lockout events and parses out the useful information.
        $FHT1 = @{
            StartTime = (Get-Date).AddDays(-7)
            EndTime   = (Get-Date)
            LogName   = 'Security'
            ID        = '4740'

        }
        $LockoutEvents = Get-WinEvent -ComputerName $PDC -FilterHashTable $FHT1
        $LockoutTable = @()
        foreach ($Event in $LockoutEvents) {
            $Output = [PSCustomObject]@{
                Username       = $Event.Properties[0].Value
                CallerComputer = $Event.Properties[1].Value
                TimeStamp      = ($Event.TimeCreated | Get-Date -Format "MM/dd/yy hh:mm tt")
            }
            $LockoutTable += $Output
        }
        $LockoutReport = "C:\temp\User Lockout Report - $(Get-Date -Format("yyyy-MM-dd")).xlsx"
        # Gets bad password events and parses out the useful information.
        $FHT2 = @{
            StartTime = (Get-Date).AddDays(-7)
            EndTime   = (Get-Date)
            LogName   = 'Security'
            ID        = '4625'
        }
        $LogonTypes = @{
            '2'  = 'Interactive'
            '3'  = 'Network'
            '4'  = 'Batch'
            '5'  = 'Service'
            '7'  = 'Unlock'
            '8'  = 'Network Clear Text'
            '9'  = 'New Credentials'
            '10' = 'Remote Interactive'
            '11' = 'Cached Interactive'
        }
        $BadPasswordEvents = Get-WinEvent -ComputerName $PDC -FilterHashTable $FHT2
        $BadPasswordTable = @()
        foreach ($Event in $BadPasswordEvents) {
            $Output = [PSCustomObject]@{
                Username       = $Event.Properties[5].Value
                'Logon Type'   = $LogonTypes["$($Event.Properties.Value[10])"]
                CallerComputer = $Event.Properties[13].Value
                'IP Address'   = $Event.Properties[19].Value
                TimeStamp      = ($Event.TimeCreated | Get-Date -Format "MM/dd/yy hh:mm tt")
            }
            $BadPasswordTable += $Output
        }
        $BadPasswordReport = "C:\temp\Bad Password Report - $(Get-Date -Format("yyyy-MM-dd")).xlsx"
        # Exports results and emails them
        $EHT1 = @{
            Autosize   = $true
            TableStyle = 'Medium2'
        }
        $LockoutTable | Export-Excel -Path $LockoutReport @EHT1
        $EHT2 = @{
            Autosize   = $true
            TableStyle = 'Medium2'
        }
        $BadPasswordTable | Export-Excel -Path $BadPasswordReport @EHT2
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
        </style>
        </head>
        <body>
        Hello Admin,<br/><br/>
        Please see attached reports.<br/>
        <br/>
        Best Regards,<br/>
        REDACTED IT
        <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
        </body>
"@
        $MHT = @{
            To         = 'REDACTED@REDACTED.org'
            CC         = 'REDACTED@REDACTED.org', 'REDACTED@REDACTED.org'
            From       = 'REDACTED@REDACTED.org'
            Subject    = 'User Security Report'
            Body       = $Body
            BodyAsHTML = $true
            Attachment = ($LockoutReport, $BadPasswordReport)
            SMTPServer = 'REDACTED'
            UseSSL     = $true
        }
        Send-MailMessage @MHT
        # Looks for large amounts of duplicates and creates a ticket with additional information.
        $BadPasswordGroup = $BadPasswordTable | Group-Object -Property Username
        foreach ($Group in $BadPasswordGroup) {
            if ($Group.Count -gt 100) {
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
                </style>
                </head>
                <body>
                Hello Admin,<br/><br/>
                The user account $($Group.Name) had $($Group.Count) bad password attempts. See report for additional details.<br/>
                <br/>
                Best Regards,<br/>
                REDACTED IT
                <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
                </body>
"@
                $BadPasswordHelpdesk = @{
                    To         = 'REDACTED@REDACTED.org'
                    From       = 'REDACTED@REDACTED.org'
                    Subject    = "Bad Password Alert - $($Group.Name)"
                    Body       = $Body
                    BodyAsHTML = $true
                    SMTPServer = 'REDACTED'
                    UseSSL     = $true
                }
                Send-MailMessage @BadPasswordHelpdesk
            }
        }
        $LockoutGroup = $LockoutTable | Group-Object -Property Username
        foreach ($Group in $LockoutGroup) {
            if ($Group.Count -gt 10) {
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
                </style>
                </head>
                <body>
                Hello Admin,<br/><br/>
                The user account $($Group.Name) has been locked out $($Group.Count) times. See report for additional details.<br/>
                <br/>
                Best Regards,<br/>
                REDACTED IT
                <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
                </body>
"@
                $LockoutHelpdesk = @{
                    To         = 'REDACTED@REDACTED.org'
                    From       = 'REDACTED@REDACTED.org'
                    Subject    = "Account Lockout Alert - $($Group.Name)"
                    Body       = $Body
                    BodyAsHTML = $true
                    SMTPServer = 'REDACTED'
                    UseSSL     = $true
                }
                Send-MailMessage @LockoutHelpdesk
            }
        }
    }
    End {
        Remove-Item $BadPasswordReport, $LockoutReport -Force
        Stop-Log -ScriptName $ScriptName
        Remove-Module Logging
    }
}
### Functions ###

### Script ###
MonitorUserAccounts
### Script ###

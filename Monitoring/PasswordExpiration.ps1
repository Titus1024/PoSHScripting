<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Monitors users passwords and notifies them of expiration
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    .\ScriptName.ps1 -Help
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

### Imports ###
Import-Module Logging
### Imports ###

### Variables ###
<# Used for logging #>$ScriptName = 'PasswordExpiration'
### Variables ###

### Functions ###
function PasswordExpiration {
    $Names = @('REDACTED$', 'REDACTED$')
    $Properties = @{
        Filter      = { Enabled -eq $true -and PasswordNeverExpires -eq $false }
        Properties  = 'msDS-UserPasswordExpiryTimeComputed'
        SearchBase  = 'OU=Users,OU=REDACTED,DC=AD,DC=REDACTED,DC=org'
        SearchScope = 'OneLevel'
    }
    $Users = Get-ADUser @Properties | Where-Object { $PSItem.Name -notin $Names }
    foreach ($User in $Users) {
        $PasswordExpiration = [DateTime]::FromFileTime($User.'msDS-UserPasswordExpiryTimeComputed')
        $PasswordExpiration = ($PasswordExpiration - (Get-Date)).Days
        # Sends an email to the user if their password is within at least 5 days of expiring.
        if ($PasswordExpiration -le 5 -and $PasswordExpiration -gt 0) {
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
            span.BoldQA {
                font-weight: bold;
                font-size: 1.15em;
            }
            </style>
            </head>
            <body>
            Hello $($User.Name),<br/><br/>
            Your password is due to expire in <span class="Bold">$PasswordExpiration</span> days. Please reset your password before then while you are in the office.<br />
            For your convenience, please see below for the password complexity standards:
            <ul>
              <li>Must <span class="Bold">not</span> contain the user's account name or parts of the user's full name that exceed two consecutive characters</li>
              <li>Must be at least <span class="Bold">10</span> characters in length</li>
              <li>Passwords expire every <span class="Bold">60</span> days.</li>
              <li>Must not be one of your past <span class="Bold">24</span> passwords.</li>
            </ul>
            Must contain characters from <span class="Bold">three</span> of the following four categories:
            <ul>
            <li>English uppercase characters (A through Z)</li>
            <li>English lowercase characters (a through z)</li>
            <li>Base 10 digits (0 through 9)</li>
            <li>Non-alphabetic characters (for example, !, $, #, %)</li>
            </ul>
            <p>
            <span class="BoldQA">Q:</span> How do I reset my password?<br/>
            <span class="BoldQA">A:</span> Press <span class="Bold">Ctrl+Alt+Del</span> while signed in and select <span class="Bold">'Change a Password'</span>.<br/>
            <span class="BoldQA">Q:</span> My password is going to expire while I am out of the office, can I still reset my password?<br/>
            <span class="BoldQA">A:</span> Yes, but you will need to be connected to the <span class="Bold">VPN</span> before resetting your password.
            </p>
            <br>
            Best Regards,<br/>
            REDACTED IT
            <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
            </body>
"@

            # Prevents emails from being sent over the weekend.
            if ((Get-Date).DayOfWeek -eq 'Sunday' -or (Get-Date).DayOfWeek -eq 'Saturday') {
                break
            }
            else {
                if ($PasswordExpiration -eq 1) {
                    $Properties = @{
                        To         = $User.UserPrincipalName
                        From       = 'noreply@REDACTED.org'
                        Subject    = "Password Expiration Reminder - $PasswordExpiration Day"
                        Body       = $Body
                        BodyAsHTML = $true
                        UseSSL     = $true
                        SMTPServer = 'REDACTED'
                    }
                    Send-MailMessage @Properties
                    Write-Log "Sending email to $($User.Name). Their password expires in $PasswordExpiration day."
                }
                else {
                    $Properties = @{
                        To         = $User.UserPrincipalName
                        From       = 'noreply@REDACTED.org'
                        Subject    = "Password Expiration Reminder - $PasswordExpiration Days"
                        Body       = $Body
                        BodyAsHTML = $true
                        UseSSL     = $true
                        SMTPServer = 'REDACTED'
                    }
                    Send-MailMessage @Properties
                    Write-Log "Sending email to $($User.Name). Their password expires in $PasswordExpiration days."
                }
            }
        }
        # Sends email to user if their password has expired. This also prevents spam if a user's password stays expired for multiple days.
        elseif ($PasswordExpiration -eq 0) {
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
            Hello $($User.Name),<br/><br/>
            Your password expired on <span class="Bold">$(Get-Date -Format "dddd, MMMM dd, yyyy")</span>.<br/><br/>
            If you are currently out of the office please contact the <span class="Bold"><a href="mailto:helpdesk@REDACTED.org?subject=Password%20Expired&">IT Help Desk<a/></span> to have your password reset.<br/>
            Do <span class="Bold">not</span> reset your password yourself if you are currently out of the office as it will cause issues.<br/>
            <br/>
            Best Regards,<br/>
            REDACTED IT
            <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
            </body>
"@
            $Properties = @{
                To         = $User.UserPrincipalName
                From       = 'noreply@REDACTED.org'
                Subject    = "Password Expiration Reminder - Password Expired"
                Body       = $Body
                BodyAsHTML = $true
                UseSSL     = $true
                SMTPServer = 'REDACTED'
                Priority   = 'High'
            }
            Send-MailMessage @Properties

            Write-Log "Sending email to $($User.Name). Their password has expired. PasswordExpiration Value - $PasswordExpiration"
        }
    }
}
### Functions ###

### Script ###
<# Used for logging, always the first function to run.#>Start-Log -ScriptName $ScriptName
PasswordExpiration
<# Used for logging, always the last function to run.#>Stop-Log -ScriptName $ScriptName
### Script ###

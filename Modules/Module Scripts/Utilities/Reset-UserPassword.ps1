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
        [Parameter(ParameterSetName = "Primary", Position = 1, Mandatory = $true)][string]$TicketNumber,
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
                Hello $($User.Name),<br/>
                <br/>
                Your password has been reset to the company default of REDACTED001, you will need to reset it on your next login.
                <br/>
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
                <br/>
                Best Regards,<br/>
                REDACTED IT
                <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
                </body>
"@
        $Properties = @{
            To         = $User.UserPrincipalName
            CC         = 'helpdesk@REDACTED.org'
            From       = 'noreply@REDACTED.org'
            Subject    = "[Ticket #$TicketNumber] Password Reset"
            Body       = $Body
            BodyAsHTML = $true
            UseSSL     = $true
            SMTPServer = 'REDACTED'
            Priority   = 'High'
        }
        Send-MailMessage @Properties
    }
    else {
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
                Hello $($User.Name),<br/>
                <br/>
                Your password has been reset to the company default of REDACTED001, please wait <span class="Bold">24</span> hours before resetting your password.<br/>
                <br/>
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
                <br/>
                Best Regards,<br/>
                REDACTED IT
                <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
                </body>
"@
        $Properties = @{
            To         = $User.UserPrincipalName
            CC         = 'helpdesk@REDACTED.org'
            From       = 'noreply@REDACTED.org'
            Subject    = "[Ticket #$TicketNumber] Password Reset"
            Body       = $Body
            BodyAsHTML = $true
            UseSSL     = $true
            SMTPServer = 'REDACTED'
            Priority   = 'High'
        }
        Send-MailMessage @Properties
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


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
    Enter the ticket number of the request for shared mailbox access. 
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
            
            $Table = @{}
            foreach ($MB in $Mailboxes) {
                $Table.Add($MB,$MB)
            }
            [System.Collections.ArrayList]$Output = $Table.GetEnumerator() | Select-Object Value | ConvertTo-Html -Fragment -As Table
            $Output.RemoveAt(2)

            $HelpDeskURL = "http://helpdesk.REDACTED.org/portal/view-help-request/$TicketNumber"
            $Body = @"
            <head>
    <style type="text/css">
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
        Hello $($UserName.Name),<br/>
        You have been given access to the following mailbox(es).<br/>
        <br>
        <span class="Bold">$Output</span>
        <br/>
        The mailbox(es) will show up in your Outlook in roughly 30-45 minutes.<br/>
        If the mailbox(es) have not shown up in that time please restart your Outlook and wait an additional 5-10 minutes.<br/>
        If you have any questions or concerns please direct them <span class="Bold"><a title ="$TicketNumber" href="$HelpDeskURL">here</a></span><br/>
        <br/>
        Best Regards,<br/>
        REDACTED IT
        <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
    </body>
"@
            $Properties = @{
                To          = 'helpdesk@REDACTED.org'
                Cc          = $UserName.UserPrincipalName
                From        = 'noreply@REDACTED.org'
                Subject     = "[Ticket #$TicketNumber]"
                Body        = $Body
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

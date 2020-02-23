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
            
            $Table = @{}
            foreach ($MB in $MailboxCap) {
                $Table.Add($MB,$MB)
            }
            [System.Collections.ArrayList]$Output = $Table.GetEnumerator() | Select-Object Value | ConvertTo-Html -Fragment -As Table
            $Output.RemoveAt(2)
            
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
                Cc          = $CC
                From        = 'noreply@REDACTED.org'
                Subject     = "[Ticket #$TicketNumber]"
                Body        = $Body
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

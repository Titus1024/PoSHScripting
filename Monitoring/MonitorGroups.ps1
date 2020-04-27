<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.1
    Language:   PowerShell
    Purpose:    This script is used to monitor and alert on specific domain and local group memberships.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    .\MonitorGroups.ps1 -Help
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
function MonitorGroups {
    Begin {
        Import-Module Logging
        $ScriptName = 'MonitorGroups'
        Start-Log -ScriptName $ScriptName
        $DomainGroups = Get-ADGroup -Filter { Name -like "*admin*" }
        #$LocalGroups = 'Administrator'
        #$Servers = Import-Excel -Path 'Path to server name list'
        $ExcelSplat = @{
            Path       = 'C:\temp\GroupReport.xlsx'
            AutoSize   = $true
            TableName  = 'Domain_Group_Report'
            TableStyle = 'Medium2'
        }
    }

    Process {
        try {
            $Import = Import-Excel $ExcelSplat.Path -ErrorAction Stop
            $Table = @()
            foreach ($Group in $DomainGroups) {
                $Members = Get-ADGroupMember -Identity $Group
                $Output = [PSCustomObject]@{
                    GroupName = $Group.Name
                    Members   = $Members.Name -join ','
                }
                $Table += $Output
            }
            $Compare = Compare-Object -ReferenceObject $Table -DifferenceObject $Import -Property GroupName, Members
            if ($Compare) {
                $CurrentGroups = $Compare | Where-Object { $PSItem.SideIndicator -eq '<=' }
                #$OldGroups = $Compare | Where-Object { $PSItem.SideIndicator -eq '=>' }

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
                Change detected in group(s): <span class="Bold">$($CurrentGroups.GroupName -join ', ')</span><br/><br/>
                If this change is not intended immediate action is required.<br/>

                See attachment for group memberships <span class="Bold">before</span> change occurred.<br/>
                <br/>
                Best Regards,<br/>
                REDACTED IT
                <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
                </body>
"@
                $EmailSplat = @{
                    To         = 'IT@REDACTED.org'
                    CC         = 'akhamenka@REDACTED.org', 'basen@REDACTED.org'
                    From       = 'noreply@REDACTED.org'
                    Subject    = 'ALERT - Group Membership Change Detected'
                    Body       = $Body
                    BodyAsHTML = $true
                    UseSSL     = $true
                    SMTPServer = 'REDACTED'
                    Attachment = $ExcelSplat.Path
                }
                Send-MailMessage @EmailSplat
            }
        }
        catch {
            # This should only run if there is no pre-existing report
            $Table = @()
            foreach ($Group in $DomainGroups) {
                $Members = Get-ADGroupMember -Identity $Group
                $Output = [PSCustomObject]@{
                    GroupName = $Group.Name
                    Members   = $Members.Name -join ','
                }
                $Table += $Output
            }
            $Table | Export-Excel @ExcelSplat
        }
        # Replaces the existing report with the most current memberships.
        $Table | Export-Excel @ExcelSplat
    }

    End {
        Stop-Log -ScriptName $ScriptName
        Remove-Module Logging
    }
}
### Functions ###

### Script ###
MonitorGroups
### Script ###

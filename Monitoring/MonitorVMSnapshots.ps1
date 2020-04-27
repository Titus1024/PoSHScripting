<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.1
    Language:   PowerShell
    Purpose:    Monitors and alerts on VM Snapshots.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    .\MonitorVMSnapshots.ps1 -Help
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
Import-Module PSCreds
### Imports ###

### Variables ###
<# Used for logging #>$ScriptName = 'MonitorVMSnapshots'
$Credential = Use-PSCred -Identity PSVMWareAdmin -Email
$ThresholdDate = -7 # Days
$ThresholdSize = 2 # GB
### Variables ###

### Functions ###
function MonitorVMSnapshots {
    # Checks for the VMWare PowerCLI module
    if ($null -eq (Get-Module VMWare.PowerCLI -ListAvailable)) {
        try {
            Install-Module -Name VMWare.PowerCLI -Scope CurrentUser -Force -ErrorAction Stop
            Write-LogWarning 'VMWare PowerCLI is not installed! Installing now...'
        }
        catch {
            Write-LogError 'Failed to install VMWare PowerCLI module. Exiting.'
            exit
        }
    }
    # Connects to the VMWare Server
    $Servers = @(
        'REDACTED.ad.REDACTED.org'<#,'REDACTED.REDACTED.local'#>
    )
    foreach ($Server in $Servers) {
        Connect-VIServer -Server $Server -Credential $Credential -Force
        $VMs = Get-VM
        foreach ($VM in $VMs) {
            $Snapshot = Get-Snapshot -VM $VM | Select-Object *
            if ($null -eq $Snapshot) {
                continue
            }
            # Alerts if the snapshot is either older than $ThresholdDate OR if the size is greater than or equal to $ThresholdSize
            elseif ($Snapshot.Created -le (Get-Date).AddDays($ThresholdDate) -or $Snapshot.SizeGB -ge $ThresholdSize) {
                # Cleans up data and makes it easier to read at a glance.
                $CurrentAge = ((Get-Date) - $Snapshot.Created).Days
                if ($Snapshot.SizeGB -lt 1) {
                    $FormattedSize = [Math]::Round($Snapshot.SizeMB, 2)
                    $FormattedSize = [string]$FormattedSize + ' MB'
                }
                else {
                    $FormattedSize = [Math]::Round($Snapshot.SizeGB, 2)
                    $FormattedSize = [string]$FormattedSize + ' GB'
                }

                $SnapshotDate = $Snapshot.Created.ToString('yyyy-mmmm-dd hh:MM:ss tt')
                $SnapshotName = $Snapshot.Name
                $Description = if ([string]::IsNullOrEmpty($Snapshot.Description)) { 'None' } else { $Snapshot.Description }
                $Size = $FormattedSize
                $Quiesced = $Snapshot.Quiesced
                # Email template used for the alert.
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
                Hello Admin,<br/>
                <br/>
                A snapshot has been detected on the <span class="Bold">$VM</span> Virtual Machine and is $CurrentAge days old.<br/>
                Please see below for additional details.<br/>
                <br/>
                Snapshot Creation Date: <span class="Bold">$SnapshotDate</span><br/>
                Snapshot Name: <span class="Bold">$SnapshotName</span><br/>
                Snapshot Description: <span class="Bold">$Description</span><br/>
                Snapshot Size: <span class="Bold">$Size</span><br/>
                Quiesced: <span class="Bold">$Quiesced</span><br/>
                <br/>
                Best Regards,<br/>
                REDACTED IT
                <p id="Note">Note: Do not reply to this email, this was an automated task and this mailbox is not monitored.</p>
                </body>
"@
                # Sends the alert if above conditions are met.
                $Properties = @{
                    To         = 'IT@REDACTED.org'
                    From       = 'noreply@REDACTED.org'
                    Subject    = "Snapshot Alert - $VM"
                    Body       = $Body
                    BodyAsHTML = $true
                    UseSSL     = $true
                    SMTPServer = 'REDACTED'
                    Priority   = 'High'
                }
                Send-MailMessage @Properties
                Write-Log "Sending alert for $VM"
            } 
        }
        # Forces a disconnect from the vCenter server.
        Disconnect-VIServer -Force -Confirm:$false
    }
}
### Functions ###

### Script ###
<# Used for logging, always the first function to run.#>Start-Log -ScriptName $ScriptName
MonitorVMSnapshots
<# Used for logging, always the last function to run.#>Stop-Log -ScriptName $ScriptName
### Script ###

function Get-LogTime {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Is used to pass a current time stamp whenever output is generated.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Get-LogTime -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    (Get-Date).ToString('yyyy-MM-dd, hh:mm:ss tt,')
}


function Start-Log {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Starts the log file for the script it is run in.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Start-Log -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)][string]$ScriptName,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $Date = (Get-Date).ToString('yyyy-MM-dd')
    $Script:Log = "\\$env:USERDNSDOMAIN\IT\PowerShell\Logs\$ScriptName\$env:COMPUTERNAME`_$Date.txt"
    $TestPath = Test-Path $Log
    if ($TestPath -eq $false) {
        New-Item -Path $Log -Force | Out-Null
        Write-Output "$(Get-LogTime) ========== $ScriptName started. ==========" >> $Log
    }
    else {
        Write-Output "$(Get-LogTime) ========== $ScriptName started. ==========" >> $Log
    }
}


function Stop-Log {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Stops the log file for the script it is run in.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Stop-Log -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)][string]$ScriptName,    
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    Write-Output "$(Get-LogTime) ========== $ScriptName finished. ==========" >> $Log
}


function Write-Log {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Used to store the information that will be passed to the log file.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER LogMessage
    Information you wish to pass to the log file goes here.
.PARAMETER ShowOutput
    If this switch is used the LogMessage information will also be printed to the console.
.EXAMPLE
    Write-Log -Help
.EXAMPLE
    Write-Log -LogMessage 'Disabled some users and moved them to a different OU'
.EXAMPLE
    Write-Log -LogMessage "Disabled $($User.Name) and moved them to the $($DestinationOU.DistinguishedName) OU."
.EXAMPLE
    Write-Log -LogMessage "Disabled $($User.Name) and moved them to the $($DestinationOU.DistinguishedName) OU." -ShowOutput
    
    2018-12-12 04:45:59 PM - Disabled John Doe and moved them to the Disabled OU.
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)]$LogMessage,
        [Parameter(ParameterSetName)][switch]$ShowOutput,    
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($ShowOutput) {
        "$(Get-LogTime) - $LogMessage" >> $Log
        Write-Output "$(Get-LogTime) $LogMessage"
    }
    else {
        "$(Get-LogTime) $LogMessage" >> $Log
    }
}


function Write-LogError {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Used to store the error messages that will be passed to the log file.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER ErrorMessage
    Error messages that you wish to pass to the log file goes here.
.PARAMETER ShowOutput
    If this switch is used the ErrorMessage information will also be printed to the console.
.EXAMPLE
    Write-LogError -Help
.EXAMPLE
    Write-LogError -ErrorMessage 'Failed to disable some users and move them to a different OU'
.EXAMPLE
    Write-LogError -ErrorMessage "Error disabling $($User.Name) and moving them to the $($DestinationOU.DistinguishedName) OU."
.EXAMPLE
    Write-LogError -ErrorMessage "Error Disabling $($User.Name) and moving them to the $($DestinationOU.DistinguishedName) OU." -ShowOutput

    /-------------------------------------------------------------------------------------------\
    |2018-12-12 04:48:45 PM ERROR - Error Disabling John Doe and moving them to the Disabled OU.|
    \-------------------------------------------------------------------------------------------/
.EXAMPLE
    try {Get-ChildItem C:\NotARealPath -ErrorAction Stop} catch {Write-LogError $PSItem.Exception.Message -ShowOutput}
    
    /--------------------------------------------------------------------------------------------\
    |2018-12-12 04:48:45 PM ERROR - Cannot find path 'C:\NotARealPath' because it does not exist.|
    \--------------------------------------------------------------------------------------------/
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)]$ErrorMessage,
        [Parameter(ParameterSetName)][switch]$ShowOutput,    
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $Length = $ErrorMessage.Length + 31
    $Dashes = ('-' * $Length)
    if ($ShowOutput) {
        Write-Output "/$Dashes\,"
        Write-Output "|$(Get-LogTime) ERROR - $ErrorMessage|"
        Write-Output "\$Dashes/,"
        #"/$Dashes\" >> $Log
        "|$(Get-LogTime) ERROR - $ErrorMessage|" >> $Log
        #"\$Dashes/" >> $Log
    }
    else {
        #"/$Dashes\" >> $Log
        "|$(Get-LogTime) ERROR - $ErrorMessage|" >> $Log
        #"\$Dashes/" >> $Log    
    }
}


function Write-LogWarning {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Used to store the warning messages that will be passed to the log file. 
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER WarningMessage
    Warning messages that you wish to pass to the log file goes here.
.PARAMETER ShowOutput
    If this switch is used the WarningMessage information will also be printed to the console.
.EXAMPLE
    Write-LogWarning -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues

#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName, Position = 0, Mandatory = $true)]$WarningMessage,
        [Parameter(ParameterSetName)][switch]$ShowOutput,    
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($ShowOutput) {
        "$(Get-LogTime) $WarningMessage" >> $Log
        Write-Warning "$(Get-LogTime) $WarningMessage"
    }
    else {
        "$(Get-LogTime) $WarningMessage" >> $Log
    }
}



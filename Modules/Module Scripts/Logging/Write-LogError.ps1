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

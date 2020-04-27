function Start-Troubleshooter {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Queries a specified system for logs within a time frame
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Start-Troubleshooter -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding()]
    param (
        [Parameter(ParameterSetName = "Server", Position = 1, Mandatory)][string]$ServerName,
        [Parameter(ParameterSetName = "Workstation", Position = 1, Mandatory)]
        [Parameter(ParameterSetName = "WorkstationStats", Position = 1, Mandatory)][string]$WorkstationName,

        [Parameter(ParameterSetName = "Server", Position = 2, Mandatory)]
        [Parameter(ParameterSetName = "Workstation", Position = 2, Mandatory)]
        [ValidateSet('Info', 'Warn', 'Error', 'Crit', 'All', 'Warn+', 'Error+')]$LogType,

        [Parameter(ParameterSetName = "Server", Position = 3, Mandatory)]
        [Parameter(ParameterSetName = "Workstation", Position = 3, Mandatory)]
        [ValidateSet('5m', '15m', '30m', '1h', '3h')]$TimeFrame,

        [Parameter(ParameterSetName = "Server", Position = 4)]
        [Parameter(ParameterSetName = "Workstation", Position = 4)]
        [switch]$ExportReport,

        [Parameter(ParameterSetName = "WorkstationStats", Position = 2)][switch]$WorkstationStats,

        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    <#
    if (![string]::IsNullOrEmpty($ServerName)) {
        # Tests if the computer is available/online.
        $TestConnection = Test-Connection -ComputerName $ServerName -Count 1 -Quiet
        if (!$TestConnection) {
            Write-Host "ERROR: $ServerName is offline or unavailable." -ForegroundColor Red
            return
        }
        $ComputerName = $ServerName
    }
    elseif ($null -ne $WorkstationName) {
        # Tests if the computer is available/online.
        $TestConnection = Test-Connection -ComputerName $WorkstationName -Count 1 -Quiet
        if (!$TestConnection) {
            Write-Warning "$WorkstationName is offline or unavailable."
            return
        }
        $ComputerName = $WorkstationName
    }
    #>
    $ComputerName = $WorkstationName
    # Workstation related information.
    if ($WorkstationStats) {
        <#TODO:
        Get uptime, print to host in red if over 7 days, yellow for 5 and green for 5 and below
        Include a prompt to continue?
        Get free disk space on C drive
        #>
        # Gets last boot up time and colors the output based off of the result.
        $LastBootUp = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $WorkstationName | Select-Object LastBootUpTime
        $LastBootUp = ((Get-Date) - $LastBootUp.LastBootUpTime).Days
        switch ($LastBootUp) {
            { $LastBootUp -ge 7 } { Write-Host "$WorkstationName has an uptime of $LastBootUp days." -ForegroundColor Red; break }
            { $LastBootUp -gt 3 -and $LastBootUp -lt 7 } { Write-Host "$WorkstationName has an uptime of $LastBootUp days." -ForegroundColor Yellow; break }
            { $LastBootUp -le 3 } { Write-Host "$WorkstationName has an uptime of $LastBootUp days." -ForegroundColor Green; break }
        }
        # Gets free space on C drive and colors output based off of the result.
        $Space = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $WorkstationName | Where-Object { $PSItem.DeviceID -eq 'C:' } | Select-Object FreeSpace
        $Space = [Math]::Round(($Space.FreeSpace / 1GB), 2)
        switch ($Space) {
            { $Space -lt 1 } { Write-Host "C: Drive on $WorkstationName has $Space GB Free. Immediate attention required." -ForegroundColor DarkRed; break }
            { $Space -lt 10 -and $Space -ge 1 } { Write-Host "C: Drive on $WorkstationName has $Space GB Free. Attention required." -ForegroundColor Red; break }
            { $Space -le 20 -and $Space -gt 10 } { Write-Host "C: Drive on $Workstation has $Space GB Free. Attention recommended." -ForegroundColor Yellow; break }
            { $Space -gt 20 } { Write-Host "C: Drive on $WorkstationName has $Space GB Free. No action needed." -ForegroundColor Green; break }
        }
        return
    }
    # Event viewer logs and filtering
    if ($TimeFrame -eq '1h' -or $TimeFrame -eq '3h' -and !$ExportReport) {
        $Prompt = Read-Host -Prompt "You have selected $TimeFrame of logs and have not used the ExportReport parameter, this will generate a lot of logs. Would you like a report exported? [Y]es/[N]o (Default: [Y])"
        if ($Prompt -eq 'N') {
            Write-Output 'Continuing without report export.'
        }
        else {
            Write-Output 'Continuing with report export.'
            $ExportReport = $true
        }
    }
    $LogNames = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $PSItem.RecordCount -gt 0 }
    switch ($TimeFrame) {
        '5m' { $StartTime = 5 }
        '15m' { $StartTime = 15 }
        '30m' { $StartTime = 30 }
        '1h' { $StartTime = 60 }
        '3h' { $StartTime = 180 }
    }
    switch ($LogType) {
        'Info' { $LogLevel = 4 }
        'Warn' { $LogLevel = 3 }
        'Error' { $LogLevel = 2 }
        'Crit' { $LogLevel = 1 }
        'All' { $LogLevel = 1, 2, 3, 4 }
        'Warn+' { $LogLevel = 1, 2, 3 }
        'Error+' { $LogLevel = 1, 2 }
    }

    $Properties = @{
        StartTime = (Get-Date).AddMinutes(-$StartTime)
        EndTime   = (Get-Date)
        LogName   = $LogNames.LogName
        Level     = $LogLevel
    }
    
    try {
        if ($ExportReport) {
            $PropertiesExcel = @{
                Path         = "C:\Temp\$ComputerName`_Logs.xlsx"
                FreezeTopRow = $true
                AutoSize     = $true
            }
            Get-WinEvent -FilterHashTable $Properties -ComputerName $ComputerName -ErrorAction Stop | Select-Object TimeCreated, ID, LevelDisplayName, Message | Export-Excel @PropertiesExcel
            Invoke-Item $PropertiesExcel.Path
        }
        else {
            $Events = Get-WinEvent -FilterHashTable $Properties -ComputerName $ComputerName -ErrorAction Stop | Select-Object TimeCreated, ID, LevelDisplayName, Message
            if ($Events.Count -gt 20) {
                Write-Output 'Your log request is larger than expected, exporting.'
                $Events | Export-Excel @PropertiesExcel
                Invoke-Item $PropertiesExcel.Path
            }
        }
    }
    catch [Exception] {
        if ($PSItem.Exception -match 'No events were found that match the specified selection criteria') {
            Write-Output 'No events were found that match the specified selection criteria'
        }
    }
}

$ServerName = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'ServerOU').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}
Register-ArgumentCompleter -CommandName Start-Troubleshooter -ParameterName ServerName -ScriptBlock $ServerName

$WorkstationName = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}
Register-ArgumentCompleter -CommandName Start-Troubleshooter -ParameterName WorkstationName -ScriptBlock $WorkstationName

<# TODO:
Start-Troubleshooter -ComputerName(dynamic) REDACTED -LogType(List) Info,Warning,Error,Critical,All,Warning+,Error+(?) -TimeFrame(List) 5m,15m,30m,1h,3h -ExportReport(switch)
#>

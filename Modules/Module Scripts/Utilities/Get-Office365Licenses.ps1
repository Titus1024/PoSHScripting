function Get-Office365Licenses {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Outputs the licenses from Office365, uses and unused.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Get-Office365Licenses -Help
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

    try {
        # Installs module for current user if they don't have it.
        $MSOnlineCheck = Get-Module -Name MSOnline -ListAvailable
        if (!$MSOnlineCheck) {
            Write-Log 'Microsoft Online Module not installed.' -ShowOutput
            Write-Log 'Installing Microsoft Online Module...' -ShowOutput
            Install-Module -Name MSOnline -Scope CurrentUser
            Write-Log 'Done.' -ShowOutput
        }
        $Credential = Use-PSCred -Identity PSLicenseAdmin -Email
        Connect-MsolService -Credential $Credential
        $Licenses = Get-MsolAccountSku | Sort-Object -Property AccountSkuID
        $RenamedLicenses = @()
        foreach ($License in $Licenses) {
            switch ($License.AccountSkuId) {
                'REDACTED2:ATP_ENTERPRISE' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:ATP_ENTERPRISE', 'Advanced Threat Protection') }
                'REDACTED2:EMS' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:EMS', 'Enterprise Mobile Security E3') }
                'REDACTED2:ENTERPRISEPACK' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:ENTERPRISEPACK', 'Office 365 E3') }
                'REDACTED2:FLOW_FREE' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:FLOW_FREE', 'Flow (Free)') }
                'REDACTED2:MCOEV' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MCOEV', 'Phone System') }
                'REDACTED2:MCOMEETADV' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MCOMEETADV', 'Audio Conferencing') }
                'REDACTED2:MCOPSTN1' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MCOPSTN1', 'Domestic Calling') }
                'REDACTED2:MEETING_ROOM' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MEETING_ROOM', 'Meeting Room') }
                'REDACTED2:MS_TEAMS_IW' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:MS_TEAMS_IW', 'Teams Trial (Free)') }
                'REDACTED2:NONPROFIT_PORTAL' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:NONPROFIT_PORTAL', 'Non-profit Portal (Free)') }
                'REDACTED2:POWER_BI_STANDARD' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:POWER_BI_STANDARD', 'PowerBI Standard (Free)') }
                'REDACTED2:PROJECTPROFESSIONAL' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:PROJECTPROFESSIONAL', 'Project Pro') }
                'REDACTED2:STANDARDPACK' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:STANDARDPACK', 'Office 365 E1 (Free)') }
                'REDACTED2:VISIOCLIENT' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:VISIOCLIENT', 'Visio Pro') }
                'REDACTED2:WINDOWS_STORE' { $RenamedLicenses += $License.AccountSkuId.Replace('REDACTED2:WINDOWS_STORE', 'Windows Store (Free?)') }
            }
        }
    
        $TableName = 'Office365 Licenses'
        $Table = New-Object System.Data.DataTable $TableName
        $ColumnNames = @('License Name', 'Active', 'Total', 'Unused')
        foreach ($Name in $ColumnNames) {
            $Column = New-Object System.Data.DataColumn $Name
            $Table.Columns.Add($Column)
        }
    
        for ($i = 0; $i -lt $RenamedLicenses.Count; $i++) {
            New-Variable -Name Row$i -Force
            $Row = $Table.NewRow()
            $Row.'License Name' = $RenamedLicenses[$i]
            $Row.Active = $Licenses.ConsumedUnits[$i]
            $Row.Total = $Licenses.ActiveUnits[$i]
            $Row.Unused = $Licenses.ActiveUnits[$i] - $Licenses.ConsumedUnits[$i]
            $Table.Rows.Add($Row)
        }
        Get-PSSession | Remove-PSSession
        return $Table
    }
    catch {
        Write-Warning $PSITem.Exception.Message
        Get-PSSession | Remove-PSSession
    }
}

function Get-PSCred {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Displays information about a PSCredential.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Specifies the PSCredential you wish to query.
.EXAMPLE
    Get-PSCred -Help
.EXAMPLE
    Get-PSCred -Identity PSADAcctMgmt
    Displays useful information about the PSCredential PSADAcctMgmt
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Identity, 
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    $Path = "\\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\"
    $Info = Get-ChildItem -Path $Path\$Identity
    $Access = Get-Acl -Path $Path\$Identity | Select-Object -ExpandProperty Access |
    Where-Object { $PSItem.IdentityReference.Value -like "$env:USERDOMAIN*" } |
    Select-Object @{n = 'Identity'; e = { $PSItem.IdentityReference } }, @{n = 'Access'; e = { $PSItem.FileSystemRights } }
    
    #Builds and formats the table
    $TableName = "$Identity Information"
    $Table = New-Object System.Data.DAtaTable $TableName
    $Columns = ('File Name', 'Permissions', 'Permissions Type', 'Creation Date', 'Last Modified Date')
    foreach ($Column in $Columns) {
        $NewColumn = New-Object System.Data.DataColumn $Column
        $Table.Columns.Add($NewColumn)
    }

    for ($i = 0; $i -lt $Info.Count; $i++) {
        New-Variable -Name Row$i -Force
        $Row = $Table.NewRow()
        $Row.'File Name' = $Info[$i].Name.Replace('.txt', '')
        $Row.Permissions = ($Access.Identity -join ',').Replace("$env:USERDOMAIN\", '')
        $Row.'Permissions Type' = 'Still in development.'
        #TODO: Figure out how to format the table to include the different user permissions.
        #$Row.'Permissions Type' = ($Access.Access -join ',')
        $Row.'Creation Date' = $Info[$i].CreationTime
        $Row.'Last Modified Date' = $Info[$i].LastWriteTime
        $Table.Rows.Add($Row)
    }
    return $Table
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Get-ChildItem -Path \\$env:USERDNSDOMAIN\IT\PowerShell\PSCreds\).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Get-PSCred -ParameterName Identity -ScriptBlock $IdentityBlock

function Get-SharedMailboxPermissions {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Pulls the permissions of a shared mailbox and formats them into a table.
                Can be used to query multiple mailboxes at one time.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Mailbox
    Specify the mailbox(es) you wish to query.
.EXAMPLE
    Get-SharedMailboxPermissions -Help
.EXAMPLE
    Get-SharedMailboxPermissions -Mailbox 'Shared Mailbox'
.EXAMPLE
    Get-SharedMailboxPermissions -Mailbox 'Shared Mailbox','Shared Mailbox Two'
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)][string[]]$Mailbox,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }

    try {
        # Connects to Exchange and gathers the permissions.
        Connect-Exchange -Commands Get-MailboxPermission -ErrorAction Stop
        foreach ($Identity in $Mailbox) {
            $Permissions = Get-MailboxPermission -Identity $Identity | Where-Object { $PSItem.User -like "*@REDACTED.org" -or $PSItem.User -like "*@REDACTED.org" } |
            Select-Object User, AccessRights
            
            # Capitalizes the mailbox name.
            $TextInfo = (Get-Culture).TextInfo
            $IdentityCap = $TextInfo.ToTitleCase($Identity)
            # Builds the table and formats it.
            $TableName = "$IdentityCap Permissions"
            $Table = New-Object System.Data.DataTable $TableName
            $ColumnOne = New-Object System.Data.DataColumn Name, ([string])
            $ColumnTwo = New-Object System.Data.DataColumn AccessRights, ([string])
            $Table.Columns.Add($ColumnOne)
            $Table.Columns.Add($ColumnTwo)
            for ($i = 0; $i -lt $Permissions.User.Count; $i++) {
                $UPN = $Permissions[$i].User
                $Username = Get-ADUser -Filter { UserPrincipalName -eq $UPN } | Select-Object -ExpandProperty Name
                New-Variable -Name Row$i -Force
                $Row = $Table.NewRow()
                $Row.Name = $Username
                $Row.AccessRights = $Permissions.AccessRights[$i]
                $Table.Rows.Add($Row)
            }
            $Lines = ('-' * $TableName.Length)
            $Table.TableName
            $Lines
            $Table | Format-Table -AutoSize
        }
        Get-PSSession | Remove-PSSession
    }
    catch {
        Write-Warning $PSItem.Exception.Message
        Get-PSSession | Remove-PSSession
    }
}

$MailboxBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Import-Csv -Path \\$env:USERDNSDOMAIN\IT\PowerShell\DynamicParamFiles\SharedMailboxes.csv).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "'$PSItem'"
    }
}

Register-ArgumentCompleter -CommandName Get-SharedMailboxPermissions -ParameterName Mailbox -ScriptBlock $MailboxBlock

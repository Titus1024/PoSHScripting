function Update-SSModule {
<#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Used to easily update modules.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Name
    Used to update a single module, supports tab completion.
.PARAMETER All
    Used to update all available modules.
.EXAMPLE
    Update-SSModule -Help
.EXAMPLE
    Update-SSModule -Name Utilities
.EXAMPLE
    Update-SSModule -All
#>
    [cmdletbinding()]
    param (
    [Parameter(ParameterSetName = "Name",Position = 0, Mandatory = $true)][string]$Name,
    [Parameter(ParameterSetName = "All",Position = 0)][switch]$All,
    [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help MyInvocation.MyCommand.Name -Full | more
        break
    }

    if ($All) {
        $Modules = Find-Module -Repository REDACTED
        foreach ($Module in $Modules) {
            try {
                Update-Module $Module.Name -ErrorAction Stop
                Write-Output "Updating $($Module.Name)."
            }
            catch {
                continue
            }
        }
    }
    elseif ($Name) {
        try {
            Update-Module $Name -ErrorAction Stop
            Write-Output "Updating $($Module.Name)."
        }
        catch [Microsoft.PowerShell.Commands.WriteErrorException] {
            Write-Warning "$Name is not installed."
            Write-Output "Run `"Install-Module $Name -Scope CurrentUser`" to install."
        }
    }

}

$NameBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)

    (Find-Module -Repository REDACTED).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Update-SSModule -ParameterName Name -ScriptBlock $NameBlock

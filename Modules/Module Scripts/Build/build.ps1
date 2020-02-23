function Build {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    This script will compile all and future utility scripts into a module. Its purpose is to create a module while
                leaving the "Functions" as individual scripts for easy management and updating.
.PARAMETER Help
    Displays helpful information about the script.
.PARAMETER Identity
    Identifies the module you wish to build.
.PARAMETER NewModule
    Used when you are building a new module, this will create the necessary files and prompt for a description.
.PARAMETER Publish
    Publishes the module to the REDACTED Repository.
.PARAMETER Update
    Updates the module manifest, uses the Microsoft versioning standard.
.EXAMPLE
    Build -Help
.EXAMPLE
    Build -Identity Logging
    Builds the module Logging.
.EXAMPLE
    Build -Identity Logging -Publish -Update Revision
    Builds the logging module and publishes it with a revision update.
.EXAMPLE
    Build -Identity SomeModule -NewModule
    Builds the module called SomeModule and create the required files.
.Link
    Submit issues, bugs etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
#>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "NewModule", Position = 0, Mandatory = $true)]
        [Parameter(ParameterSetName = "Publish", Position = 0, Mandatory = $true)]
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]
        [string]$Identity,

        [Parameter(ParameterSetName = "NewModule", Position = 1)]
        [switch]$NewModule,

        [Parameter(ParameterSetName = "Publish", Position = 2)]
        [switch]$Publish,

        [Parameter(ParameterSetName = "Publish", Position = 3)]
        [ValidateSet('Major', 'Minor', 'Build', 'Revision')]
        [string]$Update,

        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    $Path = "\\$env:USERDNSDOMAIN\IT\PowerShell\Modules\Module Scripts\"
    $NewPath = $Path | Split-Path -Parent
    if ($NewModule) {
        # Creates required files and folders for the new module.
        try {
            # This will stop existing modules from being overwritten.
            New-Item -Path $NewPath\$Identity -ItemType Directory -ErrorAction Stop
            New-Item -Path $NewPath\$Identity\$Identity'.psm1' -ItemType File
            $Properties = @{
                Path          = "$NewPath\$Identity\$Identity.psd1"
                Author        = 'Mike Polselli'
                CompanyName   = 'REDACTED'
                Description   = Read-Host -Prompt "Enter a description for $Identity."
                ModuleVersion = '1.0.0.0'
                RootModule    = "$Identity.psm1"
            }
            New-ModuleManifest @Properties
        }
        catch {
            Write-Warning "The module $Identity already exists!"
        }
    }

    $Scripts = Get-ChildItem $Path\$Identity -Include *.ps1 -Recurse
    $Module = Get-ChildItem $NewPath\$Identity -Include *.psm1 -Recurse
    $Manifest = Get-ChildItem $NewPath\$Identity -Include *.psd1 -Recurse

    $Functions = @()
    Set-Content -Path $Module -Value $null

    foreach ($Script in $Scripts) {
        $Code = Get-Content -Path $Script.FullName
        Add-Content -Path $Module -Value $Code -Force
        Add-Content -Path $Module -Value "`n" -Force
        $Functions += $Script.Name.Split('.')[0]
    }
    Update-ModuleManifest -Path $Manifest -FunctionsToExport $Functions

    $GetFile = Get-ChildItem -Path $NewPath\$Identity *.psd1
    $TestManifest = Test-ModuleManifest -Path $GetFile.FullName
    if ($TestManifest.ExportedFunctions.Count -ne $Functions.Count) {
        Write-Warning "$Identity did not export all functions properly!"
    }
    #>

    if ($Publish) {
        # Publishes the module.
        $GetCurrentVersion = Get-Content -Path $GetFile.FullName | Select-String -Pattern '^ModuleVersion = (.*)'
        [version]$CurrentVersion = $GetCurrentVersion.Matches.Groups[1].Value.Replace("'", '')
        switch ($Update) {
            Major { $UpdatedVersion = "{0}.{1}.{2}.{3}" -f ($CurrentVersion.Major + 1), ($CurrentVersion.Minor - $CurrentVersion.Minor), ($CurrentVersion.Build - $CurrentVersion.Build), ($CurrentVersion.Revision - $CurrentVersion.Revision) }
            Minor { $UpdatedVersion = "{0}.{1}.{2}.{3}" -f $CurrentVersion.Major, ($CurrentVersion.Minor + 1 ), ($CurrentVersion.Build - $CurrentVersion.Build), ($CurrentVersion.Revision - $CurrentVersion.Revision) }
            Build { $UpdatedVersion = "{0}.{1}.{2}.{3}" -f $CurrentVersion.Major, $CurrentVersion.Minor, ($CurrentVersion.Build + 1), ($CurrentVersion.Revision - $CurrentVersion.Revision) }
            Revision { $UpdatedVersion = "{0}.{1}.{2}.{3}" -f $CurrentVersion.Major, $CurrentVersion.Minor, $CurrentVersion.Build, ($CurrentVersion.Revision + 1) }
        }
        (Get-Content -Path $GetFile.FullName -Raw) -replace $GetCurrentVersion.Matches.Groups[1].Value, $UpdatedVersion.Insert($UpdatedVersion.Length, "'").Insert(0, "'") | Set-Content -Path $GetFile.FullName

        Publish-Module -Path $NewPath\$Identity -Repository REDACTED
    }
}

$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)
    $Path = "\\$env:USERDNSDOMAIN\IT\PowerShell\Modules\Module Scripts\"
    (Get-ChildItem $Path).Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}

Register-ArgumentCompleter -CommandName Build -ParameterName Identity -ScriptBlock $IdentityBlock

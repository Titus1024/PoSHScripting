function Restart-ADComputer {
    <#
.DESCRIPTION
    Developer:  Mike Polselli
    PSVersion:  5.0
    Language:   PowerShell
    Purpose:    Restarts a computer.
.PARAMETER Help
    Displays helpful information about the script.
.EXAMPLE
    Restart-ADComputer -Help
.Link
    Submit issues, bugs, feature requests, etc. to the REDACTED Gitlab group.
    https://REDACTED/groups/REDACTED/powershell/-/issues
    #>
    [cmdletbinding(DefaultParameterSetName = "Primary")]
    param (
        [Parameter(ParameterSetName = "Primary", Position = 0, Mandatory = $true)]$Identity,
        #TODO: Add Shutdown switch.
        [Parameter(ParameterSetName = "Primary", Position = 1)][switch]$Shutdown,
        [Parameter(ParameterSetName = "Help")][switch]$Help
    )
    if ($Help) {
        Get-Help $MyInvocation.MyCommand.Name -Full | more
        break
    }
    
    $TestConnection = Test-Connection $Identity -Quiet -Count 1
    if (!$TestConnection) {
        Write-Output "The computer $Identity is currently offline or unavailable."
        break
    }

    $Credential = Use-PSCred -Identity PSADAcctMgmt
    if ($Shutdown) {
        $Prompt = Read-Host -Prompt "Shutting down $Identity.`nContinue? [Y][N] (Default: Y)"
        if ($Prompt -eq 'N') {
            Write-Output "Cancelling shutdown of $Identity."
        }
        else {
            Write-Output "Shutting down $Identity."
            Stop-Computer -ComputerName $Identity -Credential $Credential -Confirm:$false
        }
    }
    else {
        $Prompt = Read-Host -Prompt "Restarting $Identity.`nContinue? [Y][N] (Default: Y)"
        if ($Prompt -eq 'N') {
            Write-Output "Cancelling restart of $Identity."
        }
        else {
            Write-Output "Restarting $Identity."
            Restart-Computer -ComputerName $Identity -Credential $Credential
            do {
                $Connection = Test-Connection $Identity -Quiet
                Write-Output "Testing connection to $Identity..."
            }
            until ($Connection -eq $true)
            Write-Output "Successful connection to $Identity."
        }
    }
}
    
$IdentityBlock = {
    param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameter)
    
    (Get-ADComputer -Filter * -SearchBase 'OU=Computers,OU=REDACTED,DC=AD,DC=REDACTED,DC=org').Name | Where-Object {
        $PSItem -like "$WordToComplete*"
    } | ForEach-Object {
        "$PSItem"
    }
}
    
Register-ArgumentCompleter -CommandName Restart-ADComputer -ParameterName Identity -ScriptBlock $IdentityBlock

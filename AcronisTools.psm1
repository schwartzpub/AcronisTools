function Get-AcronisSecretStore {
    <#
    .SYNOPSIS
        Gets a Powershell Secret Store used for Acronis Tools.
    .DESCRIPTION
        Gets secret store used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name
    )

    if(-not (Get-Module Microsoft.PowerShell.SecretManagement)){
        Write-Error "You do not have Microsoft.PowerShell.SecretManagement (required) installed, would you like to install it now?"
    }

    if(-not (Get-Module Microsoft.PowerShell.SecretStore)){
        Write-Error "You do not have Microsoft.PowerShell.SecretStore (required) installed, would you like to install it now?"
    }

    if (-not (Get-SecretInfo -Name $Name)){
        Write-Error "Secret store ($($Name)) does not exist."
    }
}
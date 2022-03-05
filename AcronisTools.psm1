function Get-AcronisSecretVault {
    <#
    .SYNOPSIS
        Gets a Powershell Secret Vault used for Acronis Tools.
    .DESCRIPTION
        Gets secret vault used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name
    )

    if (-not (Get-SecretVault -Name $Name -ErrorAction SilentlyContinue)){
        Write-Warning "Secret Vault ($($Name)) does not exist. These are the secret vaults available: "
        Get-SecretVault
    }
    else {
        Unlock-SecretVault -Name $Name
    }
}

function Get-AcronisSecret {
        <#
    .SYNOPSIS
        Gets a Powershell Secret  used for Acronis Tools.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault
    )

    if (-not (Get-Secret -Vault $Vault -Name $Name -ErrorAction SilentlyContinue)){
        Write-Warning "Secret ($($Name)) does not exist. These are the secrets available: "
        Get-SecretInfo -Vault $Vault
        return
    }

    if ($null -eq (Get-SecretInfo -Name $Name).Metadata.clientid){
        Write-Warning "Secret ($($Name)) does not contain a client id and cannot be used to access Acronis API. Please ensure your secret contains the metadata for clientid."
        return
    }

    else {
        $thisSecret = [PSCustomObject]@{
            Name = $Name
            ClientID = (Get-SecretInfo -Name $name).Metadata.clientid
            ClientSecret = Get-Secret -Name $Name
        }
        return $thisSecret
    }
}

function Get-AcronisLogins {
    $acronisVault = Read-Host "Please enter Vault name to unlock: "
    Get-AcronisSecretVault $acronisVault

    foreach ($secret in (Get-SecretInfo -Vault $acronisVault)){
        Get-AcronisSecret -Name $secret.Name -Vault $acronisVault
    }
}

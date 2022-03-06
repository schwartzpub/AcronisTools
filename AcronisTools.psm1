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

function New-AcronisSecretVault {
    <#
    .SYNOPSIS
        Creates a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name
    )

    Register-SecretVault -Name $Name -ModuleName Microsoft.PowerShell.SecretStore 
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

function New-AcronisSecret {
    <#
    .SYNOPSIS
        Creates a new PowerShell Secret for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$BaseUri
    )

    if (-not (Get-SecretVault -Name $Vault -ErrorAction SilentlyContinue)){
        Write-Warning "Secret Vault ($($Vault)) does not exist. These are the secret vaults available: "
        Get-SecretVault
        return
    }
    else {
        Set-Secret -Vault $Vault -Name $Name -Secret $ClientSecret -Metadata @{clientid=$ClientID}
    }
}

function Set-AcronisSecret {
    <#
    .SYNOPSIS
        Sets a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$BaseUri
    )

    if (-not (Get-SecretVault -Name $Vault -ErrorAction SilentlyContinue)){
        Write-Warning "Secret Vault ($($Vault)) does not exist. These are the secret vaults available: "
        Get-SecretVault
        return
    }
    elseif ($ClientID -ne $null -and $ClientSecret -eq $null) {
        Set-Secret -Vault $Vault -Name $Name -Metadata @{clientid=$ClientID}
    }
    elseif ($ClientID -eq $null -and $ClientSecret -ne $null) {
        Set-Secret -Vault $Vault -Name $Name -Secret $ClientSecret
    }
    else {
        Set-Secret -Vault $Vault -Name $Name -Secret $ClientSecret -Metadata @{clientid=$ClientID}
    }
}

function Get-AcronisTenant {
    <#
    .SYNOPSIS
        Sets a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$BaseUri
    )

}

function Get-AcronisToken {
    <#
    .SYNOPSIS
        Sets a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$BaseUri
    )

}

function Set-AcronisToken {
    <#
    .SYNOPSIS
        Sets a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$BaseUri
    )

}

function New-AcronisToken {
    <#
    .SYNOPSIS
        Sets a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$BaseUri
    )

}

function Find-AcronisClient {
    <#
    .SYNOPSIS
        Sets a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
        [string]$BaseUri
    )

}

function Get-AcronisLogins {
    $acronisVault = Read-Host "Please enter Vault name to unlock or type 'new' to create a new vault: "

    if ($acronisVault -ne "new"){
        Get-AcronisSecretVault $acronisVault
    }
    else {
        $vaultName = Read-Host "Please enter a name for your new Acronis Secrets Vault: "
        New-AcronisSecretVault -Name $vaultName

        Get-AcronisSecretVault $vaultName
        $acronisVault = $vaultName
    }

    foreach ($secret in (Get-SecretInfo -Vault $acronisVault)){
        Get-AcronisSecret -Name $secret.Name -Vault $acronisVault
    }
}

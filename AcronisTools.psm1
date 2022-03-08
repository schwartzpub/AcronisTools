function Get-AcronisSecretVault {
    <#
    .SYNOPSIS
        Gets a Powershell Secret Vault used for Acronis Tools.
    .DESCRIPTION
        Gets secret vault used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Name
    )

    BEGIN {
        if (-not (Get-SecretVault -Name $Name -ErrorAction SilentlyContinue)){
            Write-Warning "Secret Vault ($($Name)) does not exist. These are the secret vaults available: "
            Get-SecretVault
        }
    }
    PROCESS {
        if ((Get-SecretVault -Name $Name -ErrorAction SilentlyContinue)){
            Unlock-SecretVault -Name $Name
        }
    }
    END{

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
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Name
    )
    BEGIN {}
    PROCESS {
        Register-SecretVault -Name $Name -ModuleName Microsoft.PowerShell.SecretStore 
    }
    END {}
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
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Vault
    )

    BEGIN {}
    PROCESS {
        if (-not (Get-Secret -Vault $Vault -Name $Name -ErrorAction SilentlyContinue)){
            Write-Warning "Secret ($($Name)) does not exist. These are the secrets available: "
            Get-SecretInfo -Vault $Vault
            return
        }

        if ($null -eq (Get-SecretInfo -Name $Name).Metadata.clientid){
            Write-Warning "Secret ($($Name)) does not contain a client id and cannot be used to access Acronis API. Please ensure your secret contains the metadata for clientid."
            return
        }

        if ($null -eq (Get-SecretInfo -Name $Name).Metadata.baseuri){
            Write-Warning "Secret ($($Name)) does not contain a Base Uri and cannot be used to access Acronis API. Please ensure your secret contains the metadata for Base Uri."
            return
        }

        else {
            $thisSecret = [PSCustomObject]@{
                Name = $Name
                ClientID = (Get-SecretInfo -Name $Name -Vault $Vault).Metadata.clientid
                ClientSecret = Get-Secret -Name $Name -Vault $Vault
                BaseUri = (Get-SecretInfo -Name $Name -Vault $Vault).Metadata.baseuri
            }
            return $thisSecret
        }
    }
    END {}
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
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$BaseUri
    )

    BEGIN {}
    PROCESS {
        if (-not (Get-SecretVault -Name $Vault -ErrorAction SilentlyContinue)){
            Write-Warning "Secret Vault ($($Vault)) does not exist. These are the secret vaults available: "
            Get-SecretVault
            return
        }
        else {
            Set-Secret -Vault $Vault -Name $Name -Secret $ClientSecret -Metadata @{clientid=$ClientID;baseuri=$BaseUri}
        }
    }
    END {}
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
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Vault,
        [Parameter(Position = 2, ValueFromPipeline = $true)]
        [string]$ClientID,
        [Parameter(Position = 3, ValueFromPipeline = $true)]
        [string]$ClientSecret,
        [Parameter(Position = 4, ValueFromPipeline = $true)]
        [string]$BaseUri
    )
    BEGIN {
        $metadata = @{}
        $secret = ''

        if ($PSBoundParameters.ContainsKey('ClientID')){
            $metadata['clientid'] = $ClientID
        }

        if ($PSBoundParameters.ContainsKey('BaseUri')){
            $metadata['baseuri'] = $BaseUri
        }

        if ($PSBoundParameters.ContainsKey('ClientSecret')){
            $secret = $ClientSecret
        }
    }
    PROCESS {
        if (-not (Get-SecretVault -Name $Vault -ErrorAction SilentlyContinue)){
            Write-Warning "Secret Vault ($($Vault)) does not exist. These are the secret vaults available: "
            Get-SecretVault
            return
        }
        else {
            if (-not $metadata -and $clientsecret) {
                Set-Secret -Vault $Vault -Name $Name -Metadata $metadata
            }
            elseif (-not $ClientSecret -and $metadata) {
                Set-Secret -Vault $Vault -Name $Name -Secret $secret
            }
            else {
                Set-Secret -Vault $Vault -Name $Name -Secret $secret -Metadata $metadata
            }
        }
    }
    END {

    }
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
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$SecretName,
        [Parameter(Position = 1, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$SecretVault
    )

    BEGIN{
        $thisClientSecret = Get-Secret -Name $Name -Vault $Vault
        $thisClientMetadata = (Get-SecretInfo -Name $Name -Vault $Vault).Metadata

        $pair = "${thisClientMetadata.ClientID}:${thisClientSecret}"
        $pairBytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $pairBase64 = [System.Convert]::ToBase64String($pairBytes)

        $basicAuthentication = "Basic $pairBase64"
        $headers = @{"Authorization"=$basicAuthentication}
        $headers.Add("Content-Type","applicati0on/x-www-form-urlencoded")

        $postParams = @{"grant_type" = "client_credentials"}
    }
    PROCESS{
        $token = Invoke-RestMethod -Method Post -Uri "https://$($thisClientMetadata.baseuri)/api/2/idp/token" -Headers $headers -Body $postParams
    }
    END{
        return $token
    }
}

function New-AcronisClientSearch {
    <#
    .SYNOPSIS
        Sets a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$SecretVault,
        [Parameter(Position = 1, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$TokenVault
    )
    BEGIN{
        if (-not (Get-SecretVault -Name $SecretVault -ErrorAction SilentlyContinue)){
            Write-Warning "Secret Vault ($($SecretVault)) does not exist. These are the vaults available: "
            Get-SecretVault
        }
        if (-not (Get-SecretVault -Name $TokenVault -ErrorAction SilentlyContinue)){
            Write-Warning "Token Vault ($($TokenVault)) does not exist. These are the vaults available: "
            Get-SecretVault
        }
    }
    PROCESS{

    }
    END{

    }
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

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
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
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
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
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

    BEGIN{
        $pair = "${ClientID}:${ClientSecret}"
        $pairBytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $pairBase64 = [System.Convert]::ToBase64String($pairBytes)

        $basicAuthentication = "Basic $pairBase64"
        $headers = @{"Authorization"=$basicAuthentication}
        $headers.Add("Content-Type","applicati0on/x-www-form-urlencoded")

        $postParams = @{"grant_type" = "client_credentials"}
    }
    PROCESS{
        $token = Invoke-RestMethod -Method Post -Uri "https://$BaseUri/api/2/idp/token" -Headers $headers -Body $postParams

        $metadata = @{}
        $metadata['token_type'] = $token.token_type
        $metadata['expires_in'] = $token.expires_in
        $metadata['expires_on'] = $token.expires_on
        $metadata['id_token'] = $token.id_token
        $metadata['scope'] = $token.scope
    }
    END{
        if ($token.status_code -ne 200){
            return "Error"
        }
        else {
            Set-Secret -Name $Name -Vault $Vault -Secret $token.access_token
            Set-SecretInfo -Name $Name -Vault $Vault -Metadata $metadata
        }
    }
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
    BEGIN{}
    PROCESS{}
    END{}
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
        [string]$Name,
        [Parameter(Position = 1, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [string]$Vault
    )
    BEGIN{}
    PROCESS{
        if (-not (Get-Secret -Vault $Vault -Name $Name -ErrorAction SilentlyContinue)){
            Write-Warning "SToken ($($Name)) does not exist. These are the tokens available: "
            Get-SecretInfo -Vault $Vault
            return
        }
        else {
            $thisToken = [PSCustomObject]@{
                access_token = Get-Secret -Name $Name -Vault $Vault
                token_type = (Get-SecretInfo -Name $Name -Vault $Vault).Metadata.token_type
                expires_in = (Get-SecretInfo -Name $Name -Vault $Vault).Metadata.expires_in
                expires_on = (Get-SecretInfo -Name $Name -Vault $Vault).Metadata.expires_on
                id_token = (Get-SecretInfo -Name $Name -Vault $Vault).Metadata.id_token
                scope = (Get-SecretInfo -Name $Name -Vault $Vault).Metadata.scope
            }
            $thisToken
        }
    }
    END{}
}

function Test-AcronisToken {
<#
    .SYNOPSIS
        Sets a new PowerShell Secret Vault for Acronis Secrets.
    .DESCRIPTION
        Gets secret used for logging into Acronis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true, Mandatory = $true)]
        [PSCustomObject]$Token
    )

    BEGIN {}
    PROCESS {
        $unixTime = $token.expires_on

        $expireOnTime = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($unixTime))
        $timeDifference = New-TimeSpan -End $expireOnTime

        $timeDifference.TotalMinutes -gt 15
    }
    END {}
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
    BEGIN{}
    PROCESS{}
    END{}
}

function Get-AcronisApiClient {

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

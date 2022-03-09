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

function New-AcronisSecret {
    <#
    .SYNOPSIS
        Creates a new Secret in the Microsoft Secret Store for Acronis API Clients.  
    .DESCRIPTION
        Creates a new Secret in the Microsoft Secret Store for Acronis API Clients.  
        Takes several required strings, including metadata to accompany the login.
    .PARAMETER Name
        Specifies the name of the Secret, typically this will be an recognizable identifier for the tenant.
    .PARAMETER Vault
        Specifies the name of the Vault to store the secret.  This is typically a unique Vault used for storing Acronis Tools API Client Secrets.
    .PARAMETER ClientID
        The UUID of the Acronis API Client issued for API access to your Acronis Tenant.
    .PARAMETER ClientSecret
        The Client Secret issued with your Acronis API Client ID for API access to your Acronis Tenant.
    .PARAMETER BaseUri
        The Base Uri used to authenticate and make API requests to your tenant.  This is typically the domain portion of the URL (eg. dev.acronis.com)
    .EXAMPLE
        PS> New-AcronisSecret -Name AcronisTenantName -Vault AcronisVault -ClientID 962f8b0e-9f4f-11ec-b909-0242ac120002 -ClientSecret 1a474d9a50074b14b8288ca0b62573e -BaseUri us5-cloud.acronis.com
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

    if (-not (Get-SecretVault -Name $Vault -ErrorAction SilentlyContinue)){
        Write-Warning "Secret Vault ($($Vault)) does not exist. These are the secret vaults available: "
        Get-SecretVault
        return
    }
    else {
        Set-Secret -Vault $Vault -Name $Name -Secret $ClientSecret -Metadata @{clientid=$ClientID;baseuri=$BaseUri}
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

    $thisClientSecret = Get-Secret -Name $SecretName -Vault $SecretVault -AsPlainText
    $thisClientMetadata = (Get-SecretInfo -Name $SecretName -Vault $SecretVault).Metadata

    $thisClientId = $thisClientMetadata.clientid

    $pair = "${thisClientId}:${thisClientSecret}"
    $pairBytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $pairBase64 = [System.Convert]::ToBase64String($pairBytes)

    $basicAuthentication = "Basic $pairBase64"
    $headers = @{"Authorization"=$basicAuthentication}
    $headers.Add("Content-Type","application/x-www-form-urlencoded")

    $postParams = @{"grant_type" = "client_credentials"}

    $token = Invoke-RestMethod -Method Post -Uri "https://$($thisClientMetadata.baseuri)/api/2/idp/token" -Headers $headers -Body $postParams

    return $token
}

function New-AcronisClientSearch {
    <#
    .SYNOPSIS
        Performs a new search using credentials stored in the supplied Secret Vault.  
    .DESCRIPTION
        Performs a new search using credentials stored in the supplied Secret Vault.  
        Must supply the name of your Acronis API Client Secret Vault as well as the search term you wish to use.
    .PARAMETER SecretVault
        Specifies the name of the Acronis API Client Secret Vault, typically this vault only contains secrets and metadata used for the Acronis Tools solution.
    .PARAMETER SearchTerm
        The keyword(s) you would like to search for.  This will be used to search for matches in client/partner names across all tenants you have stored in your secret vault.
    .EXAMPLE
        PS> New-AcronisClientSearch -SecretVault AcronisSecretVault -SearchTerm MyAcronisPartner
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$SecretVault,
        [Parameter(Position = 1, ValueFromPipeline = $true, Mandatory = $true)]
        [string]$SearchTerm
    )

    if (-not (Get-SecretVault -Name $SecretVault -ErrorAction SilentlyContinue)){
        Write-Warning "Secret Vault ($($SecretVault)) does not exist. These are the vaults available: "
        Get-SecretVault
    }
    else {
        Get-AcronisSecretVault -Name $SecretVault
        foreach ($secret in Get-SecretInfo -Vault $SecretVault) {
            #Get new token
            $token = New-AcronisToken -SecretName $secret.Name -SecretVault $SecretVault
            $tenantId = $token.scope.Split(":")[3]

            #Search tenant
            $bearerAuthentication = "Bearer $($token.access_token)"
            $headers = @{"Authorization"=$bearerAuthentication}

            $getParams = @{"tenant"=$tenantId;"text"=$SearchTerm}

            $result = Invoke-RestMethod -Method Get -Uri "https://$($secret.Metadata.baseuri)/api/2/search" -Headers $headers -Body $getParams
            
            if (-not $result.items){
                continue
            }
            else {
                foreach ($item in $result.items){
                    Write-Output "Match found in tenant ($($secret.Name)): $($item.name)"
                }
            }
        }
    }
}
# Where is this Acronis partner??

## The Problem
It occurred to me recently that there was a pretty glaring issue with how large-scale companies interact with Acronis to manage and maintain Partner and Client tenants for backups and disaster recovery.  There is a limit on how many Partners or Clients an account can contain, and after that you have to start tacking on new accounts to accommodate the growth.  Since there isn't currently a supported way to combine these accounts, the onus is on the provider to come up with a way to organize and find the Partners and Clients in their respective tenants.  

This can lead to quite a headache when it comes to providing support as the number of accounts grows (think thousands of partners/clients across tens of Acronis accounts).  If you're documentation is up to date and well maintained, obviously this isn't a concern.  But we all know too well how often these knowledgebases are updated and maintained, leading to a very frustrating search for which tenant a particular client or partner resides in.

Thankfully Acronis has provided an API that can be used to perform a variety of functions on tenants.  In my case, I just needed a reliable (and fast!) way to find out which of the Acronis tenants the partner or client resided in.

## The Solution
Here is where (Acronis Tools)[https://github.com/schwartzpub/AcronisTools] comes in.

I thought I'd have some fun and learn a little about the Acronis API while simultaneously learning a bit more about the [Microsoft Secret Store](https://devblogs.microsoft.com/powershell/secretmanagement-and-secretstore-are-generally-available/) in PowerShell.  

My main goal was to make a simple cmdlet that would allow a user to provide a search term that would search all relevant Acronis tenants for a particular partner or client.  In order to do this we would need an API Client for each Acronis tenant, as well as a reliable, but more importantly secure, method of storing a multitude of API Client credentials that the tool could iterate through when finding the appropriate tenant.  

To start, I needed to find out what was needed in order to use the Acronis API.  According to documentation I first need to [register an Acronis API Client](https://developer.acronis.com/doc/resource-policy-management/v4/guide/getting-started/authenticating).  The documentation explains how to do this in python, but thankfully a helpful blog post from [Acronis also details how this can be done in PowerShell](https://developer.acronis.com/blog/posts/base-acronis-cyber-platform-api-operations-with-power-shell/). There's also a simpler method for creating an API Client directly in the GUI of the tenant.  The result of either method is the same, a ClientID and ClientSecret that can then be used to request a token for further API requests.

I then created a cmdlet: New-AcronisSecret.  This cmdlet will allow the user to store not only the ClientID as well as the ClientSecret, but also store the BaseUri of the API endpoint in the secret store metadata.  This will become crucial when iterating through all of the clients during the search, which is why I opted to create a wrapper for Set-Secret to ensure BaseUri and ClientID would be included in the secret metadata.

```powershell
function New-AcronisSecret {
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
```
By specifying a particular vault name, I can later pass this name to the search query in order to iterate through only the desired secrets stored in the secret store.  Without a unique vault name, you would end up iterating through any other stored secrets in your store that are unrelated to the Acronis query.

The next thing I wanted to do was create a way to retrieve and use an Acronis API Token for making API calls. Initially I was noodling various ways I could store tokens in the Microsoft Secret Store, check their validity, and if necessary request a new one to be stored and subsequently used for the script. This seemed like an excess of unnecessary logic for such a simple script, so I opted to request a new token at runtime for each tenant being searched.

I created another cmdlet for retrieving a token at runtime that would be used to search the tenant for the requested term.

```powershell
function New-AcronisToken {
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
```

Now we have the basics needed to run the search -- all that is left is to iterate through all of the stored clients and find our goal.
```powershell
function New-AcronisClientSearch {
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
```
In all, this was a quick and easy experiment that will allow someone to quickly and efficiently search for a partner/client in what could be many, many Acronis tenants to get started and help their users uncover problems that may be happening in their environment.  Without an easy way to find these partners/clients, it could take quite a while to manually search through all of the associated tenants for the one containing the right account.

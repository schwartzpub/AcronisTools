# AcronisTools
Powershell Tools for Acronis.

At its core, this is really just a useful tool to search across all tenants for a specific client or partner.  Since Acronis has limits to how many clients/partners a tenant can house, you may be in a situation where you are responsible for clients/partners across a multitude of tenants.  Sometimes finding the right tenant can be time consuming when done manually, this tool aims to make that process easier.

## Prerequisites

### Microsoft Secret Store
AcronisTools uses the Microsoft Secret Store to securely store credentials and tokens for Acronis tenants.  In order to use this tool, you must first install the appropriate modules and configure your secret store.

First, install the required modules:
```powershell
Install-Module -Name "Microsoft.PowerShell.SecretManagement" -AllowPrerelease
Install-Module -Name "Microsoft.PowerShell.SecretStore" -AllowPrerelease
```

Then, configure your API Client vault.  This will store your Acronis API Client credentials. You can name this whatever you like, the AcronisTools module will ask you to provide the name at runtime.
```powershell
Register-SecretVault -Name <AcronisSecretVault> -ModuleName "Microsoft.PowerShell.SecretStore"
```
## Authentication

### Acronis API Client
You must be issued an [Acronis API Client](https://www.acronis.com/en-us/support/documentation/AcronisCyberCloud/index.html#creating-api-client.html), once a client has been issued to you, you will store the client in your secret vault.
```powershell
New-AcronisSecret -Name <TenantName> -Vault <AcronisSecretVault> -ClientID <AcronisAPIClientID> -BaseUri <AcronisBaseUri> -ClientSecret <AcronisAPIClientSecret>
```
You can add multiple API clients for multiple tenants into the secret vault, which can be used to search multiple tenants at the same time.

```
NAME
    New-AcronisSecret

SYNOPSIS
    Creates a new Secret in the Microsoft Secret Store for Acronis API Clients.


SYNTAX
    New-AcronisSecret [-Name] <String> [-Vault] <String> [-ClientID] <String> [-ClientSecret] <String> [-BaseUri]
    <String> [<CommonParameters>]


DESCRIPTION
    Creates a new Secret in the Microsoft Secret Store for Acronis API Clients.
    Takes several required strings, including metadata to accompany the login.


PARAMETERS
    -Name <String>
        Specifies the name of the Secret, typically this will be an recognizable identifier for the tenant.

    -Vault <String>
        Specifies the name of the Vault to store the secret.  This is typically a unique Vault used for storing
        Acronis Tools API Client Secrets.

    -ClientID <String>
        The UUID of the Acronis API Client issued for API access to your Acronis Tenant.

    -ClientSecret <String>
        The Client Secret issued with your Acronis API Client ID for API access to your Acronis Tenant.

    -BaseUri <String>
        The Base Uri used to authenticate and make API requests to your tenant.  This is typically the domain portion
        of the URL (eg. dev.acronis.com)
```

### Acronis API Tokens
Acronis API Tokens will be requested at runtime.  The tokens will not be stored, and will be used for the duration of the process.

## Usage

### Searching Acronis Tenants for a Client or Partner
To search for a client/partner within your tenants, you will issue the New-AcronisClientSearch command.
```powershell
New-AcronisClientSearch -SecretVault <AcronisSecretVault> -SearchTerm <ClientName>
```
This will iterate through your tenants stored in the secrets vault and perform a search against the clients/partners in each tenant in order to locate the tenant that houses the client/partner that matches your search term.

```
NAME
    New-AcronisClientSearch

SYNOPSIS
    Performs a new search using credentials stored in the supplied Secret Vault.


SYNTAX
    New-AcronisClientSearch [-SecretVault] <String> [-SearchTerm] <String> [<CommonParameters>]


DESCRIPTION
    Performs a new search using credentials stored in the supplied Secret Vault.
    Must supply the name of your Acronis API Client Secret Vault as well as the search term you wish to use.


PARAMETERS
    -SecretVault <String>
        Specifies the name of the Acronis API Client Secret Vault, typically this vault only contains secrets and
        metadata used for the Acronis Tools solution.

    -SearchTerm <String>
        The keyword(s) you would like to search for.  This will be used to search for matches in client/partner names
        across all tenants you have stored in your secret vault.
```

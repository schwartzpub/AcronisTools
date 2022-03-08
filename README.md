# AcronisTools
Powershell Tools for Acronis

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
Register-SecretVault -Name "AcronisCredentials" -ModuleName "Microsoft.PowerShell.SecretStore"
```
## Authentication

### Acronis API Client
You must be issued an [Acronis API Client](https://www.acronis.com/en-us/support/documentation/AcronisCyberCloud/index.html#creating-api-client.html), once a client has been issued to you, you will store the client in your secret vault.
```powershell
New-AcronisSecret -Name <TenantName> -Vault <AcronisSecretVault> -ClientID <AcronisAPIClientID> -BaseUri <AcronisBaseUri> -ClientSecret <AcronisAPIClientSecret>
```
You can add multiple clients for multiple tenants into the secret vault, which can be used to search multiple tenants at the same time.

### Acronis API Tokens
Acronis API Tokens will be requested at runtime.  The tokens will not be stored, and will be used for the duration of the process.

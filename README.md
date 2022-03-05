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

Then, configure two vaults.  One will store your Acronis credentials, and one will store your Acronis API Tokens. You can name these whatever you like, the AcronisTools module will ask you to provide the names at runtime.
```powershell
Register-SecretVault -Name "AcronisCredentials" -ModuleName "Microsoft.PowerShell.SecretStore"
Register-SecretVault -Name "AcronisTokens" -ModuleName "Microsoft.PowerShell.SecretStore"
```

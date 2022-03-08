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

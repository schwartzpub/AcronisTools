# AcronisTools
Powershell Tools for Acronis

## Prerequisites

### Microsoft Secret Store
AcronisTools uses the Microsoft Secret Store to securely store credentials and tokens for Acronis tenants.  In order to use this tool, you must first install the appropriate modules and configure your secret store.

First, install the Secret Store module:
```
Install-Module Microsoft.PowerShell.SecretStore
```

Then, configure your Secret Store
```
Set-SecretStoreContiguration
```

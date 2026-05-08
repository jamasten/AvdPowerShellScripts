<#
MIT License

Copyright (c) 2026 Jason Masten

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

.SYNOPSIS
Update the Kerberos encryption for Azure Files.

.DESCRIPTION
This script will update a domain joined storage account in Azure to use AES256 Kerberos encryption for SMB connections.

.PARAMETER DomainAdminUserPrincipalName
The user principal name of the domain admin account to use for removing andcreating the computer object in Active Directory Domain Services.

.PARAMETER Environment
The name of the Azure environment.

.PARAMETER OrganizationalUnitPath
Optional. The distinguished name of the organizational unit in Active Directory Domain Services.

.PARAMETER StorageAccountName
The name of the Azure Storage Account.

.PARAMETER StorageAccountResourceGroupName
The Resource Group name containing the Azure Storage Account.

.PARAMETER SubscriptionId
The ID of the Azure Subscription.

.NOTES
  Version:              1.0
  Author:               Jason Masten
  Creation Date:        2026-05-06
  Last Modified Date:   2026-05-06

.EXAMPLE
.\Set-AzureFilesKerberosEncryption.ps1 `
    -DomainAdminUserPrincipalName 'xadmin@fabrikam.com' `
    -Environment 'AzureCloud' `
    -OrganizationalUnitPath 'OU=AVD,DC=Fabrikam,DC=COM' `
    -StorageAccountName 'saavdpeus' `
    -StorageAccountResourceGroupName 'rg-avd-p-eus' `
    -SubscriptionId '00000000-0000-0000-0000-000000000000'

This example domain joins an Azure Storage Account to the AVD organizational unit in the Fabrikam.com domain.
#>

param 
(
    [Parameter(Mandatory=$true)]
    [String]$DomainAdminUserPrincipalName,

    [Parameter(Mandatory=$false)]
    [ValidateSet("AzureCloud","AzureUSGovernment")]
    [String]$Environment = 'AzureCloud',

    [Parameter(Mandatory=$false)]
    [String]$OrganizationalUnitPath,

    [Parameter(Mandatory=$true)]
    [String]$StorageAccountName,

    [Parameter(Mandatory=$true)]
    [String]$StorageAccountResourceGroupName,

    [Parameter(Mandatory=$true)]
    [String]$SubscriptionId
)

$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'

[String]$AzureManagementAccessToken = Read-Host -Prompt "Enter the Azure Management Access Token"
[SecureString]$DomainAdminPassword = Read-Host -Prompt "Enter the password for the domain admin account $DomainAdminUserPrincipalName" -AsSecureString

switch($Environment)
{
    "AzureCloud" {
        $ResourceManagerUri = 'https://management.azure.com/'
        $StorageSuffix = 'core.windows.net'
    }
    "AzureUSGovernment" {
        $ResourceManagerUri = 'https://management.usgovcloudapi.net/'
        $StorageSuffix = 'core.usgovcloudapi.net'
    }
}

# Install Active Directory PowerShell module
$RsatInstalled = (Get-WindowsFeature -Name 'RSAT-AD-PowerShell').Installed
if(!$RsatInstalled)
{
    Install-WindowsFeature -Name 'RSAT-AD-PowerShell' | Out-Null
}

# Create Domain credential
$DomainUsername = $DomainAdminUserPrincipalName
$DomainPassword = ConvertTo-SecureString -String $DomainAdminPassword -AsPlainText -Force
[pscredential]$DomainCredential = New-Object System.Management.Automation.PSCredential ($DomainUsername, $DomainPassword)

# Get Domain information
$Domain = Get-ADDomain -Credential $DomainCredential -Current 'LocalComputer'

# Set suffix for Azure Files
$FilesSuffix = '.file.' + $StorageSuffix

# Fix the resource manager URI since only AzureCloud contains a trailing slash
$ResourceManagerUriFixed = if ($ResourceManagerUri[-1] -eq '/') { $ResourceManagerUri.Substring(0, $ResourceManagerUri.Length - 1) } else { $ResourceManagerUri }

# Set header for Azure Management API
$AzureManagementHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $AzureManagementAccessToken
}

# Domain join Azure Files to ADDS
# Get / create kerberos key for Azure Storage Account
$KerberosKey = ((Invoke-RestMethod `
    -Headers $AzureManagementHeader `
    -Method 'POST' `
    -Uri $($ResourceManagerUriFixed + '/subscriptions/' + $SubscriptionId + '/resourceGroups/' + $StorageAccountResourceGroupName + '/providers/Microsoft.Storage/storageAccounts/' + $StorageAccountName + '/listKeys?api-version=2023-05-01&$expand=kerb')).keys | Where-Object { $_.Keyname -contains 'kerb1' }).Value

if (!$KerberosKey) 
{
    Invoke-RestMethod `
        -Body (@{keyName = 'kerb1' } | ConvertTo-Json) `
        -Headers $AzureManagementHeader `
        -Method 'POST' `
        -Uri $($ResourceManagerUriFixed + '/subscriptions/' + $SubscriptionId + '/resourceGroups/' + $StorageAccountResourceGroupName + '/providers/Microsoft.Storage/storageAccounts/' + $StorageAccountName + '/regenerateKey?api-version=2023-05-01')
    
    $Key = ((Invoke-RestMethod `
        -Headers $AzureManagementHeader `
        -Method 'POST' `
        -Uri $($ResourceManagerUriFixed + '/subscriptions/' + $SubscriptionId + '/resourceGroups/' + $StorageAccountResourceGroupName + '/providers/Microsoft.Storage/storageAccounts/' + $StorageAccountName + '/listKeys?api-version=2023-05-01&$expand=kerb')).keys | Where-Object { $_.Keyname -contains 'kerb1' }).Value
} 
else 
{
    $Key = $KerberosKey
}

# Creates a password for the Azure Storage Account in AD using the Kerberos key
$ComputerPassword = ConvertTo-SecureString -String $Key.Replace("'","") -AsPlainText -Force

# Create the SPN value for the Azure Storage Account; attribute for computer object in AD 
$SPN = 'cifs/' + $StorageAccountName + $FilesSuffix

# Create the Description value for the Azure Storage Account; attribute for computer object in AD 
$Description = "Computer account object for Azure storage account $($StorageAccountName)."

# Create the AD computer object for the Azure Storage Account
$OldComputerObject = Get-ADComputer -Credential $DomainCredential -Filter {Name -eq $StorageAccountName}
if ($OldComputerObject)
{
    Remove-ADComputer -Credential $DomainCredential -Identity $StorageAccountName -Confirm:$false
}

if ($OrganizationalUnitPath) {
    $NewComputerObject = New-ADComputer -Credential $DomainCredential -Name $StorageAccountName -Path $OrganizationalUnitPath -ServicePrincipalNames $SPN -AccountPassword $ComputerPassword -Description $Description -PassThru
} else {
    $NewComputerObject = New-ADComputer -Credential $DomainCredential -Name $StorageAccountName -ServicePrincipalNames $SPN -AccountPassword $ComputerPassword -Description $Description -PassThru
}

$Body = (@{
    properties = @{
        azureFilesIdentityBasedAuthentication = @{
            activeDirectoryProperties = @{
                accountType = 'Computer'
                azureStorageSid = $NewComputerObject.SID.Value
                domainGuid = $Domain.ObjectGUID.Guid
                domainName = $Domain.DNSRoot
                domainSid = $Domain.DomainSID.Value
                forestName = $Domain.Forest
                netBiosDomainName = $Domain.NetBIOSName
                samAccountName = $StorageAccountName
            }
            directoryServiceOptions = 'AD'
        }
    }
} | ConvertTo-Json -Depth 6 -Compress)

Invoke-RestMethod `
    -Body $Body `
    -Headers $AzureManagementHeader `
    -Method 'PATCH' `
    -Uri $($ResourceManagerUriFixed + '/subscriptions/' + $SubscriptionId + '/resourceGroups/' + $StorageAccountResourceGroupName + '/providers/Microsoft.Storage/storageAccounts/' + $StorageAccountName + '?api-version=2023-05-01')

# Set the Kerberos encryption on the computer object
Set-ADComputer -Credential $DomainCredential -Identity $StorageAccountName -KerberosEncryptionType 'AES256' | Out-Null

# Reset the Kerberos key on the Storage Account
Invoke-RestMethod `
    -Body (@{keyName = 'kerb1' } | ConvertTo-Json) `
    -Headers $AzureManagementHeader `
    -Method 'POST' `
    -Uri $($ResourceManagerUriFixed + '/subscriptions/' + $SubscriptionId + '/resourceGroups/' + $StorageAccountResourceGroupName + '/providers/Microsoft.Storage/storageAccounts/' + $StorageAccountName + '/regenerateKey?api-version=2023-05-01')

$Key = ((Invoke-RestMethod `
    -Headers $AzureManagementHeader `
    -Method 'POST' `
    -Uri $($ResourceManagerUriFixed + '/subscriptions/' + $SubscriptionId + '/resourceGroups/' + $StorageAccountResourceGroupName + '/providers/Microsoft.Storage/storageAccounts/' + $StorageAccountName + '/listKeys?api-version=2023-05-01&$expand=kerb')).keys | Where-Object { $_.Keyname -contains 'kerb1' }).Value

# Update the password on the computer object with the new Kerberos key on the Storage Account
$NewPassword = ConvertTo-SecureString -String $Key -AsPlainText -Force
Set-ADAccountPassword -Credential $DomainCredential -Identity $($StorageAccountName + '$') -Reset -NewPassword $NewPassword | Out-Null
<#
================================================================================================================================================
DISCLAIMER

This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You
a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of
the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which
the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is
embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits,
including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
================================================================================================================================================

.DESCRIPTION

    This script will configure FSLogix with Azure Files on an Entra joined AVD session host.

    Reference: https://techcommunity.microsoft.com/t5/fslogix-blog/fslogix-profile-containers-for-azure-ad-cloud-only-identities/ba-p/3739352

.REQUIREMENTS
    - Must run under the SYSTEM context on the VM.  Preferred as a Run Command on the VM or Custom Script Extension.
    - Azure Storage Account created
    - ConnectionString for Az Blob Storage Account: $StorageAccountConnectionString
    - Administrative access to the system

.EXAMPLE
    .\Set-FSLogixForFilesWithEntraJoinedHosts.ps1 -FileShareUncPath $FileShareUncPath -LocalAdminUsername $LocalAdminUsername -StorageAccountKey $StorageAccountKey

.LAST UPDATED
    11.15.2024
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [String]$FileShareUncPath,

    [parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [String]$LocalAdminUsername,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullorEmpty()]
    [String]$StorageAccountKey
)

$ErrorActionPreference = "Stop"

try
{
    # Configure FSLogix using Registry settings
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'Enabled' -Value '1' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'FlipFlopProfileDirectoryName' -Value '1' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'IsDynamic' -Value '1' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'LockedRetryCount' -Value '3' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'LockedRetryInterval' -Value '15' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'ReAttachIntervalSeconds' -Value '15' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'ReAttachRetryCount' -Value '3' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'PreventLoginWithFailure' -Value '1' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'PreventLoginWithTempProfile' -Value '1' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'ProfileType' -Value '0' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'SizeInMBs' -Value '60000' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'VolumeType' -Value 'VHDX' -Type 'String' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'DeleteLocalProfileWhenVHDShouldApply' -Value '1' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'VHDLocations' -Value $FileShareUncPath -Type 'String' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'AccessNetworkAsComputerObject' -Value '1' -Type 'DWord' -Force
    Set-ItemProperty -Path 'HKLM:SOFTWARE\FSLogix\Profiles' -Name 'RemoveOrphanedOSTFilesOnLogoff' -Value '1' -Type 'DWord' -Force

    # Set the storage account credential
    $StorageAccountFqdn = $FileShareUncPath.Split('\')[2]
    $StorageAccountName = $FileShareUncPath.Split('\')[2].Split('.')[0]
    $Username = 'localhost\' + $StorageAccountName
    Start-Process -FilePath 'cmdkey.exe' -ArgumentList "/add:$StorageAccountFqdn /user:$($Username) /pass:$($StorageAccountKey)" -NoNewWindow

    # Enables loading credentials keys from the FSLogix profile when using Entra ID joined multi-session hosts
    # https://learn.microsoft.com/en-us/azure/virtual-desktop/create-profile-container-azure-ad#configure-the-session-hosts
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\AzureADAccount' -Force
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\AzureADAccount' -Name 'LoadCredKeyFromProfile' -Value '1' -Force
    
    # Exclude the local administrator from FSLogix
    $LocalGroups = "FSLogix ODFC Exclude List", "FSLogix Profile Exclude List"
    foreach ($Group in $LocalGroups)
    {
        if (-not (Get-LocalGroupMember -Group $Group).Name -contains $LocalAdminUsername)
        {
            Add-LocalGroupMember -Group $Group -Member $LocalAdminUsername | Out-Null
        }
    }
}
catch 
{
    Write-Error $_
}
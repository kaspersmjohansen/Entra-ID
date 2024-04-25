<#PSScriptInfo
.SYNOPSIS
    Script to cleanup stale Entra ID device object
 
.DESCRIPTION
    This script with get and/or list all stale Entra ID objects using the Microsoft Graph API. 
    Based on the parameters provided, you get get a table view of the stale devices and
    you are are also able to both disable and delete stale devices.

.PARAMETER DeviceAge
Device object age. 1 is the lowest supported age value of a device object and 5475 (15 years) is the max supported age value.
If not configured, the default value is 180 days, counting from the day the script is executed.

.PARAMETER DeviceJoinType
Device trust type. Supported values are - Workplace = Entra registered, AzureAD = Entra joined, ServerAD = hybrid joined
If not configured, the default value is AzureAD

.PARAMETER TenantID
Tenant ID you want to connect to.

.PARAMETER ListDevice
List stale devices in a table format

.PARAMETER DisableDevice
Disables stale devices

.PARAMETER RemoveDevice
Removes stale device from Entra - Run this at your own risk!
        
.EXAMPLE
    .\Cleanup-StaleDevices.ps1 -DeviceAge 90 -DeviceJoinType Workplace -TenantID yourdomain.onmicrosoft.com
        Shows all stale Entra registrered devices that hasn't registered with Entra within 90 days

    .\Cleanup-StaleDevices.ps1 -DeviceAge 180 -DeviceJoinType Workplace -TenantID yourdomain.onmicrosoft.com -ListDevices
        Shows all stale Entra registrered devices that hasn't registered with Entra within 180 days and lists the device in a table
    
    .\Cleanup-StaleDevices.ps1 -DeviceAge 60 -DeviceJoinType EntraAD -TenantID yourdomain.onmicrosoft.com -DisableDevices
        Disables all stale Entra joined devices that hasn't registered with Entra within 60 days.
    
    .\Cleanup-StaleDevices.ps1 -DeviceAge 60 -DeviceJoinType ServerAD -TenantID yourdomain.onmicrosoft.com -RemoveDevices
        Removes all stale Entra hybrid joined devices that hasn't registered with Entra within 60 days.

.NOTES
    To-do list/future features:
        Remove "whatif" in Disable devices and Remove devices regions
        Error handling
        Extend OS Support to Android, iOS and MacOS
        CSV file export feature

.VERSION
    0.9

.AUTHOR
    Kasper Johansen 
    kmj@apento.com

.COMPANYNAME 
    Apento

.COPYRIGHT
    Feel free to use this

.RELEASENOTES
    25-04-2024 - 0.9 - Latest BETA version

.CHANGELOG
    0.9 - Latest BETA version
#>

param(
    [Parameter(Mandatory = $false)][ValidateRange(1,5475)]
    [Int32]$DeviceAge = "180",
    [Parameter(Mandatory = $false)][ValidateSet("AzureAD","ServerAD","Workplace")]
    [string]$DeviceJoinType = "AzureAD",   
    [Parameter(Mandatory = $true)]
    [string]$TenantID,
    [switch]$ListDevice,
    [switch]$DisableDevice,
    [switch]$RemoveDevice
 )

function Get-StaleDevices
{
    param(
            $Age,
            $JoinType
    )
    Get-MgDevice -All | Where-Object {$_.ApproximateLastSignInDateTime -le $((Get-Date).AddDays(-$Age)) -and $_.OperatingSystem -eq "Windows" -and $_.TrustType -eq $JoinType}   
}

#Region Install and import Powershell module
Write-Host "Downloading and installing Powershell modules" -ForegroundColor Cyan
Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser | Out-Null
Import-Module -Name Microsoft.Graph.Identity.DirectoryManagement
#Endregion Install and import Powershell module

# Connect to Microsoft Graph API
Write-Host "Connecting to the Microsoft Graph API" -ForegroundColor Cyan
$RequiredScopes = "Device.ReadWrite.All"
Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantID -NoWelcome

#Region Get devices
# Get all devices
Write-Host "Enumerating stale devices" -ForegroundColor Cyan
Write-Host ""
$StaleDevices = Get-StaleDevices -Age $DeviceAge -JoinType $DeviceJoinType

If ($ListDevice)
{
    $StaleDevices | select-object DisplayName,OperatingSystem,OperatingSystemVersion,TrustType,ApproximateLastSignInDateTime,RegistrationDateTime | Format-Table
}
Write-Host "There are $($StaleDevices.Count) stale $DeviceJoinType devices in the $((Get-MgOrganization).DisplayName) Entra tenant which are older than $DeviceAge days" -ForegroundColor Yellow
#Endregion Get devices

#Region Disable devices
If ($DisableDevice)
{
    $params = @{
        accountEnabled = $false
    }
        ForEach ($Device in $StaleDevices)
        {
            Write-Host "Disable device - $($Device.Displayname)"
            Update-MgDevice -DeviceId $($Device.Id) -BodyParameter $params -WhatIf
        }
                $DisabledDevices = Get-MgDevice -All | Where-Object {$_.OperatingSystem -eq "Windows" -and $_.TrustType -eq $DeviceJoinType -and $_.AccountEnabled -eq "false"}
                $DisabledDevices | select-object DisplayName,OperatingSystem,OperatingSystemVersion,TrustType,ApproximateLastSignInDateTime,RegistrationDateTime | Format-Table
                Write-Host "There are $($DisabledDevices.Count) disabled $DeviceJoinType devices in the $((Get-MgOrganization).DisplayName) Entra tenant" -ForegroundColor Yellow
}
#Endregion Disable devices

#Region Remove devices
If ($DeleteDevice)
{
    ForEach ($Device in $StaleDevices)
    {
        Remove-MgDevice -DeviceId $Device.Id -WhatIf
    }
}
#Endregion Remove devices
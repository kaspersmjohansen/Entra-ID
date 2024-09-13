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

.PARAMETER OperatingSystem
    Specifies the Operating System of the device. Supported Operating Systems are, Android, iPad, iPhone, iOS, Windows and Unknown.
    If not configured, the default values is Windows. Multiple operating system values are not supported.

.PARAMETER TenantID
    Tenant ID you want to connect to.

.PARAMETER ExportToCSV
    Exports a list of devices to a CSV file. The CSV file is exported to the same folder as this script.

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

    .\Cleanup-StaleDevices.ps1 -DeviceAge 180 -DeviceJoinType Workplace -TenantID yourdomain.onmicrosoft.com -ExporttoCSV

    .\Cleanup-StaleDevices.ps1 -DeviceAge 180 -DeviceJoinType Workplace -OperatingSystem Android -TenantID yourdomain.onmicrosoft.com

.NOTES
    To-do list/future features:
        Remove "whatif" in Disable devices and Remove devices regions
        Error handling
        
.VERSION
    0.9.5

.AUTHOR
    Kasper Johansen 
    kmj@apento.com

.COMPANYNAME 
    Apento

.COPYRIGHT
    Feel free to use this as much as you want :)

.RELEASENOTES
    25-04-2024 - 0.9 - Script is in BETA, still testing stuff
    26-04-2024 - 0.9.2 - Parts of the script has been rewritten, see change log for additional information
    27-04-2024 - 0.9.3 - It's now possible to export a list of stale devices to a CSV file
    27-04-2024 - 0.9.4 - Code cleanup
    28-04-2024 - 0.9.5 - Added support for additional operating systems

.CHANGELOG
    0.9.0 - Latest BETA version
    0.9.2 - Get-StaleDevices function rewritten to use filtering instead of where-object, this change has made the script almost 50% faster
    0.9.3 - Added CSV export feature
    0.9.4 - Code cleanup. Removed unused parts of the code
    0.9.5 - The OperatingSystem property now supports Android, iPad, iPhone, iOS and Unknown operating systems 
#>

param(
    [Parameter(Mandatory = $false)][ValidateRange(1,5475)]
    [Int32]$DeviceAge = "180",
    [Parameter(Mandatory = $false)][ValidateSet("AzureAD","ServerAD","Workplace")]
    [string]$DeviceJoinType = "AzureAD",
    [Parameter(Mandatory = $false)][ValidateSet("Android","iOS","Ipad","Iphone","Windows","Unknown")]
    [string]$OperatingSystem = "Windows",   
    [Parameter(Mandatory = $true)]
    [string]$TenantID,
    [switch]$ExportToCSV,
    [switch]$ListDevice,
    [switch]$DisableDevice,
    [switch]$RemoveDevice
 )

function Get-StaleDevices
{
    param(
            [string]$Age,
            [string]$JoinType,
            [string]$OS,
            [switch]$DisabledDevices
    )
    If ($DisabledDevices)
    {
        Get-MgDevice -All -Filter "OperatingSystem eq '$OS' AND TrustType eq '$JoinType' AND AccountEnabled eq false"    
    }
    else{
        Get-MgDevice -All -Filter "ApproximateLastSignInDateTime le $((Get-Date).AddDays(-$Age).ToString("s"))Z AND OperatingSystem eq '$OS' AND TrustType eq '$JoinType'"
    }
}

#Region Install and import Powershell module
# Download and install require Powershell modules
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
# Get stale devices
Write-Host "Enumerating stale $OperatingSystem devices" -ForegroundColor Cyan
$StaleDevices = Get-StaleDevices -Age $DeviceAge -JoinType $DeviceJoinType -OS $OperatingSystem

# Create a table view of the stale devices
If ($ListDevice)
{
    Write-Host "Creating a table view list of stale $DeviceJoin $OperatingSystem devices" -ForegroundColor Cyan
    $StaleDevices | select-object DisplayName,OperatingSystem,OperatingSystemVersion,TrustType,ApproximateLastSignInDateTime,RegistrationDateTime | Format-Table
}

# Export the list of stale device to af CSV file
If ($ExportToCSV)
{
    Write-Host "Exporting list of stale $DeviceJoinType $OperatingSystem devices to a CSV file" -ForegroundColor Cyan
    $CSVfile = $("Stale" + "-" + $DeviceJoinType + "-" + $OperatingSystem + "-" + "devices" + "-" + $(Get-Date -Format HHmmssyyyy)) + ".csv"
    $StaleDevices | select-object DisplayName,OperatingSystem,OperatingSystemVersion,TrustType,ApproximateLastSignInDateTime,RegistrationDateTime | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
}
# Output the amount of stale devices
Write-Host "There are $($StaleDevices.Count) stale $DeviceJoinType $OperatingSystem devices in the $((Get-MgOrganization).DisplayName) Entra tenant which are older than $DeviceAge days" -ForegroundColor Yellow
#Endregion Get devices

#Region Disable devices
If ($DisableDevice)
{
    $params = @{
        accountEnabled = $false
    }
        ForEach ($Device in $StaleDevices)
        {
            Write-Host "Disable stale $OperatingSytem device - $($Device.Displayname)"
            Update-MgDevice -DeviceId $($Device.Id) -BodyParameter $params -WhatIf
        }
                $DisabledDevices = Get-StaleDevices -JoinType $DeviceJoinType -DisabledDevices
                Write-Host "There are $($DisabledDevices.Count) disabled $DeviceJoinType $OperatingSystem devices in the $((Get-MgOrganization).DisplayName) Entra tenant" -ForegroundColor Yellow
}
#Endregion Disable devices

#Region Remove devices
If ($DeleteDevice)
{
    ForEach ($Device in $StaleDevices)
    {
        Write-Host "Removing stale $OperatingSytem device - $($Device.Displayname)"
        Remove-MgDevice -DeviceId $Device.Id -WhatIf
    }
}
#Endregion Remove devices
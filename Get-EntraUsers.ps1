param(
    [Parameter(Mandatory = $true)][ValidateSet("Cloud","OnPremSynced","Guest","All")]
    [string]$UserType,
    [Parameter(Mandatory = $true)]
    [string]$TenantID,
    [switch]$ExportToCSV,
    [switch]$DisabledUsers
     )

#Region Install and import Powershell module
# Download and install require Powershell modules
Write-Host "Downloading and installing Powershell modules" -ForegroundColor Cyan
Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser | Out-Null
Import-Module -Name Microsoft.Graph.Users
#Endregion Install and import Powershell module



function Get-Users
{
    param(
        [switch]$Type,
        [switch]$DisabledUsers
    )
    If ($DisabledUsers)
    {
        Get-MgUser -All -Filter "accountEnabled eq false"   
    }
    else{
        Get-MgDevice -All -Filter "ApproximateLastSignInDateTime le $((Get-Date).AddDays(-$Age).ToString("s"))Z AND OperatingSystem eq '$OS' AND TrustType eq '$JoinType'"
    }
}

# Connect to Microsoft Graph API
Write-Host "Connecting to the Microsoft Graph API" -ForegroundColor Cyan
$RequiredScopes = "User.ReadBasic.All","User.Read.All","AuditLog.Read.All"
$TenantID = "virtualwarlock.net"
Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantID -NoWelcome

If ($UserType -eq "Cloud")
{
    Get-MgUser -All -Filter "OnPremisesSyncEnabled ne true and UserType eq 'Member'" -ConsistencyLevel eventual -CountVariable CountVar
}
# All cloud users including guest users
Get-MgUser -All -Filter "OnPremisesSyncEnabled ne true" -ConsistencyLevel eventual -CountVariable CountVar

# All synced users
Get-MgUser -All -Filter "OnPremisesSyncEnabled eq true"

# All cloud users excluding guest users
Get-MgUser -All -Filter "OnPremisesSyncEnabled ne true and UserType eq 'Member'" -ConsistencyLevel eventual -CountVariable CountVar

# All guest users
Get-MgUser -All -Filter "UserType ne 'Member'" -ConsistencyLevel eventual -CountVariable CountVar

# Sign in activity
Get-MgUser -UserId "944d57a0-0d24-4d55-ac5b-e9b741be9031" -Property SignInActivity | Select-Object -ExpandProperty SignInActivity
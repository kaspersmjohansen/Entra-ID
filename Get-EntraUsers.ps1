param(
    [Parameter(Mandatory = $true)][ValidateSet("Cloud","OnPremSynced","Guest","All")]
    [string]$UserType,
    [Parameter(Mandatory = $true)]
    [string]$TenantID,
    [switch]$ExportToCSV,
    [switch]$ListUser,
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

<#
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
#>

# Connect to Microsoft Graph API
Write-Host "Connecting to the Microsoft Graph API" -ForegroundColor Cyan
$RequiredScopes = "User.ReadBasic.All","User.Read.All","AuditLog.Read.All"
$TenantID = "virtualwarlock.net"
Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantID -NoWelcome

If ($UserType -eq "Cloud" -and -not $DisabledUsers)
{
    $Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity -Filter "OnPremisesSyncEnabled ne true and UserType eq 'Member'" -ConsistencyLevel eventual -CountVariable CountVar
    $Users.Count

    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }
}

If ($UserType -eq "OnPremSynced" -and -not $DisabledUsers)
{
    $Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity -Filter "OnPremisesSyncEnabled eq true" -ConsistencyLevel eventual -CountVariable CountVar
    $Users.Count

    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }
}

If ($UserType -eq "Guest" -and -not $DisabledUsers)
{
    $Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity -Filter "UserType ne 'Member'" -ConsistencyLevel eventual -CountVariable CountVar
    $Users.Count

    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }
}

If ($UserType -eq "All" -and -not $DisabledUsers)
{
    $Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity
    $Users.Count

    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }
}

If ($DisabledUsers)
{
    $Users = Get-MgUser -All -Filter "accountEnabled ne true" -Property DisplayName,UserPrincipalName,SignInActivity -ConsistencyLevel eventual -CountVariable CountVar
    $Users.Count

    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }     
}
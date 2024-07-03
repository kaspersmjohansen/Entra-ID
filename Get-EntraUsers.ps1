param(
    [Parameter(Mandatory = $true)][ValidateSet("Cloud","OnPremSynced","Guest","All")]
    [string]$UserType,
    [Parameter(Mandatory = $true)]
    [string]$TenantID,
    [Parameter(Mandatory = $false)][ValidateRange(1,5475)]
    [Int32]$UserAge = "180",
    [switch]$ExportToCSV,
    [switch]$ListUser,
    [switch]$StaleUser,
    [switch]$DisabledUsers
     )

function Get-User
{
    Param(
        [Parameter(Mandatory = $false)]        
        $Filter
    )
        If ($Filter)
        {
            Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation -Filter $Filter -ConsistencyLevel eventual -CountVariable CountVar
        }
            else 
            {
                Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation
            }
}

#Region Install and import Powershell module
# Download and install require Powershell modules
Write-Host "Downloading and installing Powershell modules" -ForegroundColor Cyan
Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser | Out-Null
Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser | Out-Null
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement 
Import-Module -Name Microsoft.Graph.Users
#Endregion Install and import Powershell module

# Connect to Microsoft Graph API
Write-Host "Connecting to the Microsoft Graph API" -ForegroundColor Cyan
$RequiredScopes = "User.ReadBasic.All","User.Read.All","AuditLog.Read.All"
$TenantID = "virtualwarlock.net"
Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantID -NoWelcome

# Get all enabled cloud users
If ($UserType -eq "Cloud" -and -not $DisabledUsers -and -not $UserAge)
{
    $Users = Get-User -Filter "OnPremisesSyncEnabled ne true and UserType eq 'Member'"
    # Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation -Filter "OnPremisesSyncEnabled ne true and UserType eq 'Member'" -ConsistencyLevel eventual -CountVariable CountVar
    
    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }
    
    Write-Host "There are $($Users.Count) $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow

}

# Get all enabled on-prem synced users 
If ($UserType -eq "OnPremSynced" -and -not $DisabledUsers -and -not $UserAge)
{
    $Users = Get-User -Filter "OnPremisesSyncEnabled eq true"
    #$Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation -Filter "OnPremisesSyncEnabled eq true" -ConsistencyLevel eventual -CountVariable CountVar
    
    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }

    Write-Host "There are $($Users.Count) $UserType users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
}

# Get all enabled guest users
If ($UserType -eq "Guest" -and -not $DisabledUsers -and -not $UserAge)
{
    $Users = Get-User -Filter "UserType ne 'Member'"
    #$Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation -Filter "UserType ne 'Member'" -ConsistencyLevel eventual -CountVariable CountVar
    
    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }

    Write-Host "There are $($Users.Count) $UserType users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
}

If ($UserType -eq "All" -and -not $DisabledUsers -and -not $UserAge)
{
    $Users = Get-User
    # $Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation
    
    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }

    Write-Host "There are $($Users.Count) users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
}

If ($DisabledUsers)
{
    $Users = Get-User -Filter "accountEnabled ne true"
    #$Users = Get-MgUser -All -Filter "accountEnabled ne true" -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation -ConsistencyLevel eventual -CountVariable CountVar
    
    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }
    
    Write-Host "There are $($Users.Count) disabled users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
}

If ($UserAge)
{
    $Users = Get-User | Where-Object {($_.SignInActivity.LastSignInDateTime -le $((Get-Date).AddDays(-$UserAge)))}
   
    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Format-Table
        # $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + $UserAge+"days"+"-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}} | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
    }
    
    Write-Host "There are $($Users.Count) users that have never signed in or have not signed in, within the last $UserAge days in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
    
}

#$Inactiveusers= get-MgUser -Property DisplayName, UserPrincipalName, SignInActivity, UserType
#$Inactiveusers | Where-Object {($_.SignInActivity.LastSignInDateTime -le $((Get-Date).AddDays(-30))) -and ($_.UserType -eq "Member")}
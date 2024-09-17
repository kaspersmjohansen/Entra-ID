param(
    [Parameter(Mandatory = $true)][ValidateSet("Entra","Hybrid","Guest","All")]
    [string]$UserType,
    [Parameter(Mandatory = $true)]
    [string]$TenantID,
    [Parameter(Mandatory = $false)][ValidateRange(1,5475)]
    [Int32]$UserAge,
    #[Parameter(Mandatory = $false)][ValidateSet("True","False","Only")]
    #[string]$DisabledUsers = "false",
    [switch]$ExportToCSV,
    [switch]$ListUser,
    #[switch]$StaleUser,
    [switch]$DisabledUsers
     )

function Get-User
{
    Param(
        [Parameter(Mandatory = $false)]        
        $Filter,
        [switch]$Disabled = $false,
        [switch]$List = $false
    )
        If ($Filter)
        {
            If ($Disabled)
            {
                If ($List)
                {
                    $Usr = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation,UserType -Filter $($Filter+" "+"and"+" "+"accountEnabled eq false") -ConsistencyLevel eventual -CountVariable CountVar
                    $Usr | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table
                }
                    else
                    {
                        Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation,UserType -Filter $($Filter+" "+"and"+" "+"accountEnabled eq false") -ConsistencyLevel eventual -CountVariable CountVar
                    }
            }
                else 
                {
                    If ($List)
                    {
                        $Usr = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation,UserType -Filter $Filter -ConsistencyLevel eventual -CountVariable CountVar
                        $Usr | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table    
                    }
                    else
                    {
                        Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation,UserType -Filter $Filter -ConsistencyLevel eventual -CountVariable CountVar
                    }
                }
        }
            else 
            {
                Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation,UserType
            }
}

<#
function Get-UserList
{
    $Users = Get-User -Filter "UserType eq '$User'"
    $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table
}
#>

<#
function Get-UserCSV
{
    Write-Host "Exporting list of users to $PSScriptRoot\$CSVfile" -ForegroundColor Cyan
    $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmss-MMddyyyy)) + ".csv"
    Get-UserList | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
}
#>

#Region Install and import Powershell module
# Install NuGet pacakage provider
If (!(Get-PackageProvider | Where-Object {$_.Name -eq "NuGet"}))
{
    Write-Host "Downloading and installing Powershell modules" -ForegroundColor Cyan
    try
    {
        Write-Host "Installing NuGet package provider" -ForegroundColor Cyan 
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
    }
    catch
    {
        Write-Host "Something happened with the package provider installation: $($_.Exception.Message)"
        Break
    }
}

# Configure PSGallery as a trusted source
If ($((Get-PSRepository -Name PSGallery).InstallationPolicy) -eq "Untrusted")
{
    Write-Host "Configuring PSGallery as a trusted installation source" -ForegroundColor Cyan 
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

# Modules to be installed and imported
$Modules = "Microsoft.Graph.Authentication","Microsoft.Graph.Identity.DirectoryManagement","Microsoft.Graph.Users"

# Install Powershell modules
ForEach ($Module in $Modules) 
{
    If ((!(Get-Module -Name $Module)))
    {
        try
        {
            Write-Host "Installing the $Module Powershell module" -ForegroundColor Cyan
            Install-Module -Name $Module -Scope CurrentUser -Force | Out-Null    
        }
        catch
        {
            Write-Host "Something happened with the $Module Powershell module installation: $($_.Exception.Message)"
            Break
        }            
    }    
}
# Importing Powershell modules
ForEach ($Module in $Modules)
{
    If ((!(Get-Module -Name $Module)))
    {
        try
        {
            Write-Host "Importing the $Module Powershell module" -ForegroundColor Cyan
            Import-Module -Name $Module   
        }
        catch
        {
            Write-Host "Something happened with the $Module Powershell module import: $($_.Exception.Message)"
            Break
        }
    } 
}

#Endregion Install and import Powershell module

# Connect to Microsoft Graph API
Write-Host "Connecting to the Microsoft Graph API" -ForegroundColor Cyan
$RequiredScopes = "User.ReadBasic.All","User.Read.All","AuditLog.Read.All"
Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantID -NoWelcome

# Set user type
$User = Switch ($UserType) 
{  
    "Entra" {"Member"}
    "Hybrid" {"OnPremisesSyncEnabled"}
    #"Guest" {"Guest"}
    #"All" {"All"}
}

# Get all enabled cloud users
If ($UserType -eq "Entra") #-and -not $DisabledUsers -and -not $UserAge)
{
    If ($DisabledUsers -and (!($ListUser)))
    {
        $Users = Get-User -Filter "UserType eq '$User'" -Disabled:$true -List:$false
        If ($Users.Count -gt "1")
        {
            Write-Host "There are $($Users.Count) disabled $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
        }
            else
            {
                Write-Host "There is $($Users.Count) disabled $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
            }
    }
        elseif ($DisabledUsers -and $ListUser)
        {
            Write-host "Listing disabled users"
            Get-User -Filter "UserType eq '$User'" -Disabled:$true -List:$true
        }
            elseif ($ListUser -and (!($DisabledUsers)))
            {
                Write-Host "Listing non-disabled users"
                Get-User -Filter "UserType eq '$User'" -List:$true -Disabled:$false
            }
                else
                {
                    $Users = Get-User -Filter "UserType eq '$User'"
                    If ($Users.Count -gt "1")
                    {
                        Write-Host "There are $($Users.Count) $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
                    }
                        else
                        {
                            Write-Host "There is $($Users.Count) $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
                        }
                }
    
    # Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation -Filter "OnPremisesSyncEnabled ne true and UserType eq 'Member'" -ConsistencyLevel eventual -CountVariable CountVar
    
    
        <#
        $Users = Get-User -Filter "UserType eq '$User'" -Disabled
        If ($Users.Count -gt "1")
        {
            $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table
            Write-Host "There are $($Users.Count) disabled $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
        }
            else
            {
                $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table
                Write-Host "There is $($Users.Count) disabled $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
            }
        #$Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table
        #>
    #}
    
    If ($ListUser -and -not $DisabledUsers)
    {
        Get-User -Filter "UserType eq '$User'" -List
    }    <#
        $Users = Get-User -Filter "UserType eq '$User'"
        If ($Users.Count -gt "1")
        {
            $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table
            Write-Host "There are $($Users.Count) disabled $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
        }
            else
            {
                $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table
                Write-Host "There is $($Users.Count) disabled $UserType-only users in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
            }
        #>    
    #}

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of users $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        #$CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        #$Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
        Get-UserCSV
    }
}
<#
# Get all enabled on-prem synced users 
If ($UserType -eq "Hybrid" -and -not $DisabledUsers -and -not $UserAge)
{
    $Users = Get-User -Filter "OnPremisesSyncEnabled eq true"
    #$Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,SignInActivity,accountEnabled,UsageLocation -Filter "OnPremisesSyncEnabled eq true" -ConsistencyLevel eventual -CountVariable CountVar
    
    If ($ListUser)
    {
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Format-Table
    }

    If ($ExporttoCSV)
    {
        #Write-Host "Exporting list of stale $DeviceJoinType $OperatingSytem devices to a CSV file" -ForegroundColor Cyan
        $CSVfile = $($UserType + "-" + "Users" + "-" +$(Get-Date -Format HHmmssyyyy)) + ".csv"
        $Users | Select-Object Displayname,UserPrincipalName,@{Name='LastNonInteractiveSignInDateTime';Expression={$_.SignInActivity.LastNonInteractiveSignInDateTime}},@{Name='LastSignInDateTime';Expression={$_.SignInActivity.LastSignInDateTime}},@{Name='AccountEnabled';Expression={$_.AccountEnabled}},@{Name='UsageLocation';Expression={$_.UsageLocation}},UserType | Export-Csv -Path $PSScriptRoot\$CSVfile -NoClobber -NoTypeInformation -Delimiter ";" -Encoding utf8 -Append
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

<#
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
    #>

If ($UserAge)
{
    $UserAge
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
    
    Write-Host "There are $($Users.Count) users that have never signed in or have not signed in within the last $UserAge days in the $((Get-MgOrganization).DisplayName) Entra ID tenant" -ForegroundColor Yellow
    
}

#$Inactiveusers= get-MgUser -Property DisplayName, UserPrincipalName, SignInActivity, UserType
#$Inactiveusers | Where-Object {($_.SignInActivity.LastSignInDateTime -le $((Get-Date).AddDays(-30))) -and ($_.UserType -eq "Member")}
#>
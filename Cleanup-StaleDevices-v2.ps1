param(
    [Parameter(Mandatory = $false)][ValidateRange(1,5475)]
    [Int32]$DeviceAge = "90",
    [Parameter(Mandatory = $false)][ValidateSet("AzureAD","ServerAD","Workplace")]
    [string]$DeviceJoinType = "AzureAD",
    [Parameter(Mandatory = $false)][ValidateSet("Android","iOS","Ipad","Iphone","Windows","MacMDM","Unknown")]
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
            [Parameter(Mandatory = $false)]
            [string]$Age,
            [Parameter(Mandatory = $true)]
            [string]$JoinType,
            [Parameter(Mandatory = $true)]
            [string]$OS,            
            [switch]$DisabledDevices
    )
    $apiVersion = "beta"
    $baseUri = "https://graph.microsoft.com/$apiVersion"
        
        If ($DisabledDevices)
        {
            $StaleDevices = Invoke-MgGraphRequest -Method Get -Uri "$baseUri/devices?`$filter=operatingSystem eq '$OS' AND TrustType eq '$JoinType' AND accountEnabled eq false"
            If ($StaleDevices.count -gt "0")
            {
                $ListView = [System.Collections.Generic.List[Object]]::new()
                Foreach ($Device in $StaleDevices.value) {    
                    $ListLine  = [PSCustomObject] @{
                    DeviceId                = $Device.DeviceId
                    DisplayName             = $Device.DisplayName
                    OperatingSystem         = $Device.OperatingSystem
                    OperatingSystemVersion  = $Device.OperatingSystemVersion
                    TrustType               = $Device.TrustType
                    LastSignInDateTime      = $Device.ApproximateLastSignInDateTime
                    RegistrationDateTime    = $Device.RegistrationDateTime
                    AccountEnabled          = $Device.AccountEnabled        
                    }  
                        $ListView.Add($ListLine)   
                }
                    $ListView | Sort-Object LastSignInDateTime | Format-Table
            }
            else
            {
                Write-Host "No disabled $OS devices with the $JoinType TrustType" -ForegroundColor
            }
        }
            else
            {            
                [string]$DevAge = "$((Get-Date).AddDays(-$Age).ToString("yyyy-MM-ddTHH:mm:ssZ"))"
                $StaleDevices = Invoke-MgGraphRequest -Method Get -Uri "$baseUri/devices?`$filter=approximateLastSignInDateTime le $DevAge AND operatingSystem eq '$OS' AND TrustType eq '$JoinType'&`$count=true"                
                $ListView = [System.Collections.Generic.List[Object]]::new()
                Foreach ($Device in $StaleDevices.value) {    
                    $ListLine  = [PSCustomObject] @{
                    DeviceId                = $Device.DeviceId
                    DisplayName             = $Device.DisplayName
                    OperatingSystem         = $Device.OperatingSystem
                    OperatingSystemVersion  = $Device.OperatingSystemVersion
                    TrustType               = $Device.TrustType
                    LastSignInDateTime      = $Device.ApproximateLastSignInDateTime
                    RegistrationDateTime    = $Device.RegistrationDateTime
                    AccountEnabled          = $Device.AccountEnabled         
                    }  
                        $ListView.Add($ListLine)   
                }
                    $ListView | Sort-Object LastSignInDateTime | Format-Table
            }
}

$Report = [System.Collections.Generic.List[Object]]::new() 
Foreach ($Device in $StaleDevices.value) {    
    $ReportLine  = [PSCustomObject] @{
        DeviceId                = $Device.DeviceId
        DisplayName             = $Device.DisplayName
        OperatingSystem         = $Device.OperatingSystem
        OperatingSystemVersion  = $Device.OperatingSystemVersion
        TrustType               = $Device.TrustType
        LastSignInDateTime      = $Device.ApproximateLastSignInDateTime
        RegistrationDateTime    = $Device.RegistrationDateTime
         
    }  
    $Report.Add($ReportLine)   
} # End ForEach

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan

try
{
    $RequiredScopes = "Device.ReadWrite.All"
    Connect-MgGraph -Scopes $RequiredScopes -TenantID $TenantID  
    Write-Host "Connected successfully." -ForegroundColor Green
}
catch
{
    Write-Error "Connection failed: $_"
    exit
}
cls

If ($DisabledDevices)
{
    Write-Host "Disbaled $OperatingSystem devices" -ForegroundColor Cyan
    Get-StaleDevices -JoinType $DeviceJoinType -OS $OperatingSystem -DisabledDevices
}
else
{
    Write-Host "Stale $OperatingSystem devices" -ForegroundColor Cyan
    Get-StaleDevices -Age $DeviceAge -JoinType $DeviceJoinType -OS $OperatingSystem
}
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement

param(
    [Parameter(Mandatory = $false)][ValidateRange(1, 5475)]
    [Int32]$DeviceAge = 90,
    [Parameter(Mandatory = $false)][ValidateSet("AzureAD", "ServerAD", "Workplace")]
    [string]$DeviceJoinType = "AzureAD",
    [Parameter(Mandatory = $false)][ValidateSet("Android", "iOS", "Ipad", "Iphone", "Windows", "MacMDM", "Unknown")]
    [string]$OperatingSystem = "Windows",
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    [switch]$ExportToCSV,
    [switch]$ListDevice,
    [switch]$DisableDevice,
    [switch]$RemoveDevice,
    [switch]$DisabledDevices
)

function Get-GraphPagedResults {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $Results = [System.Collections.Generic.List[Object]]::new()
    do {
        $Response = Invoke-MgGraphRequest -Method Get -Uri $Uri -Headers @{ ConsistencyLevel = "eventual" }
        if ($Response.value) {
            $Results.AddRange([Object[]]$Response.value)
        }
        $Uri = $Response.'@odata.nextLink'
    } while ($Uri)
    return $Results
}

function Get-StaleDevices {
    param(
        [Parameter(Mandatory = $false)]
        [Int32]$Age,
        [Parameter(Mandatory = $true)]
        [string]$JoinType,
        [Parameter(Mandatory = $true)]
        [string]$OS,
        [switch]$DisabledDevices
    )

    $BaseUri = "https://graph.microsoft.com/v1.0"

    if ($DisabledDevices) {
        $Uri = "$BaseUri/devices?`$filter=operatingSystem eq '$OS' AND trustType eq '$JoinType' AND accountEnabled eq false&`$count=true&`$select=deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,registrationDateTime,accountEnabled"
        $RawDevices = Get-GraphPagedResults -Uri $Uri

        if ($RawDevices.Count -eq 0) {
            Write-Host "No disabled $OS devices found with TrustType '$JoinType'." -ForegroundColor Yellow
            return $null
        }
    }
    else {
        $DevAge = (Get-Date).AddDays(-$Age).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $Uri = "$BaseUri/devices?`$filter=approximateLastSignInDateTime le $DevAge AND operatingSystem eq '$OS' AND trustType eq '$JoinType'&`$count=true&`$select=deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,registrationDateTime,accountEnabled"
        $RawDevices = Get-GraphPagedResults -Uri $Uri

        if ($RawDevices.Count -eq 0) {
            Write-Host "No stale $OS devices found older than $Age days with TrustType '$JoinType'." -ForegroundColor Yellow
            return $null
        }
    }

    $ListView = foreach ($Device in $RawDevices) {
        [PSCustomObject]@{
            DeviceId               = $Device.deviceId
            DisplayName            = $Device.displayName
            OperatingSystem        = $Device.operatingSystem
            OperatingSystemVersion = $Device.operatingSystemVersion
            TrustType              = $Device.trustType
            LastSignInDateTime     = $Device.approximateLastSignInDateTime
            RegistrationDateTime   = $Device.registrationDateTime
            AccountEnabled         = $Device.accountEnabled
        }
    }

    return $ListView | Sort-Object LastSignInDateTime
}

# Connect to Microsoft Graph - reuse existing session if tenant matches
$ctx = Get-MgContext
if (-not $ctx -or $ctx.TenantId -ne $TenantId) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    try {
        Connect-MgGraph -Scopes "Device.ReadWrite.All" -TenantId $TenantId -NoWelcome -ErrorAction Stop
        Write-Host "Connected successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Connection failed: $($_.Exception.Message)"
        exit 1
    }
}
else {
    Write-Host "Reusing existing Graph session for tenant $($ctx.TenantId)." -ForegroundColor Green
}

Clear-Host

# Retrieve devices
if ($DisabledDevices) {
    Write-Host "Disabled $OperatingSystem devices (TrustType: $DeviceJoinType)" -ForegroundColor Cyan
    $Devices = Get-StaleDevices -JoinType $DeviceJoinType -OS $OperatingSystem -DisabledDevices
}
else {
    Write-Host "Stale $OperatingSystem devices older than $DeviceAge days (TrustType: $DeviceJoinType)" -ForegroundColor Cyan
    $Devices = Get-StaleDevices -Age $DeviceAge -JoinType $DeviceJoinType -OS $OperatingSystem
}

if (-not $Devices) { exit 0 }

# List
if ($ListDevice) {
    $Devices | Format-Table -AutoSize
}

# Export
if ($ExportToCSV) {
    $ExportPath = ".\StaleDevices_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Devices | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $($Devices.Count) devices to $ExportPath" -ForegroundColor Green
}

# Disable
if ($DisableDevice) {
    Write-Host "Disabling $($Devices.Count) devices..." -ForegroundColor Yellow
    foreach ($Device in $Devices) {
        try {
            Invoke-MgGraphRequest -Method Patch `
                -Uri "https://graph.microsoft.com/v1.0/devices/$($Device.DeviceId)" `
                -Body (@{ accountEnabled = $false } | ConvertTo-Json) `
                -ContentType "application/json" -ErrorAction Stop
            Write-Host "Disabled: $($Device.DisplayName)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to disable $($Device.DisplayName): $($_.Exception.Message)"
        }
    }
}

# Remove
if ($RemoveDevice) {
    Write-Host "Removing $($Devices.Count) devices..." -ForegroundColor Yellow
    foreach ($Device in $Devices) {
        try {
            Invoke-MgGraphRequest -Method Delete `
                -Uri "https://graph.microsoft.com/v1.0/devices/$($Device.DeviceId)" `
                -ErrorAction Stop
            Write-Host "Removed: $($Device.DisplayName)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to remove $($Device.DisplayName): $($_.Exception.Message)"
        }
    }
}

# Default output if no action switch was specified
if (-not ($ListDevice -or $ExportToCSV -or $DisableDevice -or $RemoveDevice)) {
    $Devices | Format-Table -AutoSize
}
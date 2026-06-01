#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
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

# Mutual exclusion guard
if ($DisableDevice -and $RemoveDevice) {
    Write-Error "Cannot use -DisableDevice and -RemoveDevice together. Choose one."
    exit 1
}

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

function Invoke-MgGraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [hashtable]$Body,
        [int]$MaxRetries = 3
    )
    $Attempt = 0
    do {
        try {
            $Params = @{
                Method      = $Method
                Uri         = $Uri
                ErrorAction = "Stop"
            }
            if ($Body) {
                $Params.Body        = ($Body | ConvertTo-Json)
                $Params.ContentType = "application/json"
            }
            Invoke-MgGraphRequest @Params
            return
        }
        catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429 -and $Attempt -lt $MaxRetries) {
                $RetryAfter = $_.Exception.Response.Headers['Retry-After']
                $Wait = if ($RetryAfter) { [int]$RetryAfter } else { 10 }
                Write-Warning "Graph throttled (429). Retrying in $Wait seconds... (attempt $($Attempt + 1) of $MaxRetries)"
                Start-Sleep -Seconds $Wait
            }
            else {
                throw
            }
        }
        $Attempt++
    } while ($Attempt -le $MaxRetries)
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
    # id = AAD object id (required for PATCH/DELETE); deviceId = hardware-bound Entra device id
    $Select = "id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,registrationDateTime,accountEnabled"

    if ($DisabledDevices) {
        $Uri = "$BaseUri/devices?`$filter=operatingSystem eq '$OS' AND trustType eq '$JoinType' AND accountEnabled eq false&`$count=true&`$select=$Select"
        $RawDevices = Get-GraphPagedResults -Uri $Uri

        if ($RawDevices.Count -eq 0) {
            Write-Host "No disabled $OS devices found with TrustType '$JoinType'." -ForegroundColor Yellow
            return $null
        }
    }
    else {
        $DevAge = (Get-Date).AddDays(-$Age).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $Uri = "$BaseUri/devices?`$filter=approximateLastSignInDateTime le $DevAge AND operatingSystem eq '$OS' AND trustType eq '$JoinType'&`$count=true&`$select=$Select"
        $RawDevices = Get-GraphPagedResults -Uri $Uri

        if ($RawDevices.Count -eq 0) {
            Write-Host "No stale $OS devices found older than $Age days with TrustType '$JoinType'." -ForegroundColor Yellow
            return $null
        }
    }

    $ListView = foreach ($Device in $RawDevices) {
        [PSCustomObject]@{
            ObjectId               = $Device.id
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

# Connect to Microsoft Graph - reuse existing session if tenant and scopes match
$ctx = Get-MgContext
$NeedsWrite = $DisableDevice -or $RemoveDevice
$RequiredScope = if ($NeedsWrite) { "Device.ReadWrite.All" } else { "Device.Read.All" }

$SessionValid = $ctx -and ($ctx.TenantId -eq $TenantId)
$ScopesMissing = $SessionValid -and $NeedsWrite -and ($ctx.Scopes -notcontains "Device.ReadWrite.All")

if ($ScopesMissing) {
    Write-Error "Current Graph session lacks Device.ReadWrite.All. Reconnect without an existing session, or omit -DisableDevice/-RemoveDevice."
    exit 1
}

if (-not $SessionValid) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    try {
        Connect-MgGraph -Scopes $RequiredScope -TenantId $TenantId -NoWelcome -ErrorAction Stop
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

Write-Host "Found $(@($Devices).Count) device(s)." -ForegroundColor Cyan

# List
if ($ListDevice) {
    $Devices | Format-Table -AutoSize
}

# Export
if ($ExportToCSV) {
    $ExportPath = ".\StaleDevices_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Devices | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $(@($Devices).Count) devices to $ExportPath" -ForegroundColor Green
}

# Disable
if ($DisableDevice) {
    Write-Host "Disabling $(@($Devices).Count) device(s)..." -ForegroundColor Yellow
    foreach ($Device in $Devices) {
        Write-Host "  Processing: $($Device.DisplayName) [$($Device.DeviceId)]"
        if ($PSCmdlet.ShouldProcess($Device.DisplayName, "Disable")) {
            try {
                Invoke-MgGraphRequestWithRetry -Method Patch `
                    -Uri "https://graph.microsoft.com/v1.0/devices/$($Device.ObjectId)" `
                    -Body @{ accountEnabled = $false }
                Write-Host "  Disabled: $($Device.DisplayName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to disable $($Device.DisplayName): $($_.Exception.Message)"
            }
        }
    }
}

# Remove
if ($RemoveDevice) {
    Write-Host "Removing $(@($Devices).Count) device(s)..." -ForegroundColor Yellow
    foreach ($Device in $Devices) {
        Write-Host "  Processing: $($Device.DisplayName) [$($Device.DeviceId)]"
        if ($PSCmdlet.ShouldProcess($Device.DisplayName, "Remove")) {
            try {
                Invoke-MgGraphRequestWithRetry -Method Delete `
                    -Uri "https://graph.microsoft.com/v1.0/devices/$($Device.ObjectId)"
                Write-Host "  Removed: $($Device.DisplayName)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to remove $($Device.DisplayName): $($_.Exception.Message)"
            }
        }
    }
}

# Default output if no action switch was specified
if (-not ($ListDevice -or $ExportToCSV -or $DisableDevice -or $RemoveDevice)) {
    $Devices | Format-Table -AutoSize
}
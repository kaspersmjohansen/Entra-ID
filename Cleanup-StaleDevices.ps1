#Requires -Version 5.1

<#
.SYNOPSIS
    Finds stale Entra ID devices and disables or deletes them (report, staged runs or local web UI).
.DESCRIPTION
    Stale = last sign-in older than -StaleDays (no sign-in: registered more than -NoSignInDays ago).
    Disable: stale and enabled. Delete: disabled and inactive for -StaleDays + -GraceDays.
    Report only (never changed): Hybrid joined (clean up in on-premises AD), unknown join type,
    Autopilot and Intune-managed devices (unless -IncludeAutopilot / -IncludeIntuneManaged).
    Delete is blocked for devices with BitLocker keys or LAPS passwords (or unknown) unless -AllowKeyLoss.
    Every rule is checked again against Graph right before a device is changed.
    Modes: Report (read-only), Disable, Delete, UI (local web UI on 127.0.0.1 with CSRF token).
.PARAMETER Mode
    Report (default), Disable, Delete or UI.
.PARAMETER StaleDays
    Days without sign-in before a device is stale. Default 90, minimum 30.
.PARAMETER GraceDays
    Extra days a disabled device is kept before it can be deleted. Default 30.
.PARAMETER NoSignInDays
    For devices without a last sign-in: days since registration. Default = StaleDays (minimum 30).
.PARAMETER ForceDelete
    Delete mode / UI: also deletes stale devices that are enabled or within the grace period. Logged as ForceDelete.
.PARAMETER AuthMode
    GraphCli (default): Microsoft Graph Command Line Tools (scopes need admin consent once).
    UserRights: sign in with a preconsented Microsoft app, effective access = your Entra roles (no admin consent).
.PARAMETER ClientId
    Application (client) id to sign in with. Implies -AuthMode UserRights. Default: Azure PowerShell app.
.PARAMETER ReadOnly
    Requests only Device.Read.All, blocks every write, refuses Disable/Delete, UI is view-only.
    BitLocker/LAPS status is read only if the session already has the key scopes, otherwise Unknown.
.PARAMETER JoinType
    EntraJoined, Registered, HybridJoined or All (default).
.PARAMETER OperatingSystem
    Windows, macOS, iOS, Android, Linux, Other or All (default).
.PARAMETER IncludeAutopilot
    Allows actions on Windows Autopilot devices (cannot be reprovisioned after delete).
.PARAMETER IncludeIntuneManaged
    Allows actions on Intune/MDM-managed devices (retire them in Intune first).
.PARAMETER AllowKeyLoss
    Allows deleting devices with BitLocker recovery keys or LAPS passwords (or where this is unknown).
.PARAMETER SkipKeyCheck
    Does not request the BitLocker/LAPS read scopes. Key status is Unknown, so delete needs -AllowKeyLoss.
.PARAMETER MaxDevices
    Maximum devices changed per run (Disable/Delete stop before any change if more). Default 50.
.PARAMETER IncludeActive
    Report: also lists devices that are not stale.
.PARAMETER OutputPath
    CSV report (UTF-8 with BOM, formula injection protected).
.PARAMETER HtmlPath
    HTML report.
.PARAMETER AuditPath
    Audit CSV for every action (appended). Default: StaleDevices-Audit-<UTC time>.csv in the current folder.
.PARAMETER Port
    UI port on 127.0.0.1 (1024-65535). Default 8734.
.PARAMETER NoBrowser
    UI: does not open the browser.
.PARAMETER TenantId
    Tenant ID (GUID) or verified domain name. Reconnects if the current session is another tenant.
.PARAMETER UseWAM
    Signs in with the Windows Web Account Manager (passkey / FIDO2 in Windows PowerShell 5.1).
.PARAMETER PassThru
    Also returns the report rows / action results when files are written.
.EXAMPLE
    .\Cleanup-StaleDevices.ps1 -TenantId contoso.onmicrosoft.com -HtmlPath .\stale.html -OutputPath .\stale.csv
.EXAMPLE
    .\Cleanup-StaleDevices.ps1 -AuthMode UserRights -TenantId contoso.onmicrosoft.com -Mode Disable -WhatIf
.EXAMPLE
    .\Cleanup-StaleDevices.ps1 -Mode Disable -JoinType EntraJoined -OperatingSystem Windows -WhatIf
.NOTES
    Kasper Johansen | Apento | kmj@apento.com
    Version: 5.0.0 (2026-11-24). Rewritten: eligibility rules, key-loss protection, hardened UI, audit, -ReadOnly, -AuthMode.
    Auth (no app registration): GraphCli = Microsoft Graph Command Line Tools (scopes need admin consent once).
    -AuthMode UserRights = Azure PowerShell app (preconsented everywhere): access = your Entra roles via
    Directory.AccessAsUser.All, no admin consent; it has no BitLocker/LAPS scopes, so key status is Unknown (delete needs -AllowKeyLoss).
    Scopes (GraphCli): Report/-ReadOnly Device.Read.All; Disable/Delete/UI Directory.AccessAsUser.All (no narrower one);
    key read BitlockerKey.ReadBasic.All + DeviceLocalCredential.ReadBasic.All; app-only Device.ReadWrite.All.
    Role: Cloud Device Administrator (delete: Intune / Windows 365 Administrator); key read also needs a reader role.
    Exit codes: 0 success, 1 error or failed action, 3 access denied, 4 sign-in/session error.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('Report', 'Disable', 'Delete', 'UI')]
    [string]$Mode = 'Report',

    [Parameter()]
    [ValidateRange(30, 3650)]
    [int]$StaleDays = 90,

    [Parameter()]
    [ValidateRange(0, 3650)]
    [int]$GraceDays = 30,

    [Parameter()]
    [ValidateRange(30, 3650)]
    [int]$NoSignInDays,

    [Parameter()]
    [switch]$ReadOnly,

    [Parameter()]
    [ValidateSet('GraphCli', 'UserRights')]
    [string]$AuthMode = 'GraphCli',

    [Parameter()]
    [string]$ClientId,

    [Parameter()]
    [switch]$ForceDelete,

    [Parameter()]
    [ValidateSet('EntraJoined', 'Registered', 'HybridJoined', 'All')]
    [string]$JoinType = 'All',

    [Parameter()]
    [ValidateSet('Windows', 'macOS', 'iOS', 'Android', 'Linux', 'Other', 'All')]
    [string]$OperatingSystem = 'All',

    [Parameter()]
    [switch]$IncludeAutopilot,

    [Parameter()]
    [switch]$IncludeIntuneManaged,

    [Parameter()]
    [switch]$AllowKeyLoss,

    [Parameter()]
    [switch]$SkipKeyCheck,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$MaxDevices = 50,

    [Parameter()]
    [switch]$IncludeActive,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$HtmlPath,

    [Parameter()]
    [string]$AuditPath,

    [Parameter()]
    [ValidateRange(1024, 65535)]
    [int]$Port = 8734,

    [Parameter()]
    [switch]$NoBrowser,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseWAM,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '5.0.0'
if (-not $PSBoundParameters.ContainsKey('InformationAction')) {
    $InformationPreference = 'Continue'
}
if (-not $PSBoundParameters.ContainsKey('NoSignInDays')) {
    $NoSignInDays = $StaleDays
}
$script:WamRestoreValue = $null
$ExitCodeSuccess = 0
$ExitCodeError = 1
$ExitCodePermission = 3
$ExitCodeSignIn = 4
$GraphBase = 'https://graph.microsoft.com/v1.0'
$DeviceSelect = 'id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,registrationDateTime,accountEnabled,isManaged,physicalIds'
$KeyHeaders = @{ 'ocp-client-name' = 'Cleanup-StaleDevices'; 'ocp-client-version' = $ScriptVersion }
$KeyScopes = @('BitlockerKey.ReadBasic.All', 'DeviceLocalCredential.ReadBasic.All')
$AzurePowerShellAppId = '1950a258-227b-4e31-a9cf-717495945fc2'
if ($ClientId -and $ClientId -notmatch $GuidPattern) {
    throw "-ClientId must be a GUID."
}
$script:UserRights = ($AuthMode -eq 'UserRights') -or [bool]$ClientId
$script:AuthClientId = if ($script:UserRights) { if ($ClientId) { $ClientId } else { $AzurePowerShellAppId } } else { '' }
if ($script:UserRights) {
    # First-party apps are preconsented for Directory.AccessAsUser.All only (not Device.Read.All or the key scopes),
    # so request just that scope; the GET-only guard keeps -ReadOnly / Report runs read-only.
    $RequiredScopes = @('Directory.AccessAsUser.All')
}
else {
    $RequiredScopes = @(if ($ReadOnly -or $Mode -eq 'Report') { 'Device.Read.All' } else { 'Directory.AccessAsUser.All' })
    if (-not $SkipKeyCheck -and -not $ReadOnly) {
        $RequiredScopes += $KeyScopes
    }
}
$MaxRetries = 5
$MaxRetryAfterSeconds = 120
$JoinTypeLabels = @{ AzureAD = 'Entra joined'; Workplace = 'Registered'; ServerAD = 'Hybrid joined' }
$JoinTypeFilter = @{ EntraJoined = 'AzureAD'; Registered = 'Workplace'; HybridJoined = 'ServerAD' }
$ReportColumns = @('DisplayName', 'Status', 'Reason', 'JoinType', 'OperatingSystem', 'OperatingSystemVersion', 'AccountEnabled',
    'LastSignIn', 'Registered', 'DaysInactive', 'DeleteEligibleFrom', 'IsManaged', 'Autopilot', 'BitLocker', 'Laps',
    'CanDisable', 'CanDelete', 'CanForceDelete', 'DeviceId', 'ObjectId')
$AuditColumns = @('TimestampUtc', 'Operator', 'TenantId', 'Mode', 'Action', 'Result', 'DisplayName', 'ObjectId', 'DeviceId', 'Detail')
$SensitiveReportWarning = 'contains device information. Store it securely and delete it when no longer needed.'
$script:AuditFile = $null
$script:ActionCount = 0
$script:WorstExit = $ExitCodeSuccess
$script:ReadOnlyRun = ($ReadOnly -or $Mode -eq 'Report')
$script:ProbeKeys = ($ReadOnly -or $script:UserRights) -and -not $SkipKeyCheck
$script:SkipKeys = [bool]$SkipKeyCheck
$script:KeySkip = @{ BitLocker = $false; Laps = $false }
$script:Now = [datetime]::UtcNow
$GuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
$script:Tenant = [PSCustomObject]@{ DisplayName = ''; Id = ''; Account = ''; AppOnly = $false; ClientId = ''; Scopes = @() }

function Get-MissingGraphScope {
    # Returns missing scopes. ReadWrite and higher privileged alternatives count as granted.
    param(
        [Parameter()]
        [AllowNull()]
        [string[]]$GrantedScopes,

        [Parameter(Mandatory)]
        [string[]]$RequiredScopes,

        [Parameter()]
        [switch]$AppOnly
    )

    $alternativeScopes = @{
        'Device.Read.All' = @('Device.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All', 'Directory.AccessAsUser.All')
    }
    if ($AppOnly) {
        # Directory.AccessAsUser.All is delegated only; app-only writes need Device.ReadWrite.All.
        $RequiredScopes = @($RequiredScopes | ForEach-Object { if ($_ -eq 'Directory.AccessAsUser.All') { 'Device.ReadWrite.All' } else { $_ } })
    }

    $granted = @($GrantedScopes | Where-Object { $_ })
    $missing = foreach ($scope in $RequiredScopes) {
        $acceptedScopes = @($scope, ($scope -replace '\.Read\.', '.ReadWrite.'))
        if ($alternativeScopes.ContainsKey($scope)) {
            $acceptedScopes += $alternativeScopes[$scope]
        }
        $isGranted = $false
        foreach ($acceptedScope in $acceptedScopes) {
            if ($granted -contains $acceptedScope) {
                $isGranted = $true
            }
        }
        if (-not $isGranted) {
            $scope
        }
    }
    return @($missing)
}

function Get-GraphTenantInfo {
    # Tenant name, id and verified domains, or $null.
    try {
        $orgUri = 'https://graph.microsoft.com/v1.0/organization?$select=displayName,id,verifiedDomains'
        $orgResponse = Invoke-MgGraphRequest -Method GET -Uri $orgUri
        $org = @($orgResponse.value) | Select-Object -First 1
        if ($org) {
            return [PSCustomObject]@{
                Id              = [string]$org.id
                DisplayName     = [string]$org.displayName
                VerifiedDomains = @($org.verifiedDomains | ForEach-Object { [string]$_.name } | Where-Object { $_ })
            }
        }
    }
    catch {
        Write-Verbose "Tenant organization details could not be read: $($_.Exception.Message)"
    }
    return $null
}

function Test-GraphTenantMatch {
    # $true / $false, or $null if a domain name cannot be verified.
    param(
        [Parameter(Mandatory)]
        [object]$Context,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter()]
        [AllowNull()]
        [object]$TenantInfo
    )

    $tenantGuid = [guid]::Empty
    if ([guid]::TryParse($TenantId, [ref]$tenantGuid)) {
        return ([string]$Context.TenantId -eq $tenantGuid.ToString())
    }
    if ($TenantInfo -and $TenantInfo.VerifiedDomains.Count -gt 0) {
        return ($TenantInfo.VerifiedDomains -contains $TenantId.Trim())
    }
    return $null
}

function Test-WindowsPlatform {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Get-GraphAuthModuleVersion {
    # Version of the module that provides Connect-MgGraph, or $null.
    [CmdletBinding()]
    [OutputType([version])]
    param()

    $connectCommand = Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue
    if ($connectCommand -and $connectCommand.Module) {
        return [version]$connectCommand.Module.Version
    }
    return $null
}

function Write-GraphModuleUpdateWarning {
    # Warns on Windows when the module is older than 2.34.0 (WAM not default).
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Test-WindowsPlatform)) {
        return $false
    }
    $moduleVersion = Get-GraphAuthModuleVersion
    if ($moduleVersion -and $moduleVersion -lt [version]'2.34.0') {
        Write-Warning "Microsoft.Graph.Authentication $moduleVersion is used. Update to 2.34.0 or later with Update-Module Microsoft.Graph.Authentication (WAM by default, passkey / FIDO2 sign-in). Check the loaded version with Get-Module Microsoft.Graph.Authentication."
        return $true
    }
    return $false
}

function Enable-StaleDevicesWam {
    # Enables WAM before Connect-MgGraph (2.0 - 2.33); the persisted option is restored at the end.
    # Returns NotWindows, Default, AlreadyEnabled or Enabled.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not (Test-WindowsPlatform)) {
        Write-Warning '-UseWAM is ignored: WAM is only available on Windows.'
        return 'NotWindows'
    }

    $moduleVersion = Get-GraphAuthModuleVersion

    if ($moduleVersion -and $moduleVersion -ge [version]'2.34.0') {
        Write-Information "-UseWAM: Microsoft.Graph.Authentication $moduleVersion uses WAM by default. No setting changed."
        return 'Default'
    }

    $setOptionCommand = Get-Command -Name Set-MgGraphOption -ErrorAction SilentlyContinue
    if (-not $setOptionCommand -or -not $setOptionCommand.Parameters.ContainsKey('EnableLoginByWAM')) {
        $foundVersion = if ($moduleVersion) { [string]$moduleVersion } else { 'not found' }
        throw "-UseWAM requires Microsoft.Graph.Authentication 2.0.0 or later, found version $foundVersion. Run Update-Module Microsoft.Graph.Authentication. No devices have been changed."
    }

    $previousValue = $false
    $currentOption = Get-MgGraphOption -ErrorAction SilentlyContinue
    if ($currentOption -and ($currentOption.PSObject.Properties.Name -contains 'EnableWAMForMSGraph')) {
        $previousValue = [bool]$currentOption.EnableWAMForMSGraph
    }

    if ($previousValue) {
        Write-Verbose 'Web Account Manager (WAM) sign-in is already enabled (Get-MgGraphOption).'
        return 'AlreadyEnabled'
    }

    Set-MgGraphOption -EnableLoginByWAM $true
    if ($null -eq $script:WamRestoreValue) {
        $script:WamRestoreValue = $previousValue
    }
    Write-Information 'WAM sign-in enabled for this run (restored at the end).'
    return 'Enabled'
}

function Restore-StaleDevicesWam {
    [CmdletBinding()]
    param()

    if ($null -eq $script:WamRestoreValue) {
        return
    }
    $restoreValue = [bool]$script:WamRestoreValue
    try {
        Set-MgGraphOption -EnableLoginByWAM $restoreValue
        Write-Verbose "Web Account Manager (WAM) option restored to EnableLoginByWAM = $restoreValue"
    }
    catch {
        Write-Warning "Could not restore the Web Account Manager (WAM) option. Run Set-MgGraphOption -EnableLoginByWAM `$$restoreValue to restore it: $($_.Exception.Message)"
    }
    finally {
        $script:WamRestoreValue = $null
    }
}

function Get-GraphErrorDetail {
    # HTTP status, Graph error code and message from an error record.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $statusCode = $null
    $errorCode = $null
    $errorMessage = $null
    $exception = $ErrorRecord.Exception

    try {
        if ($exception.PSObject.Properties['Response'] -and $exception.Response -and $exception.Response.PSObject.Properties['StatusCode']) {
            $statusCode = [int]$exception.Response.StatusCode
        }
        elseif ($exception.PSObject.Properties['StatusCode'] -and $exception.StatusCode) {
            $statusCode = [int]$exception.StatusCode
        }
    }
    catch {
        $statusCode = $null
    }

    $detailText = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $detailText = [string]$ErrorRecord.ErrorDetails.Message
    }
    $allText = (@($detailText, [string]$exception.Message) | Where-Object { $_ }) -join ' '

    if ($detailText) {
        try {
            $errorBody = $detailText | ConvertFrom-Json -ErrorAction Stop
            if ($errorBody.error) {
                $errorCode = [string]$errorBody.error.code
                $errorMessage = [string]$errorBody.error.message
            }
        }
        catch {
            Write-Verbose 'The Graph error details are not JSON.'
        }
    }
    if (-not $errorCode -and $allText -match '"code"\s*:\s*"([^"]+)"') {
        $errorCode = $Matches[1]
    }
    if (-not $errorCode -and $allText -match '\b(Authentication_RequestFromNonPremiumTenantOrB2CTenant|Authorization_RequestDenied|Authentication_RequestDenied|accessDenied)\b') {
        $errorCode = $Matches[1]
    }
    if (-not $statusCode) {
        if ($allText -match '(?:does not indicate success:|\bStatusCode\b\D{0,5}|\bHTTP/\d(?:\.\d)?)\s*(\d{3})\b') {
            $statusCode = [int]$Matches[1]
        }
        elseif ($allText -match '\bForbidden\b') {
            $statusCode = 403
        }
        elseif ($allText -match '\bUnauthorized\b') {
            $statusCode = 401
        }
    }

    return [PSCustomObject]@{
        StatusCode = $statusCode
        Code       = $errorCode
        Message    = $errorMessage
        Text       = $allText
    }
}

function Connect-StaleDevicesGraph {
    # Reuses the session if tenant and scopes match, otherwise connects. Returns the tenant.
    param(
        [Parameter(Mandatory)]
        [string[]]$RequiredScopes,

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [switch]$UseWAM
    )

    $null = Write-GraphModuleUpdateWarning

    $context = Get-MgContext
    $tenantInfo = $null
    $reason = $null

    if (-not $context) {
        $reason = 'no existing Microsoft Graph session'
    }
    else {
        $isAppOnly = ([string]$context.AuthType -eq 'AppOnly')

        if ($ClientId -and [string]$context.ClientId -ne $ClientId) {
            if ($isAppOnly) {
                throw "The existing Microsoft Graph session uses a different app ($($context.ClientId)). Disconnect-MgGraph and run again."
            }
            $reason = "the existing Microsoft Graph session uses app $($context.ClientId), not $ClientId"
        }

        if (-not $reason -and $TenantId) {
            $tenantInfo = Get-GraphTenantInfo
            $tenantMatch = Test-GraphTenantMatch -Context $context -TenantId $TenantId -TenantInfo $tenantInfo
            if ($tenantMatch -ne $true) {
                if ($tenantMatch -eq $false) {
                    $reason = "the existing Microsoft Graph session belongs to tenant $($context.TenantId), not '$TenantId'"
                }
                else {
                    $reason = "it could not be verified that the existing Microsoft Graph session (tenant $($context.TenantId)) belongs to '$TenantId'"
                }
                if ($isAppOnly) {
                    throw "Cannot reuse the app-only Microsoft Graph session: $reason. Connect the app to the correct tenant and run the script again."
                }
            }
        }

        if (-not $reason) {
            $missingScopes = @(Get-MissingGraphScope -GrantedScopes $context.Scopes -RequiredScopes $RequiredScopes -AppOnly:$isAppOnly)
            if ($missingScopes.Count -gt 0) {
                if ($isAppOnly) {
                    throw "The app-only Microsoft Graph session is missing the application permission(s): $($missingScopes -join ', '). Grant them with admin consent."
                }
                $reason = "the existing Microsoft Graph session is missing the scope(s): $($missingScopes -join ', ')"
            }
        }
    }

    if ($reason) {
        Write-Information "Connecting to Microsoft Graph: $reason."
        $connectParams = @{
            Scopes = $RequiredScopes
        }
        if ($ClientId) {
            $connectParams['ClientId'] = $ClientId
        }
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        elseif ($context -and $context.TenantId) {
            # Missing scopes only: stay in the same tenant.
            $connectParams['TenantId'] = $context.TenantId
        }
        if ($UseWAM) {
            $null = Enable-StaleDevicesWam
        }
        Connect-MgGraph @connectParams | Out-Null

        $context = Get-MgContext
        if (-not $context) {
            throw 'Connect-MgGraph did not establish a Microsoft Graph session.'
        }
        $tenantInfo = $null

        $missingScopes = @(Get-MissingGraphScope -GrantedScopes $context.Scopes -RequiredScopes $RequiredScopes)
        if ($missingScopes.Count -gt 0) {
            Write-Warning "The Microsoft Graph session is missing the scope(s): $($missingScopes -join ', '). Parts of the run may fail."
        }
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for tenant $($context.TenantId)"
        if ($UseWAM) {
            if ([string]$context.AuthType -eq 'AppOnly') {
                Write-Verbose '-UseWAM is ignored: the existing Microsoft Graph session is app-only (no interactive sign-in).'
            }
            else {
                Write-Verbose '-UseWAM has no effect: the existing Microsoft Graph session is reused, no sign-in is needed.'
            }
        }
    }

    if (-not $tenantInfo) {
        $tenantInfo = Get-GraphTenantInfo
    }

    if ($TenantId) {
        $tenantMatch = Test-GraphTenantMatch -Context $context -TenantId $TenantId -TenantInfo $tenantInfo
        if ($tenantMatch -eq $false) {
            throw "The Microsoft Graph session belongs to tenant $($context.TenantId), not '$TenantId'. No devices have been changed."
        }
        elseif ($null -eq $tenantMatch) {
            Write-Warning "Could not verify that tenant $($context.TenantId) has the domain '$TenantId'."
        }
    }

    if ($tenantInfo) {
        $tenantDisplayName = $tenantInfo.DisplayName
        $tenantIdValue = $tenantInfo.Id
    }
    else {
        $tenantDisplayName = '(name not available)'
        $tenantIdValue = [string]$context.TenantId
        Write-Warning "The tenant name could not be read. Verify that tenant $tenantIdValue is correct."
    }
    Write-Information "Connected to tenant: $tenantDisplayName ($tenantIdValue) as $($context.Account)"

    return [PSCustomObject]@{
        DisplayName = $tenantDisplayName
        Id          = $tenantIdValue
        Account     = [string]$context.Account
        AppOnly     = ([string]$context.AuthType -eq 'AppOnly')
        ClientId    = [string]$context.ClientId
        Scopes      = @($context.Scopes)
    }
}

function ConvertTo-CsvSafeRow {
    # Prefixes text starting with = + - @ tab CR with ' (CSV formula injection).
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Row
    )

    begin {
        $formulaStart = [char[]]@('=', '+', '-', '@', [char]9, [char]13)
    }
    process {
        $safeRow = [ordered]@{}
        foreach ($property in $Row.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string] -and $value.Length -gt 0 -and $formulaStart -contains $value[0]) {
                $value = "'" + $value
            }
            $safeRow[$property.Name] = $value
        }
        [PSCustomObject]$safeRow
    }
}

function Export-StaleDevicesCsv {
    # CSV as UTF-8 with BOM (PS 5.1 and 7); header only for an empty report.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Report,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string[]]$Columns
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if ($Report.Count -gt 0) {
        $lines = @($Report | ConvertTo-CsvSafeRow | ConvertTo-Csv -NoTypeInformation)
    }
    else {
        $lines = @(($Columns | ForEach-Object { '"' + $_ + '"' }) -join ',')
    }
    $utf8WithBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true
    [System.IO.File]::WriteAllLines($fullPath, [string[]]$lines, $utf8WithBom)
}

function Get-RetryAfterSecond {
    # Retry-After from the error response, otherwise exponential backoff.
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [int]$Attempt
    )

    $seconds = $null
    try {
        $exception = $ErrorRecord.Exception
        if ($exception.PSObject.Properties['Response'] -and $exception.Response -and $exception.Response.Headers) {
            $retryAfter = $exception.Response.Headers.RetryAfter
            if ($retryAfter -and $retryAfter.Delta) {
                $seconds = [int][math]::Ceiling($retryAfter.Delta.TotalSeconds)
            }
            elseif ($retryAfter -and $retryAfter.Date) {
                $seconds = [int][math]::Ceiling(($retryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds)
            }
        }
    }
    catch {
        $seconds = $null
    }
    if ($null -eq $seconds) {
        $seconds = [int][math]::Pow(2, $Attempt)
    }
    return [math]::Max(1, [math]::Min($seconds, $MaxRetryAfterSeconds))
}

function ConvertTo-UtcTimestamp {
    # Timestamp -> ISO 8601 UTC (2026-11-01T10:00:00Z). Unparseable values are returned unchanged.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or [string]$Value -eq '') {
        return ''
    }
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Value -is [System.DateTimeOffset]) {
        $utc = $Value.UtcDateTime
    }
    elseif ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
            $utc = [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
        }
        else {
            $utc = $Value.ToUniversalTime()
        }
    }
    else {
        $parsed = [System.DateTimeOffset]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
        if (-not [System.DateTimeOffset]::TryParse([string]$Value, $invariant, $styles, [ref]$parsed)) {
            return [string]$Value
        }
        $utc = $parsed.UtcDateTime
    }
    return $utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $invariant)
}

function ConvertTo-HtmlSafe {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object]$Value
    )

    process {
        if ($null -eq $Value) {
            return ''
        }
        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }
}
function Invoke-StaleDevicesGraph {
    # Invoke-MgGraphRequest with retry on 429 (GET also 503/504). Writes are only retried on 429.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [string]$Body,

        [Parameter()]
        [hashtable]$Headers
    )

    if ($Method -ne 'GET' -and $script:ReadOnlyRun) {
        throw "Read-only run: $Method requests are blocked."
    }
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $request = @{ Method = $Method; Uri = $Uri }
            if ($Body) {
                $request['Body'] = $Body
                $request['ContentType'] = 'application/json'
            }
            if ($Headers) {
                $request['Headers'] = $Headers
            }
            return Invoke-MgGraphRequest @request
        }
        catch {
            $status = (Get-GraphErrorDetail -ErrorRecord $_).StatusCode
            $retryable = ($status -eq 429) -or ($Method -eq 'GET' -and $status -in @(503, 504))
            if (-not $retryable -or $attempt -gt $MaxRetries) {
                throw
            }
            $wait = Get-RetryAfterSecond -ErrorRecord $_ -Attempt $attempt
            Write-Verbose "HTTP $status from Graph, retry $attempt of $MaxRetries in $wait s: $Method $Uri"
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-MgGraphAllPage {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    while ($nextUri) {
        $response = Invoke-StaleDevicesGraph -Method GET -Uri $nextUri -Headers $Headers
        foreach ($item in @($response.value)) {
            if ($null -ne $item) {
                $results.Add($item)
            }
        }
        $nextUri = $response.'@odata.nextLink'
    }
    return , $results.ToArray()
}

function ConvertTo-UtcDateTime {
    # Graph timestamp -> UTC [datetime], or $null.
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value -or [string]$Value -eq '') {
        return $null
    }
    if ($Value -is [System.DateTimeOffset]) {
        return $Value.UtcDateTime
    }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) {
            return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
        }
        return $Value.ToUniversalTime()
    }
    $parsed = [System.DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([System.DateTimeOffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }
    return $null
}

function Get-DeviceOsFamily {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$OperatingSystem
    )

    $os = ([string]$OperatingSystem).Trim()
    if ($os -match '^windows') { return 'Windows' }
    if ($os -match '^(macmdm|macos|mac os|osx)') { return 'macOS' }
    if ($os -match '^(ios|ipad|iphone)') { return 'iOS' }
    if ($os -match '^android') { return 'Android' }
    if ($os -match '^linux') { return 'Linux' }
    return 'Other'
}

function Test-AutopilotDevice {
    # Windows Autopilot devices have a [ZTDID] entry in physicalIds.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Device
    )

    if ($null -eq $Device) {
        return $false
    }
    foreach ($id in @($Device.physicalIds)) {
        if ([string]$id -like '`[ZTDID`]*') {
            return $true
        }
    }
    return $false
}

function Get-DeviceKeyIndex {
    # deviceIds with BitLocker keys / LAPS passwords. $null = could not be read (Unknown).
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $index = @{ BitLocker = $null; Laps = $null }
    if ($script:SkipKeys) {
        return $index
    }
    if (-not $script:KeySkip.BitLocker) {
        try {
            $keys = Get-MgGraphAllPage -Uri "$GraphBase/informationProtection/bitlocker/recoveryKeys" -Headers $KeyHeaders
            $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($key in $keys) { if ($key.deviceId) { [void]$set.Add([string]$key.deviceId) } }
            $index.BitLocker = $set
        }
        catch {
            Write-Warning "BitLocker keys could not be read (status Unknown, delete blocked without -AllowKeyLoss): $($_.Exception.Message)"
        }
    }
    if (-not $script:KeySkip.Laps) {
        try {
            $creds = Get-MgGraphAllPage -Uri "$GraphBase/directory/deviceLocalCredentials?`$select=id,deviceName" -Headers $KeyHeaders
            $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($cred in $creds) { if ($cred.id) { [void]$set.Add([string]$cred.id) } }
            $index.Laps = $set
        }
        catch {
            Write-Warning "LAPS passwords could not be read (status Unknown, delete blocked without -AllowKeyLoss): $($_.Exception.Message)"
        }
    }
    return $index
}

function Get-KeyStatusFromIndex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Set,

        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DeviceId
    )

    if ($null -eq $Set -or -not $DeviceId) {
        return 'Unknown'
    }
    if ($Set.Contains($DeviceId)) {
        return 'Yes'
    }
    return 'No'
}

function Get-DeviceKeyStatusLive {
    # Fresh BitLocker / LAPS status for one device (used right before delete).
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DeviceId
    )

    $status = @{ BitLocker = 'Unknown'; Laps = 'Unknown' }
    if ($script:SkipKeys -or $DeviceId -notmatch $GuidPattern) {
        return $status
    }
    try {
        $filter = [uri]::EscapeDataString("deviceId eq '$DeviceId'")
        $keys = Invoke-StaleDevicesGraph -Method GET -Uri "$GraphBase/informationProtection/bitlocker/recoveryKeys?`$filter=$filter" -Headers $KeyHeaders
        $status.BitLocker = if (@($keys.value | Where-Object { $_ }).Count -gt 0) { 'Yes' } else { 'No' }
    }
    catch {
        Write-Verbose "BitLocker status for $DeviceId unknown: $($_.Exception.Message)"
    }
    try {
        $null = Invoke-StaleDevicesGraph -Method GET -Uri "$GraphBase/directory/deviceLocalCredentials/$DeviceId`?`$select=id" -Headers $KeyHeaders
        $status.Laps = 'Yes'
    }
    catch {
        if ((Get-GraphErrorDetail -ErrorRecord $_).StatusCode -eq 404) {
            $status.Laps = 'No'
        }
        else {
            Write-Verbose "LAPS status for $DeviceId unknown: $($_.Exception.Message)"
        }
    }
    return $status
}

function Get-StaleDeviceAssessment {
    # Applies all eligibility rules to one Graph device object.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [object]$Device,

        [Parameter()]
        [string]$BitLocker = 'Unknown',

        [Parameter()]
        [string]$Laps = 'Unknown'
    )

    $lastSignIn = ConvertTo-UtcDateTime -Value $Device.approximateLastSignInDateTime
    $registered = ConvertTo-UtcDateTime -Value $Device.registrationDateTime
    $trust = [string]$Device.trustType
    $enabled = ($Device.accountEnabled -ne $false)
    $autopilot = Test-AutopilotDevice -Device $Device
    $managed = ($Device.isManaged -eq $true)

    $reference = $null
    $threshold = $StaleDays
    $basis = 'last sign-in'
    if ($lastSignIn) {
        $reference = $lastSignIn
    }
    elseif ($registered) {
        $reference = $registered
        $threshold = $NoSignInDays
        $basis = 'registered, never signed in'
    }

    $days = $null
    $isStale = $false
    $deleteFrom = $null
    $pastGrace = $false
    if ($reference) {
        $days = [int][math]::Floor(($script:Now - $reference).TotalDays)
        $isStale = ($reference -le $script:Now.AddDays(-$threshold))
        $deleteFrom = $reference.AddDays($threshold + $GraceDays)
        $pastGrace = ($script:Now -ge $deleteFrom)
    }

    $exclusions = @()
    if ($trust -eq 'ServerAD') {
        $exclusions += 'Hybrid joined: report only, clean up in on-premises AD'
    }
    elseif ($trust -notin @('AzureAD', 'Workplace')) {
        $exclusions += 'Unknown join type: report only'
    }
    if ($autopilot -and -not $IncludeAutopilot) {
        $exclusions += 'Autopilot device (use -IncludeAutopilot)'
    }
    if ($managed -and -not $IncludeIntuneManaged) {
        $exclusions += 'Intune/MDM managed: retire in Intune first (or use -IncludeIntuneManaged)'
    }
    $keyReasons = @()
    if (-not $AllowKeyLoss) {
        if ($BitLocker -ne 'No') { $keyReasons += "BitLocker key: $BitLocker" }
        if ($Laps -ne 'No') { $keyReasons += "LAPS password: $Laps" }
    }

    $canDisable = $isStale -and $enabled -and $exclusions.Count -eq 0
    $canDelete = $isStale -and (-not $enabled) -and $pastGrace -and $exclusions.Count -eq 0 -and $keyReasons.Count -eq 0
    $canForceDelete = [bool]$ForceDelete -and $isStale -and $exclusions.Count -eq 0 -and $keyReasons.Count -eq 0
    $inactiveText = if ($null -ne $days) { "inactive $days days ($basis)" } else { '' }

    if (-not $reference) {
        $status = 'Unknown'; $reason = 'No last sign-in or registration date'
    }
    elseif (-not $isStale) {
        $status = 'Active'; $reason = "Not stale: $inactiveText"
    }
    elseif ($exclusions.Count -gt 0) {
        $status = 'Excluded'; $reason = ($exclusions -join '; ')
    }
    elseif ($enabled) {
        $status = 'Stale'; $reason = "Stale, $inactiveText. Disable first."
    }
    elseif (-not $pastGrace) {
        $status = 'GracePeriod'; $reason = "Disabled, $inactiveText. Delete from $($deleteFrom.ToString('yyyy-MM-dd'))."
    }
    elseif ($keyReasons.Count -gt 0) {
        $status = 'DeleteBlocked'; $reason = ($keyReasons -join '; ') + ' (use -AllowKeyLoss)'
    }
    else {
        $status = 'DeleteReady'; $reason = "Disabled, $inactiveText."
    }
    if ($status -in @('Stale', 'GracePeriod') -and $keyReasons.Count -gt 0) {
        $reason += ' Delete blocked: ' + ($keyReasons -join '; ') + '.'
    }

    $joinLabel = if ($JoinTypeLabels.ContainsKey($trust)) { $JoinTypeLabels[$trust] } elseif ($trust) { $trust } else { 'Unknown' }
    [PSCustomObject]@{
        DisplayName            = [string]$Device.displayName
        Status                 = $status
        Reason                 = $reason
        JoinType               = $joinLabel
        OperatingSystem        = [string]$Device.operatingSystem
        OperatingSystemVersion = [string]$Device.operatingSystemVersion
        AccountEnabled         = $Device.accountEnabled
        LastSignIn             = ConvertTo-UtcTimestamp -Value $lastSignIn
        Registered             = ConvertTo-UtcTimestamp -Value $registered
        DaysInactive           = $days
        DeleteEligibleFrom     = ConvertTo-UtcTimestamp -Value $deleteFrom
        IsManaged              = $managed
        Autopilot              = $autopilot
        BitLocker              = $BitLocker
        Laps                   = $Laps
        CanDisable             = [bool]$canDisable
        CanDelete              = [bool]$canDelete
        CanForceDelete         = [bool]$canForceDelete
        DeviceId               = [string]$Device.deviceId
        ObjectId               = [string]$Device.id
    }
}

function Get-StaleDeviceReport {
    # Reads all devices and key status, applies -JoinType / -OperatingSystem and the rules.
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $script:Now = [datetime]::UtcNow
    Write-Information 'Reading devices from Microsoft Graph...'
    $devices = Get-MgGraphAllPage -Uri "$GraphBase/devices?`$select=$DeviceSelect&`$top=999"
    $index = Get-DeviceKeyIndex
    $statusOrder = @{ DeleteReady = 0; DeleteBlocked = 1; GracePeriod = 2; Stale = 3; Excluded = 4; Unknown = 5; Active = 6 }
    $rows = foreach ($device in $devices) {
        if ($JoinType -ne 'All' -and [string]$device.trustType -ne $JoinTypeFilter[$JoinType]) {
            continue
        }
        if ($OperatingSystem -ne 'All' -and (Get-DeviceOsFamily -OperatingSystem $device.operatingSystem) -ne $OperatingSystem) {
            continue
        }
        $bitLocker = Get-KeyStatusFromIndex -Set $index.BitLocker -DeviceId $device.deviceId
        $laps = Get-KeyStatusFromIndex -Set $index.Laps -DeviceId $device.deviceId
        Get-StaleDeviceAssessment -Device $device -BitLocker $bitLocker -Laps $laps
    }
    $sorted = @($rows | Sort-Object -Property @{ Expression = { $statusOrder[$_.Status] } }, @{ Expression = { $_.DaysInactive }; Descending = $true }, DisplayName)
    return , $sorted
}

function Write-StaleDeviceAudit {
    # Appends one row to the audit CSV (created with UTF-8 BOM and header).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Entry
    )

    if (-not $script:AuditFile) {
        $path = $AuditPath
        if (-not $path) {
            $path = Join-Path -Path (Get-Location).ProviderPath -ChildPath ('StaleDevices-Audit-' + $script:Now.ToString('yyyyMMdd-HHmmss') + 'Z.csv')
        }
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
        if (-not (Test-Path -LiteralPath $fullPath)) {
            $header = (($AuditColumns | ForEach-Object { '"' + $_ + '"' }) -join ',') + "`r`n"
            [System.IO.File]::WriteAllText($fullPath, $header, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true))
        }
        $script:AuditFile = $fullPath
        Write-Information "Audit log: $fullPath"
    }
    $line = @($Entry | Select-Object -Property $AuditColumns | ConvertTo-CsvSafeRow | ConvertTo-Csv -NoTypeInformation)[1]
    [System.IO.File]::AppendAllText($script:AuditFile, $line + "`r`n", (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
}

function Invoke-StaleDeviceAction {
    # Re-reads the device from Graph, re-checks all rules, then disables or deletes it (or simulates).
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ObjectId,

        [Parameter(Mandatory)]
        [ValidateSet('Disable', 'Delete', 'ForceDelete')]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter()]
        [switch]$Simulate,

        [Parameter()]
        [switch]$Declined
    )

    $entry = [PSCustomObject]@{
        TimestampUtc = [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        Operator     = $script:Tenant.Account
        TenantId     = $script:Tenant.Id
        Mode         = $Source
        Action       = $Action
        Result       = ''
        DisplayName  = ''
        ObjectId     = $ObjectId
        DeviceId     = ''
        Detail       = ''
    }
    if ($script:ReadOnlyRun) {
        $entry.Result = 'Blocked'; $entry.Detail = 'Read-only run.'
        Write-StaleDeviceAudit -Entry $entry
        return $entry
    }
    if ($ObjectId -notmatch $GuidPattern) {
        $entry.Result = 'Blocked'; $entry.Detail = 'Invalid object id.'
        Write-StaleDeviceAudit -Entry $entry
        return $entry
    }
    if ($Declined) {
        $entry.Result = 'Declined'; $entry.Detail = 'Not confirmed.'
        Write-StaleDeviceAudit -Entry $entry
        return $entry
    }
    try {
        $device = Invoke-StaleDevicesGraph -Method GET -Uri "$GraphBase/devices/$ObjectId`?`$select=$DeviceSelect"
        $entry.DisplayName = [string]$device.displayName
        $entry.DeviceId = [string]$device.deviceId
        $script:Now = [datetime]::UtcNow
        $keys = @{ BitLocker = 'Unknown'; Laps = 'Unknown' }
        if ($Action -ne 'Disable') {
            $keys = Get-DeviceKeyStatusLive -DeviceId $device.deviceId
        }
        $check = Get-StaleDeviceAssessment -Device $device -BitLocker $keys.BitLocker -Laps $keys.Laps
        $allowed = switch ($Action) {
            'Disable' { $check.CanDisable }
            'Delete' { $check.CanDelete }
            'ForceDelete' { $check.CanForceDelete }
        }
        if (-not $allowed) {
            $entry.Result = 'Blocked'
            $entry.Detail = "Not eligible for $Action now ($($check.Status)): $($check.Reason)"
        }
        elseif ($Simulate) {
            $entry.Result = 'WhatIf'
            $entry.Detail = "Eligible ($($check.Status)). No change made."
        }
        else {
            if ($Action -eq 'Disable') {
                $null = Invoke-StaleDevicesGraph -Method PATCH -Uri "$GraphBase/devices/$ObjectId" -Body '{"accountEnabled":false}'
            }
            else {
                $null = Invoke-StaleDevicesGraph -Method DELETE -Uri "$GraphBase/devices/$ObjectId"
            }
            $entry.Result = 'Success'
            $entry.Detail = "$($check.Status): $($check.Reason)"
        }
    }
    catch {
        $detail = Get-GraphErrorDetail -ErrorRecord $_
        $failure = Get-StaleDevicesFailure -ErrorRecord $_ -Step 'Actions'
        if ($detail.StatusCode -eq 404) {
            $entry.Result = 'Blocked'; $entry.Detail = 'Device not found (already deleted?).'
        }
        else {
            $entry.Result = 'Failed'; $entry.Detail = $failure.Message
            if ($failure.ExitCode -gt $script:WorstExit) {
                $script:WorstExit = $failure.ExitCode
            }
        }
    }
    Write-StaleDeviceAudit -Entry $entry
    return $entry
}

function Get-StaleDevicesFailure {
    # Maps an error to exit code and message.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [ValidateSet('Module', 'SignIn', 'Devices', 'Actions', 'Other')]
        [string]$Step
    )

    $detail = Get-GraphErrorDetail -ErrorRecord $ErrorRecord
    $codeParts = @()
    if ($detail.Code) { $codeParts += "Graph error code: $($detail.Code)" }
    if ($detail.StatusCode) { $codeParts += "HTTP $($detail.StatusCode)" }
    $codeText = if ($codeParts.Count -gt 0) { " ($($codeParts -join ', '))" } else { '' }
    $graphMessage = if ($detail.Message) { $detail.Message } else { $ErrorRecord.Exception.Message }
    $isPermission = ($Step -notin @('Module', 'Other')) -and (($detail.StatusCode -eq 403) -or ([string]$detail.Code -in @('Authorization_RequestDenied', 'Authentication_RequestDenied', 'accessDenied', 'Forbidden')))

    if ($isPermission) {
        $need = if ($Step -eq 'Actions') { 'Directory.AccessAsUser.All (app-only: Device.ReadWrite.All) and Cloud Device Administrator (or Intune / Windows 365 Administrator for delete)' } else { 'Device.Read.All (delegated: admin consent once for Microsoft Graph Command Line Tools)' }
        return [PSCustomObject]@{
            ExitCode = $ExitCodePermission; ErrorId = 'GraphAccessDenied'
            Category = [System.Management.Automation.ErrorCategory]::PermissionDenied
            Message  = "Access denied$codeText. Requires $need. Graph message: $graphMessage"
        }
    }
    if ($Step -eq 'SignIn' -or ($Step -notin @('Module', 'Other') -and $detail.StatusCode -eq 401)) {
        return [PSCustomObject]@{
            ExitCode = $ExitCodeSignIn; ErrorId = 'GraphSignInFailed'
            Category = [System.Management.Automation.ErrorCategory]::AuthenticationError
            Message  = "Microsoft Graph sign-in or session check failed$codeText. $($ErrorRecord.Exception.Message)"
        }
    }
    return [PSCustomObject]@{
        ExitCode = $ExitCodeError; ErrorId = 'CleanupStaleDevicesFailed'
        Category = [System.Management.Automation.ErrorCategory]::NotSpecified
        Message  = "Failed$codeText. $graphMessage"
    }
}

function Get-StaleDevicesSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Rows
    )

    $parts = foreach ($status in @('DeleteReady', 'DeleteBlocked', 'GracePeriod', 'Stale', 'Excluded', 'Unknown', 'Active')) {
        $count = @($Rows | Where-Object { $_.Status -eq $status }).Count
        if ($count -gt 0) { "${status}: $count" }
    }
    if (-not $parts) { return 'none' }
    return ($parts -join ', ')
}

function Get-StaleDevicesSettingsText {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $flags = @()
    if ($ReadOnly) { $flags += 'ReadOnly' }
    if ($ForceDelete) { $flags += 'ForceDelete' }
    if ($IncludeAutopilot) { $flags += 'IncludeAutopilot' }
    if ($IncludeIntuneManaged) { $flags += 'IncludeIntuneManaged' }
    if ($AllowKeyLoss) { $flags += 'AllowKeyLoss' }
    if ($script:SkipKeys) { $flags += 'SkipKeyCheck' }
    $flagText = if ($flags.Count -gt 0) { ', ' + ($flags -join ', ') } else { '' }
    return "StaleDays $StaleDays, GraceDays $GraceDays, NoSignInDays $NoSignInDays, JoinType $JoinType, OS $OperatingSystem$flagText"
}

function ConvertTo-StaleDevicesHtml {
    # Static HTML report (no scripts; all values HTML-encoded).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Rows
    )

    $sb = [System.Text.StringBuilder]::new()
    $generated = [datetime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'", [System.Globalization.CultureInfo]::InvariantCulture)
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>Stale devices - $(ConvertTo-HtmlSafe $script:Tenant.DisplayName)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2937}
h1{font-size:20px;margin:0 0 4px}
.meta,.note{color:#6b7280;font-size:13px}
.note{background:#fef3c7;border:1px solid #fcd34d;padding:8px 12px;border-radius:6px;color:#78350f;margin:12px 0}
.cards{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.card{border:1px solid #e5e7eb;border-radius:8px;padding:8px 14px;min-width:110px}
.card b{display:block;font-size:20px}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{border-bottom:1px solid #e5e7eb;padding:5px 6px;text-align:left;vertical-align:top}
th{background:#f3f4f6;position:sticky;top:0}
</style>
</head>
<body>
<h1>Stale devices</h1>
<div class="meta">Tenant: $(ConvertTo-HtmlSafe $script:Tenant.DisplayName) ($(ConvertTo-HtmlSafe $script:Tenant.Id)) | Generated: $generated | Cleanup-StaleDevices $ScriptVersion</div>
<div class="meta">Settings: $(ConvertTo-HtmlSafe (Get-StaleDevicesSettingsText))</div>
<div class="note">This report $(ConvertTo-HtmlSafe $SensitiveReportWarning) Hybrid joined devices are report only. Deleting a device also deletes its BitLocker keys and LAPS password.</div>
<div class="cards">
"@)
    foreach ($status in @('DeleteReady', 'DeleteBlocked', 'GracePeriod', 'Stale', 'Excluded', 'Unknown', 'Active')) {
        $count = @($Rows | Where-Object { $_.Status -eq $status }).Count
        [void]$sb.Append("<div class=""card""><b>$count</b>$status</div>")
    }
    [void]$sb.Append("</div>`n<table>`n<thead><tr>")
    foreach ($column in $ReportColumns) {
        [void]$sb.Append('<th>' + (ConvertTo-HtmlSafe $column) + '</th>')
    }
    [void]$sb.Append("</tr></thead>`n<tbody>`n")
    foreach ($row in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($column in $ReportColumns) {
            [void]$sb.Append('<td>' + (ConvertTo-HtmlSafe $row.$column) + '</td>')
        }
        [void]$sb.Append("</tr>`n")
    }
    if ($Rows.Count -eq 0) {
        [void]$sb.Append("<tr><td colspan=""$($ReportColumns.Count)"">No devices.</td></tr>`n")
    }
    [void]$sb.Append("</tbody>`n</table>`n</body>`n</html>`n")
    return $sb.ToString()
}

function Get-UiSecret {
    # Random hex string (cryptographic RNG).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [int]$Bytes = 32
    )

    $buffer = New-Object -TypeName byte[] -ArgumentList $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return ([System.BitConverter]::ToString($buffer) -replace '-', '').ToLowerInvariant()
}

function Test-UiTokenEqual {
    # Constant-time string compare.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Supplied,

        [Parameter(Mandatory)]
        [string]$Expected
    )

    if ([string]::IsNullOrEmpty($Supplied) -or $Supplied.Length -ne $Expected.Length) {
        return $false
    }
    $diff = 0
    for ($i = 0; $i -lt $Expected.Length; $i++) {
        $diff = $diff -bor ([int][char]$Supplied[$i] -bxor [int][char]$Expected[$i])
    }
    return ($diff -eq 0)
}

function Test-UiRequest {
    # Returns $null if the request may be served, otherwise the reason.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Request,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter(Mandatory)]
        [int]$UiPort,

        [Parameter()]
        [switch]$Api
    )

    if (-not $Request.RemoteIsLoopback) {
        return 'Remote address is not loopback.'
    }
    if ($Request.DuplicateSecurityHeader) {
        return 'Duplicate Host, Origin or token header.'
    }
    $hostHeader = [string]$Request.Headers['Host']
    if ($hostHeader -notin @("127.0.0.1:$UiPort", "localhost:$UiPort")) {
        return 'Invalid Host header.'
    }
    if (-not $Api) {
        return $null
    }
    if ($Request.Method -ne 'POST') {
        return 'Only POST is allowed.'
    }
    $origin = [string]$Request.Headers['Origin']
    if ($origin -notin @("http://127.0.0.1:$UiPort", "http://localhost:$UiPort")) {
        return 'Invalid or missing Origin header.'
    }
    $fetchSite = [string]$Request.Headers['Sec-Fetch-Site']
    if ($fetchSite -and $fetchSite -ne 'same-origin') {
        return 'Cross-site request.'
    }
    if ([string]$Request.Headers['Content-Type'] -notmatch '^application/json\s*(;|$)') {
        return 'Content-Type must be application/json.'
    }
    if (-not (Test-UiTokenEqual -Supplied ([string]$Request.Headers['X-CSRF-Token']) -Expected $Token)) {
        return 'Invalid CSRF token.'
    }
    return $null
}

function Read-UiHttpRequest {
    # Minimal HTTP/1.1 request parser (headers max 16 KB, body max 64 KB).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.TcpClient]$Client
    )

    $stream = $Client.GetStream()
    $stream.ReadTimeout = 5000
    $buffer = New-Object -TypeName byte[] -ArgumentList 8192
    $ms = New-Object -TypeName System.IO.MemoryStream
    $headerEnd = -1
    while ($headerEnd -lt 0) {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { return $null }
        $ms.Write($buffer, 0, $read)
        $text = [System.Text.Encoding]::ASCII.GetString($ms.ToArray())
        $headerEnd = $text.IndexOf("`r`n`r`n")
        if ($headerEnd -lt 0 -and $ms.Length -gt 16384) { throw 'Request header too large.' }
    }
    $all = $ms.ToArray()
    $lines = [System.Text.Encoding]::ASCII.GetString($all, 0, $headerEnd) -split "`r`n"
    $requestLine = $lines[0] -split ' '
    if ($requestLine.Count -ne 3) { throw 'Bad request line.' }
    $headers = @{}
    $duplicate = $false
    foreach ($line in $lines[1..($lines.Count - 1)]) {
        $colon = $line.IndexOf(':')
        if ($colon -le 0) { continue }
        $name = $line.Substring(0, $colon).Trim()
        $value = $line.Substring($colon + 1).Trim()
        if ($headers.ContainsKey($name)) {
            if ($name -in @('Host', 'Origin', 'X-CSRF-Token', 'Content-Length')) { $duplicate = $true }
            continue
        }
        $headers[$name] = $value
    }
    $length = 0
    if ($headers.ContainsKey('Content-Length') -and -not [int]::TryParse($headers['Content-Length'], [ref]$length)) { throw 'Bad Content-Length.' }
    if ($length -lt 0 -or $length -gt 65536) { throw 'Request body too large.' }
    $body = New-Object -TypeName System.IO.MemoryStream
    $bodyStart = $headerEnd + 4
    if ($all.Length -gt $bodyStart) { $body.Write($all, $bodyStart, $all.Length - $bodyStart) }
    while ($body.Length -lt $length) {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { break }
        $body.Write($buffer, 0, $read)
    }
    $remote = $Client.Client.RemoteEndPoint
    [PSCustomObject]@{
        Method                  = $requestLine[0]
        Path                    = ($requestLine[1] -split '\?')[0]
        Headers                 = $headers
        Body                    = [System.Text.Encoding]::UTF8.GetString($body.ToArray(), 0, [math]::Min([int]$body.Length, $length))
        RemoteIsLoopback        = ($remote -is [System.Net.IPEndPoint]) -and [System.Net.IPAddress]::IsLoopback($remote.Address)
        DuplicateSecurityHeader = $duplicate
    }
}

function Send-UiHttpResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.TcpClient]$Client,

        [Parameter(Mandatory)]
        [int]$Status,

        [Parameter(Mandatory)]
        [string]$ContentType,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Body = '',

        [Parameter()]
        [string]$Csp = "default-src 'none'; frame-ancestors 'none'"
    )

    $reasons = @{ 200 = 'OK'; 400 = 'Bad Request'; 403 = 'Forbidden'; 404 = 'Not Found'; 405 = 'Method Not Allowed'; 500 = 'Internal Server Error' }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $head = "HTTP/1.1 $Status $($reasons[$Status])`r`n" +
        "Content-Type: $ContentType`r`n" +
        "Content-Length: $($bytes.Length)`r`n" +
        "Content-Security-Policy: $Csp`r`n" +
        "X-Content-Type-Options: nosniff`r`n" +
        "X-Frame-Options: DENY`r`n" +
        "Referrer-Policy: no-referrer`r`n" +
        "Cross-Origin-Resource-Policy: same-origin`r`n" +
        "Cross-Origin-Opener-Policy: same-origin`r`n" +
        "Cache-Control: no-store`r`n" +
        "Connection: close`r`n`r`n"
    $headBytes = [System.Text.Encoding]::ASCII.GetBytes($head)
    $stream = $Client.GetStream()
    $stream.Write($headBytes, 0, $headBytes.Length)
    if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }
    $stream.Flush()
    $Client.Close()
}

function ConvertTo-UiJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$InputObject
    )

    # Escape < > & so JSON can never be sniffed as HTML.
    $json = $InputObject | ConvertTo-Json -Depth 6 -Compress
    return $json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
}

function Get-UiState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $rows = @($script:UiRows)
    $script:LoadedDevices = @{}
    foreach ($row in $rows) { $script:LoadedDevices[$row.ObjectId] = $row }
    return @{
        ok          = $true
        version     = $ScriptVersion
        tenant      = $script:Tenant.DisplayName
        tenantId    = $script:Tenant.Id
        operator    = $script:Tenant.Account
        settings    = (Get-StaleDevicesSettingsText)
        whatIf      = [bool]$WhatIfPreference
        readOnly    = [bool]$script:ReadOnlyRun
        forceDelete = [bool]$ForceDelete -and -not $script:ReadOnlyRun
        maxDevices  = $MaxDevices
        actionsUsed = $script:ActionCount
        summary     = (Get-StaleDevicesSummary -Rows $rows)
        devices     = @($rows | ForEach-Object {
                @{ objectId = $_.ObjectId; name = $_.DisplayName; status = $_.Status; reason = $_.Reason; joinType = $_.JoinType
                    os = $_.OperatingSystem; osVersion = $_.OperatingSystemVersion; enabled = $_.AccountEnabled; lastSignIn = $_.LastSignIn
                    days = $_.DaysInactive; deleteFrom = $_.DeleteEligibleFrom; managed = $_.IsManaged; autopilot = $_.Autopilot
                    bitLocker = $_.BitLocker; laps = $_.Laps; canDisable = $_.CanDisable; canDelete = $_.CanDelete; canForceDelete = $_.CanForceDelete }
            })
    }
}

function Invoke-UiAction {
    # Validates an action request from the UI and runs it device by device.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Body
    )

    if ($script:ReadOnlyRun) {
        return @{ status = 403; error = 'Read-only run: actions are disabled.' }
    }
    $actionMap = @{ disable = 'Disable'; delete = 'Delete'; forcedelete = 'ForceDelete' }
    $confirmText = @{ Disable = 'DISABLE'; Delete = 'DELETE'; ForceDelete = 'FORCE DELETE' }
    $actionKey = [string]$Body.action
    if (-not $actionMap.ContainsKey($actionKey)) {
        return @{ status = 400; error = 'Unknown action.' }
    }
    $action = $actionMap[$actionKey]
    if ($action -eq 'ForceDelete' -and -not $ForceDelete) {
        return @{ status = 403; error = 'Force delete is not enabled. Start the script with -ForceDelete.' }
    }
    if ([string]$Body.confirm -cne $confirmText[$action]) {
        return @{ status = 400; error = "Confirmation text '$($confirmText[$action])' is required." }
    }
    $ids = @($Body.ids)
    if ($ids.Count -lt 1 -or $ids.Count -gt 20) {
        return @{ status = 400; error = 'Send 1 to 20 device ids per request.' }
    }
    foreach ($id in $ids) {
        if ($id -isnot [string] -or $id -notmatch $GuidPattern) {
            return @{ status = 400; error = 'Invalid device id.' }
        }
        if (-not $script:LoadedDevices.ContainsKey($id)) {
            return @{ status = 400; error = 'Device is not in the loaded list. Reload and try again.' }
        }
    }
    if ($script:ActionCount + $ids.Count -gt $MaxDevices) {
        return @{ status = 400; error = "Limit reached: -MaxDevices $MaxDevices per run ($($script:ActionCount) used)." }
    }
    $results = foreach ($id in $ids) {
        $script:ActionCount++
        $entry = Invoke-StaleDeviceAction -ObjectId $id -Action $action -Source 'UI' -Simulate:([bool]$WhatIfPreference)
        Write-Information "[UI $action] $($entry.Result) $($entry.DisplayName) - $($entry.Detail)"
        @{ objectId = $entry.ObjectId; name = $entry.DisplayName; result = $entry.Result; detail = $entry.Detail }
    }
    return @{ status = 200; ok = $true; results = @($results); actionsUsed = $script:ActionCount }
}

function Invoke-UiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.TcpClient]$Client
    )

    $json = 'application/json; charset=utf-8'
    $request = Read-UiHttpRequest -Client $Client
    if (-not $request) {
        $Client.Close()
        return
    }
    if ($request.Method -eq 'GET' -and $request.Path -in @('/', '/index.html')) {
        $reason = Test-UiRequest -Request $request -Token $script:UiToken -UiPort $Port
        if ($reason) {
            Send-UiHttpResponse -Client $Client -Status 403 -ContentType 'text/plain; charset=utf-8' -Body $reason
            return
        }
        $nonce = Get-UiSecret -Bytes 16
        $csp = "default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        $page = $script:UiHtml.Replace('__NONCE__', $nonce).Replace('__TOKEN__', $script:UiToken)
        Send-UiHttpResponse -Client $Client -Status 200 -ContentType 'text/html; charset=utf-8' -Body $page -Csp $csp
        return
    }
    if (-not $request.Path.StartsWith('/api/')) {
        Send-UiHttpResponse -Client $Client -Status 404 -ContentType 'text/plain; charset=utf-8' -Body 'Not found'
        return
    }
    if ($request.Method -ne 'POST') {
        Send-UiHttpResponse -Client $Client -Status 405 -ContentType $json -Body '{"ok":false,"error":"Only POST is allowed."}'
        return
    }
    $reason = Test-UiRequest -Request $request -Token $script:UiToken -UiPort $Port -Api
    if ($reason) {
        Write-Warning "UI request rejected: $reason"
        Send-UiHttpResponse -Client $Client -Status 403 -ContentType $json -Body (ConvertTo-UiJson @{ ok = $false; error = $reason })
        return
    }
    $body = $null
    try {
        if ($request.Body) { $body = $request.Body | ConvertFrom-Json }
    }
    catch {
        Send-UiHttpResponse -Client $Client -Status 400 -ContentType $json -Body '{"ok":false,"error":"Invalid JSON."}'
        return
    }
    try {
        switch ($request.Path) {
            '/api/devices' {
                Send-UiHttpResponse -Client $Client -Status 200 -ContentType $json -Body (ConvertTo-UiJson (Get-UiState))
            }
            '/api/reload' {
                $script:UiRows = Get-UiRow -Rows (Get-StaleDeviceReport)
                Send-UiHttpResponse -Client $Client -Status 200 -ContentType $json -Body (ConvertTo-UiJson (Get-UiState))
            }
            '/api/action' {
                $result = Invoke-UiAction -Body $body
                $status = $result.status
                $result.Remove('status')
                if (-not $result.ContainsKey('ok')) { $result['ok'] = $false }
                Send-UiHttpResponse -Client $Client -Status $status -ContentType $json -Body (ConvertTo-UiJson $result)
            }
            '/api/stop' {
                $script:UiRunning = $false
                Send-UiHttpResponse -Client $Client -Status 200 -ContentType $json -Body '{"ok":true}'
            }
            default {
                Send-UiHttpResponse -Client $Client -Status 404 -ContentType $json -Body '{"ok":false,"error":"Not found."}'
            }
        }
    }
    catch {
        $failure = Get-StaleDevicesFailure -ErrorRecord $_ -Step 'Devices'
        Write-Warning "UI request failed: $($failure.Message)"
        Send-UiHttpResponse -Client $Client -Status 500 -ContentType $json -Body (ConvertTo-UiJson @{ ok = $false; error = $failure.Message })
    }
}

function Get-UiRow {
    # Rows shown in the UI: all non-active devices (all devices with -IncludeActive).
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Rows
    )

    return , @($Rows | Where-Object { $IncludeActive -or $_.Status -ne 'Active' })
}

function Invoke-StaleDevicesUi {
    # Local web UI on 127.0.0.1 only. Stops with Ctrl+C or the Stop button.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Rows
    )

    $script:UiToken = Get-UiSecret
    $script:UiRows = Get-UiRow -Rows $Rows
    $script:LoadedDevices = @{}
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
    }
    catch {
        throw "Could not listen on 127.0.0.1:$Port ($($_.Exception.Message)). Use -Port to choose another port."
    }
    $url = "http://127.0.0.1:$Port/"
    $script:UiRunning = $true
    Write-Information "UI running at $url (this computer only). Stop with Ctrl+C or the Stop button."
    if ($WhatIfPreference) {
        Write-Information 'UI runs with -WhatIf: devices are not changed.'
    }
    if (-not $NoBrowser) {
        Start-Process $url
    }
    try {
        while ($script:UiRunning) {
            if (-not $listener.Pending()) {
                [System.Threading.Thread]::Sleep(200)
                continue
            }
            $client = $listener.AcceptTcpClient()
            try {
                Invoke-UiRequest -Client $client
            }
            catch {
                Write-Verbose "UI connection error: $($_.Exception.Message)"
                try { Send-UiHttpResponse -Client $client -Status 400 -ContentType 'text/plain; charset=utf-8' -Body 'Bad request' } catch { $client.Close() }
            }
        }
    }
    finally {
        $listener.Stop()
        Write-Information 'UI stopped.'
    }
}

$script:UiHtml = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="csrf-token" content="__TOKEN__">
<title>Cleanup-StaleDevices</title>
<style nonce="__NONCE__">
[hidden]{display:none !important}
body{font-family:Segoe UI,Arial,sans-serif;margin:0;color:#1f2937;background:#f9fafb}
header{background:#1f2937;color:#fff;padding:12px 20px}
header h1{font-size:18px;margin:0}
header .meta{font-size:12px;color:#d1d5db;margin-top:4px}
main{padding:16px 20px}
.badge{display:inline-block;background:#f59e0b;color:#111827;border-radius:4px;padding:1px 6px;font-size:12px;margin-left:8px}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
select,input,button{font:inherit;font-size:13px;padding:4px 8px}
button{cursor:pointer;border:1px solid #9ca3af;border-radius:4px;background:#fff}
button.warn{background:#fef3c7;border-color:#f59e0b}
button.danger{background:#fee2e2;border-color:#dc2626}
button:disabled{opacity:.5;cursor:default}
.msg{font-size:13px;color:#374151;min-height:18px}
.msg.err{color:#b91c1c}
.note{background:#fef3c7;border:1px solid #fcd34d;padding:6px 10px;border-radius:6px;font-size:12px;color:#78350f}
table{border-collapse:collapse;width:100%;font-size:12px;background:#fff}
th,td{border-bottom:1px solid #e5e7eb;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#f3f4f6;position:sticky;top:0}
#log{font-size:12px;max-height:180px;overflow:auto;background:#fff;border:1px solid #e5e7eb;padding:6px;margin-top:8px}
.ok{color:#047857}.bad{color:#b91c1c}.info{color:#374151}
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.4);display:flex;align-items:center;justify-content:center}
#dialog{background:#fff;padding:18px;border-radius:8px;max-width:520px}
</style>
</head>
<body>
<header>
<h1>Cleanup-StaleDevices <span id="whatif" class="badge" hidden>WhatIf: no changes</span> <span id="readonly" class="badge" hidden>Read-only: view only</span></h1>
<div class="meta">Tenant: <span id="tenant"></span> | Signed in: <span id="operator"></span></div>
<div class="meta">Settings: <span id="settings"></span></div>
</header>
<main>
<div class="note">Disable is reversible. Delete cannot be undone and removes BitLocker keys and LAPS passwords. Hybrid joined devices are report only. Every rule is checked again before a device is changed.</div>
<div class="bar">
<select id="fStatus"><option value="*">All statuses</option></select>
<select id="fJoin"><option value="*">All join types</option></select>
<select id="fOs"><option value="*">All OS</option></select>
<input id="fSearch" type="search" placeholder="Search name or reason">
<button id="reloadBtn" type="button">Reload</button>
<button id="stopBtn" type="button">Stop UI</button>
</div>
<div class="bar">
<button id="selAllBtn" type="button">Select shown</button>
<button id="selNoneBtn" type="button">Clear selection</button>
<button id="disableBtn" type="button" class="warn">Disable selected</button>
<button id="deleteBtn" type="button" class="danger">Delete selected</button>
<button id="forceBtn" type="button" class="danger" hidden>Force delete selected</button>
<span id="selCount" class="msg"></span>
</div>
<div class="msg">Summary: <span id="summary"></span> | <span id="limit"></span> | <span id="shown"></span></div>
<div id="status" class="msg"></div>
<table>
<thead><tr><th></th><th>Name</th><th>Status</th><th>Reason</th><th>Join type</th><th>OS</th><th>Enabled</th><th>Last sign-in (UTC)</th><th>Days</th><th>Delete from (UTC)</th><th>Managed</th><th>Autopilot</th><th>BitLocker</th><th>LAPS</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<div id="log" hidden></div>
</main>
<div id="overlay" hidden>
<div id="dialog">
<h2 id="dlgTitle"></h2>
<p id="dlgText"></p>
<p>Type <b id="dlgWord"></b> to confirm:</p>
<input id="dlgInput" type="text" autocomplete="off">
<div class="bar"><button id="dlgCancel" type="button">Cancel</button><button id="dlgOk" type="button" class="danger" disabled>Confirm</button></div>
</div>
</div>
<script nonce="__NONCE__">
(function () {
  'use strict';
  var token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  var state = null, selected = {}, pending = null, maxRows = 2000;
  var words = { disable: 'DISABLE', 'delete': 'DELETE', forcedelete: 'FORCE DELETE' };
  var flags = { disable: 'canDisable', 'delete': 'canDelete', forcedelete: 'canForceDelete' };
  function el(id) { return document.getElementById(id); }
  function setText(node, value) { node.textContent = (value === null || value === undefined) ? '' : String(value); return node; }
  function yesNo(v) { return v === true ? 'Yes' : (v === false ? 'No' : ''); }
  function setStatus(msg, isError) { setText(el('status'), msg); el('status').className = isError ? 'msg err' : 'msg'; }
  function api(path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token }, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().then(function (d) { if (!r.ok) { d.ok = false; } return d; }); });
  }
  function load(path) {
    setStatus('Loading devices...');
    return api(path, {}).then(function (d) {
      if (!d.ok) { setStatus(d.error || 'Error', true); return; }
      state = d; selected = {}; render(); setStatus('');
    }).catch(function (e) { setStatus('Request failed: ' + e.message, true); });
  }
  function unique(key) {
    var seen = {}, out = [];
    state.devices.forEach(function (d) { var v = d[key] || ''; if (!seen[v]) { seen[v] = true; out.push(v); } });
    return out.sort();
  }
  function fill(id, values) {
    var sel = el(id), cur = sel.value;
    while (sel.options.length > 1) { sel.remove(1); }
    values.forEach(function (v) { var o = document.createElement('option'); o.value = v; o.textContent = v === '' ? '(empty)' : v; sel.appendChild(o); });
    sel.value = values.indexOf(cur) >= 0 ? cur : '*';
  }
  function render() {
    setText(el('tenant'), state.tenant + ' (' + state.tenantId + ')');
    setText(el('operator'), state.operator);
    setText(el('settings'), state.settings);
    setText(el('summary'), state.summary);
    setText(el('limit'), state.actionsUsed + ' of ' + state.maxDevices + ' device actions used');
    el('whatif').hidden = !state.whatIf;
    el('forceBtn').hidden = !state.forceDelete;
    el('readonly').hidden = !state.readOnly;
    ['selAllBtn', 'selNoneBtn', 'disableBtn', 'deleteBtn'].forEach(function (id) { el(id).hidden = state.readOnly; });
    if (state.readOnly) { selected = {}; }
    fill('fStatus', unique('status')); fill('fJoin', unique('joinType')); fill('fOs', unique('os'));
    renderRows();
  }
  function matches(d) {
    var s = el('fStatus').value, j = el('fJoin').value, o = el('fOs').value, q = el('fSearch').value.toLowerCase();
    if (s !== '*' && d.status !== s) { return false; }
    if (j !== '*' && (d.joinType || '') !== j) { return false; }
    if (o !== '*' && (d.os || '') !== o) { return false; }
    if (q && ((d.name || '') + ' ' + (d.reason || '')).toLowerCase().indexOf(q) < 0) { return false; }
    return true;
  }
  function shownDevices() { return state ? state.devices.filter(matches) : []; }
  function renderRows() {
    var tbody = el('rows');
    while (tbody.firstChild) { tbody.removeChild(tbody.firstChild); }
    var list = shownDevices();
    list.slice(0, maxRows).forEach(function (d) {
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.disabled = state.readOnly || !(d.canDisable || d.canDelete || d.canForceDelete);
      cb.checked = !!selected[d.objectId];
      cb.addEventListener('change', function () { if (cb.checked) { selected[d.objectId] = d; } else { delete selected[d.objectId]; } updateSel(); });
      td.appendChild(cb); tr.appendChild(td);
      [d.name, d.status, d.reason, d.joinType, d.os + (d.osVersion ? ' ' + d.osVersion : ''), yesNo(d.enabled), d.lastSignIn, d.days,
        d.deleteFrom, yesNo(d.managed), yesNo(d.autopilot), d.bitLocker, d.laps].forEach(function (v) {
        tr.appendChild(setText(document.createElement('td'), v));
      });
      tbody.appendChild(tr);
    });
    setText(el('shown'), list.length > maxRows ? ('first ' + maxRows + ' of ' + list.length + ' shown (use filters)') : (list.length + ' shown'));
    updateSel();
  }
  function selectedFor(action) {
    return Object.keys(selected).map(function (k) { return selected[k]; }).filter(function (d) { return d[flags[action]]; });
  }
  function updateSel() {
    var n = Object.keys(selected).length;
    setText(el('selCount'), n + ' selected');
    el('disableBtn').disabled = selectedFor('disable').length === 0;
    el('deleteBtn').disabled = selectedFor('delete').length === 0;
    el('forceBtn').disabled = selectedFor('forcedelete').length === 0;
  }
  function openConfirm(action) {
    var list = selectedFor(action);
    if (!list.length) { setStatus('None of the selected devices can be used for this action.', true); return; }
    pending = { action: action, ids: list.map(function (d) { return d.objectId; }) };
    var verb = action === 'disable' ? 'Disable' : (action === 'delete' ? 'Delete' : 'Force delete');
    setText(el('dlgTitle'), verb + ' ' + list.length + ' device(s)?');
    setText(el('dlgText'), action === 'disable'
      ? 'Sets accountEnabled = false. This can be undone.'
      : 'Permanently deletes the devices from Entra ID, including BitLocker keys and LAPS passwords. This cannot be undone.'
        + (action === 'forcedelete' ? ' Force delete skips the grace period and also deletes enabled devices.' : ''));
    setText(el('dlgWord'), words[action]);
    el('dlgInput').value = '';
    el('dlgOk').disabled = true;
    el('overlay').hidden = false;
    el('dlgInput').focus();
  }
  function closeConfirm() { el('overlay').hidden = true; }
  function logLine(text, cls) {
    var div = document.createElement('div'); div.className = cls; setText(div, text);
    el('log').appendChild(div); el('log').hidden = false; el('log').scrollTop = el('log').scrollHeight;
  }
  function runAction() {
    var job = pending; pending = null; closeConfirm();
    if (!job) { return; }
    var chunks = [];
    for (var i = 0; i < job.ids.length; i += 20) { chunks.push(job.ids.slice(i, i + 20)); }
    logLine('Starting ' + job.action + ' on ' + job.ids.length + ' device(s)...', 'info');
    var p = Promise.resolve(true);
    chunks.forEach(function (ids) {
      p = p.then(function (go) {
        if (!go) { return false; }
        return api('/api/action', { action: job.action, ids: ids, confirm: words[job.action] }).then(function (d) {
          if (!d.ok) { logLine('Stopped: ' + (d.error || 'error'), 'bad'); return false; }
          d.results.forEach(function (r) {
            logLine(r.result + ': ' + (r.name || r.objectId) + (r.detail ? ' - ' + r.detail : ''), r.result === 'Success' || r.result === 'WhatIf' ? 'ok' : 'bad');
          });
          return true;
        });
      });
    });
    p.then(function () { logLine('Done. Reloading...', 'info'); return load('/api/reload'); })
     .catch(function (e) { logLine('Request failed: ' + e.message, 'bad'); });
  }
  ['fStatus', 'fJoin', 'fOs'].forEach(function (id) { el(id).addEventListener('change', renderRows); });
  var timer = null;
  el('fSearch').addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(renderRows, 200); });
  el('reloadBtn').addEventListener('click', function () { load('/api/reload'); });
  el('stopBtn').addEventListener('click', function () { api('/api/stop', {}).then(function () { setStatus('UI stopped. You can close this tab.'); }); });
  el('selAllBtn').addEventListener('click', function () { shownDevices().slice(0, maxRows).forEach(function (d) { if (d.canDisable || d.canDelete || d.canForceDelete) { selected[d.objectId] = d; } }); renderRows(); });
  el('selNoneBtn').addEventListener('click', function () { selected = {}; renderRows(); });
  el('disableBtn').addEventListener('click', function () { openConfirm('disable'); });
  el('deleteBtn').addEventListener('click', function () { openConfirm('delete'); });
  el('forceBtn').addEventListener('click', function () { openConfirm('forcedelete'); });
  el('dlgCancel').addEventListener('click', function () { pending = null; closeConfirm(); });
  el('dlgInput').addEventListener('input', function () { el('dlgOk').disabled = !pending || el('dlgInput').value !== words[pending.action]; });
  el('dlgOk').addEventListener('click', runAction);
  load('/api/devices');
})();
</script>
</body>
</html>
'@

$exitCode = $ExitCodeSuccess
$step = 'Module'
$actionResults = [System.Collections.Generic.List[object]]::new()
try {
    Write-Verbose "Cleanup-StaleDevices version $ScriptVersion"
    if ($ReadOnly -and $Mode -in @('Disable', 'Delete')) {
        $step = 'Other'
        throw "-ReadOnly cannot be used with -Mode $Mode. Use -Mode Report or UI (the report shows CanDisable / CanDelete)."
    }
    if ($script:UserRights -and -not $TenantId) {
        $step = 'Other'
        throw '-AuthMode UserRights (or -ClientId) needs -TenantId so the first-party app signs in to the right tenant.'
    }
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue) -or -not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }

    $step = 'SignIn'
    $script:Tenant = Connect-StaleDevicesGraph -RequiredScopes $RequiredScopes -TenantId $TenantId -ClientId $script:AuthClientId -UseWAM:$UseWAM
    Write-Information "Mode: $Mode. $(Get-StaleDevicesSettingsText)"
    if ($script:UserRights) {
        Write-Information "Signed in with app $script:AuthClientId. Effective access = your Entra roles (Directory.AccessAsUser.All)."
    }
    if ($ReadOnly) {
        Write-Information 'Read-only run: only GET requests are sent, no devices can be changed.'
    }
    if ($script:ProbeKeys) {
        $script:KeySkip.BitLocker = (@(Get-MissingGraphScope -GrantedScopes $script:Tenant.Scopes -RequiredScopes 'BitlockerKey.ReadBasic.All').Count -gt 0)
        $script:KeySkip.Laps = (@(Get-MissingGraphScope -GrantedScopes $script:Tenant.Scopes -RequiredScopes 'DeviceLocalCredential.ReadBasic.All').Count -gt 0)
        $skipped = @($KeyScopes | Where-Object { ($_ -like 'Bitlocker*' -and $script:KeySkip.BitLocker) -or ($_ -like 'DeviceLocal*' -and $script:KeySkip.Laps) })
        if ($skipped.Count -gt 0) {
            $hint = if ($script:UserRights) { 'This app has no BitLocker/LAPS scopes; use -AuthMode GraphCli for key status.' } else { 'Admin consent for these scopes adds it.' }
            Write-Warning "The session does not have $($skipped -join ', '), so that BitLocker/LAPS status is Unknown. $hint"
        }
    }
    if ($WhatIfPreference) {
        Write-Information '-WhatIf: no devices are changed.'
    }

    $step = 'Devices'
    $allRows = Get-StaleDeviceReport
    Write-Information "$($allRows.Count) device(s) match the filters. $(Get-StaleDevicesSummary -Rows $allRows)"
    if (@($allRows | Where-Object { $_.BitLocker -eq 'Unknown' -or $_.Laps -eq 'Unknown' }).Count -gt 0 -and -not $AllowKeyLoss) {
        Write-Warning 'BitLocker/LAPS status is Unknown for some devices. Delete is blocked for those devices unless -AllowKeyLoss is used.'
    }
    $report = @($allRows | Where-Object { $IncludeActive -or $_.Status -ne 'Active' })

    if ($OutputPath) {
        Export-StaleDevicesCsv -Report $report -Path $OutputPath -Columns $ReportColumns
        Write-Information "CSV report exported to $OutputPath"
        Write-Warning "The CSV report $OutputPath $SensitiveReportWarning"
    }
    if ($HtmlPath) {
        $htmlFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($HtmlPath)
        [System.IO.File]::WriteAllText($htmlFull, (ConvertTo-StaleDevicesHtml -Rows $report), (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $true))
        Write-Information "HTML report exported to $HtmlPath"
        Write-Warning "The HTML report $HtmlPath $SensitiveReportWarning"
    }

    $step = 'Actions'
    if ($Mode -in @('Disable', 'Delete')) {
        $targets = @()
        if ($Mode -eq 'Disable') {
            $targets = @($allRows | Where-Object { $_.CanDisable } | ForEach-Object { [PSCustomObject]@{ Row = $_; Action = 'Disable' } })
        }
        else {
            $targets = @($allRows | Where-Object { $_.CanDelete -or $_.CanForceDelete } | ForEach-Object {
                    $action = if ($_.CanDelete) { 'Delete' } else { 'ForceDelete' }
                    [PSCustomObject]@{ Row = $_; Action = $action }
                })
        }
        Write-Information "$($targets.Count) device(s) eligible for $Mode."
        if ($targets.Count -gt $MaxDevices) {
            throw "$($targets.Count) devices are eligible, more than -MaxDevices $MaxDevices. No devices have been changed. Narrow the filters or raise -MaxDevices."
        }
        $operations = @{
            Disable     = 'Disable device'
            Delete      = 'Delete device (cannot be undone)'
            ForceDelete = 'FORCE delete device: skips grace period / enabled check (cannot be undone)'
        }
        foreach ($target in $targets) {
            $row = $target.Row
            $label = "$($row.DisplayName) ($($row.ObjectId))"
            if ($PSCmdlet.ShouldProcess($label, $operations[$target.Action])) {
                $entry = Invoke-StaleDeviceAction -ObjectId $row.ObjectId -Action $target.Action -Source $Mode
            }
            elseif ($WhatIfPreference) {
                $entry = Invoke-StaleDeviceAction -ObjectId $row.ObjectId -Action $target.Action -Source $Mode -Simulate
            }
            else {
                $entry = Invoke-StaleDeviceAction -ObjectId $row.ObjectId -Action $target.Action -Source $Mode -Declined
            }
            $actionResults.Add($entry)
            Write-Information "[$($entry.Action)] $($entry.Result) $label - $($entry.Detail)"
            if ($entry.Result -eq 'Failed' -and $script:WorstExit -eq $ExitCodePermission) {
                Write-Warning 'Access denied: stopping. Remaining devices were not processed.'
                break
            }
        }
        $resultSummary = foreach ($result in @('Success', 'WhatIf', 'Blocked', 'Declined', 'Failed')) {
            $count = @($actionResults | Where-Object { $_.Result -eq $result }).Count
            if ($count -gt 0) { "${result}: $count" }
        }
        $resultText = if ($resultSummary) { $resultSummary -join ', ' } else { 'no devices' }
        Write-Information "Done. $resultText"
        if (@($actionResults | Where-Object { $_.Result -eq 'Failed' }).Count -gt 0 -and $script:WorstExit -eq $ExitCodeSuccess) {
            $script:WorstExit = $ExitCodeError
        }
        if ($PassThru -or (-not $OutputPath -and -not $HtmlPath)) {
            Write-Output $actionResults.ToArray()
        }
    }
    elseif ($Mode -eq 'UI') {
        Invoke-StaleDevicesUi -Rows $allRows
    }
    elseif ($PassThru -or (-not $OutputPath -and -not $HtmlPath)) {
        Write-Output $report
    }
}
catch {
    $failure = Get-StaleDevicesFailure -ErrorRecord $_ -Step $step
    $exitCode = $failure.ExitCode
    Write-Error -Message $failure.Message -Category $failure.Category -ErrorId $failure.ErrorId -ErrorAction Continue
}
finally {
    Restore-StaleDevicesWam
}
if ($exitCode -eq $ExitCodeSuccess) {
    $exitCode = $script:WorstExit
}
exit $exitCode

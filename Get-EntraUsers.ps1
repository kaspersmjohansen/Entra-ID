#Requires -Version 5.1

<#
.SYNOPSIS
    Lists Entra ID users with their sync type: Hybrid, CloudOnly or PreviouslySynced.
.DESCRIPTION
    Reads all users from Microsoft Graph (read-only) and classifies each user:
    - Hybrid: onPremisesSyncEnabled is true.
    - PreviouslySynced: not synced now, but on-premises attributes remain (e.g.
      onPremisesImmutableId or onPremisesSecurityIdentifier).
    - CloudOnly: no on-premises attributes.
    Output: objects, CSV and/or HTML report. Timestamps are ISO 8601 UTC.
.PARAMETER UserType
    Sync type to include: Hybrid, CloudOnly, PreviouslySynced or All (default). Alias: -SyncType.
.PARAMETER OutputPath
    CSV export path (UTF-8 with BOM, formula injection protected).
.PARAMETER HtmlPath
    HTML report path (summary cards and filters).
.PARAMETER TenantId
    Tenant ID (GUID) or verified domain name. Reconnects if the current session is another tenant.
.PARAMETER ExcludeGuests
    Leaves out guest users.
.PARAMETER ExcludeDisabled
    Leaves out disabled accounts.
.PARAMETER UseWAM
    Signs in with the Windows Web Account Manager (passkey / FIDO2 in Windows PowerShell 5.1).
.PARAMETER PassThru
    Also returns the objects when -OutputPath or -HtmlPath is used.
.EXAMPLE
    .\Get-EntraUsers.ps1 -HtmlPath C:\Reports\EntraUsers.html
.EXAMPLE
    .\Get-EntraUsers.ps1 -UserType PreviouslySynced -ExcludeGuests -OutputPath C:\Reports\PreviouslySynced.csv
.EXAMPLE
    .\Get-EntraUsers.ps1 -UserType CloudOnly -ExcludeDisabled | Select-Object UserPrincipalName, CreatedDateTime
.NOTES
    Kasper Johansen | Apento | kmj@apento.com
    Version: 1.0.0 (2026-11-23)

    Changelog
    1.0.0 - 2026-11-23 Rewritten: sync type classification, CSV/HTML report, least privilege, exit codes.

    Permission: User.Read.All (Directory.Read.All also accepted). Read-only.
    onPremisesImmutableId alone can also be set on cloud users in federated domains.

    Exit codes
    0 = success, 1 = Graph/other error, 3 = access denied, 4 = sign-in/session error
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [Alias('SyncType')]
    [ValidateSet('Hybrid', 'CloudOnly', 'PreviouslySynced', 'All')]
    [string]$UserType = 'All',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$HtmlPath,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$ExcludeGuests,

    [Parameter()]
    [switch]$ExcludeDisabled,

    [Parameter()]
    [switch]$UseWAM,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.0.0'
# Show information messages unless the caller sets -InformationAction.
if (-not $PSBoundParameters.ContainsKey('InformationAction')) {
    $InformationPreference = 'Continue'
}
# WAM option to restore at the end (set by Enable-EntraUsersWam).
$script:WamRestoreValue = $null
$RequiredScopes = @('User.Read.All')
# Exit codes (2 is not used).
$ExitCodeSuccess = 0
$ExitCodeError = 1
$ExitCodePermission = 3
$ExitCodeSignIn = 4
# On-premises properties are only returned with $select.
$UserSelect = @('id', 'displayName', 'userPrincipalName', 'userType', 'accountEnabled', 'createdDateTime',
    'onPremisesSyncEnabled', 'onPremisesImmutableId', 'onPremisesSecurityIdentifier', 'onPremisesDomainName',
    'onPremisesSamAccountName', 'onPremisesUserPrincipalName', 'onPremisesDistinguishedName',
    'onPremisesLastSyncDateTime')
# CSV column order (header for an empty report).
$ReportColumns = @('UserPrincipalName', 'DisplayName', 'UserType', 'AccountEnabled', 'AccountStatus', 'SyncType',
    'SyncTypeReason', 'OnPremisesSyncEnabled', 'OnPremisesDomainName', 'OnPremisesSamAccountName',
    'OnPremisesLastSyncDateTime', 'CreatedDateTime', 'Id')
$SyncTypeLabels = [ordered]@{ Hybrid = 'Hybrid'; CloudOnly = 'Cloud-only'; PreviouslySynced = 'Previously synced' }
$SyncTypeNote = 'Hybrid: synced now. Previously synced: not synced, on-premises attributes remain. Cloud-only: no on-premises attributes. onPremisesImmutableId alone can also be set on cloud users in federated domains.'
# Max rows shown at a time in the HTML report.
$HtmlPageSize = 1000
$SensitiveReportWarning = 'contains sensitive information about user accounts. Store it securely and delete it when no longer needed.'

function Get-MgGraphAllPage {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri

    while ($nextUri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        if ($response.value) {
            $results.AddRange($response.value)
        }
        $nextUri = $response.'@odata.nextLink'
    }

    return $results
}

function Get-AccountStatus {
    # accountEnabled -> Enabled / Disabled / Unknown ($null).
    param(
        [Parameter()]
        [AllowNull()]
        [object]$AccountEnabled
    )

    if ($AccountEnabled -is [bool]) {
        if ($AccountEnabled) { return 'Enabled' }
        return 'Disabled'
    }
    if ($null -ne $AccountEnabled) {
        $text = ([string]$AccountEnabled).Trim()
        if ($text -eq 'true') { return 'Enabled' }
        if ($text -eq 'false') { return 'Disabled' }
    }
    return 'Unknown'
}

function Get-MissingGraphScope {
    # Returns missing scopes. ReadWrite and higher privileged alternatives count as granted.
    param(
        [Parameter()]
        [AllowNull()]
        [string[]]$GrantedScopes,

        [Parameter(Mandatory)]
        [string[]]$RequiredScopes
    )

    $alternativeScopes = @{
        'User.Read.All' = @('Directory.Read.All', 'Directory.ReadWrite.All')
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

function Enable-EntraUsersWam {
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
        throw "-UseWAM requires Microsoft.Graph.Authentication 2.0.0 or later, found version $foundVersion. Run Update-Module Microsoft.Graph.Authentication. No data has been read."
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

function Restore-EntraUsersWam {
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

function Connect-EntraUsersGraph {
    # Reuses the session if tenant and scopes match, otherwise connects. Returns the tenant.
    param(
        [Parameter(Mandatory)]
        [string[]]$RequiredScopes,

        [Parameter()]
        [string]$TenantId,

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

        if ($TenantId) {
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
            $missingScopes = @(Get-MissingGraphScope -GrantedScopes $context.Scopes -RequiredScopes $RequiredScopes)
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
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        elseif ($context -and $context.TenantId) {
            # Missing scopes only: stay in the same tenant.
            $connectParams['TenantId'] = $context.TenantId
        }
        if ($UseWAM) {
            $null = Enable-EntraUsersWam
        }
        Connect-MgGraph @connectParams | Out-Null

        $context = Get-MgContext
        if (-not $context) {
            throw 'Connect-MgGraph did not establish a Microsoft Graph session.'
        }
        $tenantInfo = $null

        $missingScopes = @(Get-MissingGraphScope -GrantedScopes $context.Scopes -RequiredScopes $RequiredScopes)
        if ($missingScopes.Count -gt 0) {
            Write-Warning "The Microsoft Graph session is missing the scope(s): $($missingScopes -join ', '). Parts of the report may fail."
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
            throw "The Microsoft Graph session belongs to tenant $($context.TenantId), not '$TenantId'. No data has been read."
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
    }
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

function Export-EntraUsersCsv {
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

function Get-EntraUserSyncType {
    # Returns SyncType (Hybrid / PreviouslySynced / CloudOnly) and Reason.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$User
    )

    $syncEnabled = $null
    if ($null -ne $User) {
        $syncEnabled = $User.onPremisesSyncEnabled
    }
    if ($syncEnabled -is [string]) {
        $syncEnabled = switch ($syncEnabled.Trim()) { 'true' { $true } 'false' { $false } default { $null } }
    }
    if ($syncEnabled -eq $true) {
        return [PSCustomObject]@{ SyncType = 'Hybrid'; Reason = 'onPremisesSyncEnabled true' }
    }

    $found = @()
    foreach ($property in @('onPremisesImmutableId', 'onPremisesSecurityIdentifier', 'onPremisesSamAccountName',
            'onPremisesDomainName', 'onPremisesUserPrincipalName', 'onPremisesDistinguishedName', 'onPremisesLastSyncDateTime')) {
        if ($null -ne $User -and -not [string]::IsNullOrWhiteSpace([string]$User.$property)) {
            $found += $property
        }
    }
    $syncText = if ($syncEnabled -eq $false) { 'onPremisesSyncEnabled false' } else { 'onPremisesSyncEnabled empty' }
    if ($found.Count -gt 0) {
        return [PSCustomObject]@{ SyncType = 'PreviouslySynced'; Reason = "$syncText; set: $($found -join ', ')" }
    }
    return [PSCustomObject]@{ SyncType = 'CloudOnly'; Reason = "$syncText; no on-premises attributes" }
}

function Get-EntraUsersFailure {
    # Maps an error to exit code and message.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [ValidateSet('SignIn', 'Users', 'Other')]
        [string]$Step
    )

    $detail = Get-GraphErrorDetail -ErrorRecord $ErrorRecord
    $codeParts = @()
    if ($detail.Code) {
        $codeParts += "Graph error code: $($detail.Code)"
    }
    if ($detail.StatusCode) {
        $codeParts += "HTTP $($detail.StatusCode)"
    }
    $codeText = if ($codeParts.Count -gt 0) { " ($($codeParts -join ', '))" } else { '' }
    $graphMessage = if ($detail.Message) { $detail.Message } else { $ErrorRecord.Exception.Message }
    $isPermission = ($detail.StatusCode -eq 403) -or ([string]$detail.Code -in @('Authorization_RequestDenied', 'Authentication_RequestDenied', 'accessDenied', 'Forbidden'))
    $stepText = switch ($Step) {
        'Users' { 'the users (/users)' }
        'SignIn' { 'Microsoft Graph sign-in' }
        default { 'the report' }
    }

    if ($isPermission) {
        return [PSCustomObject]@{
            ExitCode = $ExitCodePermission
            ErrorId  = 'GraphAccessDenied'
            Category = [System.Management.Automation.ErrorCategory]::PermissionDenied
            Message  = "Access denied reading $stepText$codeText. Requires User.Read.All and, if reading users is restricted, a role such as Global Reader or Directory Readers (app-only: application permission with admin consent). No report was created. Graph message: $graphMessage"
        }
    }
    if ($Step -eq 'SignIn' -or $detail.StatusCode -eq 401) {
        return [PSCustomObject]@{
            ExitCode = $ExitCodeSignIn
            ErrorId  = 'GraphSignInFailed'
            Category = [System.Management.Automation.ErrorCategory]::AuthenticationError
            Message  = "Microsoft Graph sign-in or session check failed$codeText. No data has been read. $($ErrorRecord.Exception.Message)"
        }
    }
    return [PSCustomObject]@{
        ExitCode = $ExitCodeError
        ErrorId  = 'EntraUsersReportFailed'
        Category = [System.Management.Automation.ErrorCategory]::NotSpecified
        Message  = "Failed to create the Entra users report while reading $stepText$codeText. No report was created. $($ErrorRecord.Exception.Message)"
    }
}

function ConvertTo-EntraUsersHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Report,

        [Parameter()]
        [string]$TenantDisplayName,

        [Parameter()]
        [string]$TenantIdValue,

        [Parameter()]
        [string]$FilterText
    )

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $now = [System.DateTimeOffset]::Now
    $generatedOn = $now.ToString("yyyy-MM-dd HH:mm 'UTC'zzz", $invariant)
    $generatedOnUtc = $now.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $invariant)

    $totalUsers = @($Report).Count
    $counts = @{ Hybrid = 0; CloudOnly = 0; PreviouslySynced = 0; Member = 0; Guest = 0; Enabled = 0; Disabled = 0 }
    $domains = New-Object System.Collections.Generic.SortedSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($user in $Report) {
        $counts[[string]$user.SyncType]++
        if ([string]$user.UserType -eq 'Guest') { $counts.Guest++ } else { $counts.Member++ }
        if ($user.AccountStatus -eq 'Enabled') { $counts.Enabled++ } elseif ($user.AccountStatus -eq 'Disabled') { $counts.Disabled++ }
        if ($user.OnPremisesDomainName) { $null = $domains.Add([string]$user.OnPremisesDomainName) }
    }
    $domainOptions = (@($domains) | ForEach-Object { $safeValue = ConvertTo-HtmlSafe ([string]$_).ToLowerInvariant(); "<option value=`"$safeValue`">$(ConvertTo-HtmlSafe $_)</option>" }) -join ''
    $syncOptions = ($SyncTypeLabels.Keys | ForEach-Object { "<option value=`"$_`">$($SyncTypeLabels[$_])</option>" }) -join ''

    # StringBuilder + HtmlEncode for speed in large tenants.
    $builder = New-Object -TypeName System.Text.StringBuilder -ArgumentList (4096 + 900 * $totalUsers)
    $rowIndex = 0
    foreach ($user in $Report) {
        $rowIndex++
        $statusClass = switch ($user.AccountStatus) { 'Enabled' { 'yes' } 'Disabled' { 'no' } default { 'unknown' } }
        $syncClass = 'sync-' + ([string]$user.SyncType).ToLowerInvariant()
        $syncLabel = $SyncTypeLabels[[string]$user.SyncType]
        $cells = @(
            @('', $user.DisplayName),
            @('', $user.UserPrincipalName),
            @('', $user.UserType),
            @($statusClass, $user.AccountStatus),
            @($syncClass, $syncLabel),
            @('reason', $user.SyncTypeReason),
            @('', $user.OnPremisesDomainName),
            @('', $user.OnPremisesSamAccountName),
            @('', $user.OnPremisesLastSyncDateTime),
            @('', $user.CreatedDateTime)
        )
        $null = $builder.Append('        <tr data-sync="').Append([System.Net.WebUtility]::HtmlEncode([string]$user.SyncType))
        $null = $builder.Append('" data-usertype="').Append([System.Net.WebUtility]::HtmlEncode([string]$user.UserType))
        $null = $builder.Append('" data-status="').Append([System.Net.WebUtility]::HtmlEncode([string]$user.AccountStatus))
        $null = $builder.Append('" data-domain="').Append([System.Net.WebUtility]::HtmlEncode(([string]$user.OnPremisesDomainName).ToLowerInvariant()))
        if ($rowIndex -gt $HtmlPageSize) {
            $null = $builder.Append('" hidden>')
        }
        else {
            $null = $builder.Append('">')
        }
        foreach ($cell in $cells) {
            if ($cell[0]) {
                $null = $builder.Append('<td class="').Append($cell[0]).Append('">')
            }
            else {
                $null = $builder.Append('<td>')
            }
            $null = $builder.Append([System.Net.WebUtility]::HtmlEncode([string]$cell[1])).Append('</td>')
        }
        $null = $builder.Append("</tr>`n")
    }
    $rowsHtml = $builder.ToString()
    $noUsersHtml = ''
    if ($totalUsers -eq 0) {
        $noUsersHtml = '<div class="empty" id="noUsers" role="status">No users in this report.</div>'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Entra Users Report</title>
<style>
    :root { --border: #d9dde3; --head: #1f2937; --yes: #1a7f37; --no: #b42318; }
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f7f8fa; }
    h1 { font-size: 20px; margin-bottom: 4px; }
    .meta { color: #6b7280; font-size: 13px; margin-bottom: 12px; }
    .notice { background: #fff4e5; border: 1px solid #f5b971; border-left: 4px solid #b54708; border-radius: 6px; color: #7a2e0e; font-size: 13px; padding: 10px 14px; margin-bottom: 20px; }
    .summary { display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
    .card { background: #fff; border: 1px solid var(--border); border-radius: 6px; padding: 10px 16px; min-width: 140px; }
    .card .num { font-size: 22px; font-weight: 600; }
    .card .label { font-size: 12px; color: #6b7280; }
    .filters { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; background: #fff; border: 1px solid var(--border); border-radius: 6px; padding: 12px; }
    .filters label { font-size: 12px; color: #374151; display: block; margin-bottom: 4px; }
    .filters input, .filters select { padding: 6px 8px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; min-width: 160px; }
    table { border-collapse: collapse; width: 100%; background: #fff; font-size: 13px; }
    th, td { border: 1px solid var(--border); padding: 6px 10px; text-align: left; white-space: nowrap; }
    th { background: var(--head); color: #fff; position: sticky; top: 0; }
    td.yes { color: var(--yes); font-weight: 600; }
    td.no { color: var(--no); font-weight: 600; }
    td.unknown { color: #6b7280; font-style: italic; }
    td.sync-hybrid { color: #1d4ed8; font-weight: 600; }
    td.sync-cloudonly { color: #047857; font-weight: 600; }
    td.sync-previouslysynced { color: #b54708; font-weight: 600; }
    td.reason { color: #6b7280; font-size: 12px; }
    .note { color: #6b7280; font-size: 12px; margin: -12px 0 20px 0; }
    .empty { background: #fff; border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 14px; color: #6b7280; font-size: 14px; }
    .table-wrap { max-height: 70vh; overflow: auto; border: 1px solid var(--border); border-radius: 6px; }
    #rowCount { font-size: 12px; color: #6b7280; margin: 8px 0; }
    tr[hidden] { display: none; }
    .more { margin: 0 0 8px 0; font-size: 12px; color: #6b7280; }
    .more button { font-size: 12px; padding: 4px 10px; border: 1px solid var(--border); border-radius: 4px; background: #fff; cursor: pointer; }
</style>
</head>
<body>

<h1>Entra ID Users Report</h1>
<div class="meta">Tenant $(ConvertTo-HtmlSafe $TenantDisplayName) ($(ConvertTo-HtmlSafe $TenantIdValue)) | Generated <time id="generatedOn" datetime="$generatedOnUtc">$generatedOn ($generatedOnUtc)</time> | Script version $ScriptVersion | <span id="reportFilter">$(ConvertTo-HtmlSafe $FilterText)</span></div>
<div class="notice" id="sensitiveNotice" role="note"><strong>Sensitive report:</strong> store it securely, do not share it unencrypted and delete it when no longer needed.</div>

<div class="summary" id="summaryCards">
    <div class="card"><div class="num" id="cardTotal">$totalUsers</div><div class="label">Users in report</div></div>
    <div class="card"><div class="num" id="cardHybrid">$($counts.Hybrid)</div><div class="label">Hybrid (synced)</div></div>
    <div class="card"><div class="num" id="cardCloudOnly">$($counts.CloudOnly)</div><div class="label">Cloud-only</div></div>
    <div class="card"><div class="num" id="cardPreviouslySynced">$($counts.PreviouslySynced)</div><div class="label">Previously synced</div></div>
    <div class="card"><div class="num" id="cardMembers">$($counts.Member)</div><div class="label">Members</div></div>
    <div class="card"><div class="num" id="cardGuests">$($counts.Guest)</div><div class="label">Guests</div></div>
    <div class="card"><div class="num" id="cardEnabled">$($counts.Enabled)</div><div class="label">Enabled</div></div>
    <div class="card"><div class="num" id="cardDisabled">$($counts.Disabled)</div><div class="label">Disabled</div></div>
</div>
<div class="note" id="syncTypeNote">$(ConvertTo-HtmlSafe $SyncTypeNote)</div>

<div class="filters">
    <div>
        <label for="searchBox">Search name / UPN / SAM account</label>
        <input type="text" id="searchBox" placeholder="Type to search...">
    </div>
    <div>
        <label for="syncFilter">Sync type</label>
        <select id="syncFilter"><option value="">All</option>$syncOptions</select>
    </div>
    <div>
        <label for="userTypeFilter">User type</label>
        <select id="userTypeFilter"><option value="">All</option><option value="Member">Member</option><option value="Guest">Guest</option></select>
    </div>
    <div>
        <label for="statusFilter">Account status</label>
        <select id="statusFilter"><option value="">All</option><option value="Enabled">Enabled</option><option value="Disabled">Disabled</option><option value="Unknown">Unknown</option></select>
    </div>
    <div>
        <label for="domainFilter">On-premises domain</label>
        <select id="domainFilter"><option value="">All</option><option value="__none">(none)</option>$domainOptions</select>
    </div>
</div>

<div id="rowCount" role="status"></div>
<div class="more" id="moreRows" hidden><button type="button" id="showMore">Show $HtmlPageSize more</button> <button type="button" id="showAll">Show all</button> <span class="more-note">At most $HtmlPageSize rows are shown at a time. Ctrl+F only searches shown rows.</span></div>
$noUsersHtml

<div class="table-wrap">
<table id="reportTable">
    <thead>
        <tr>
            <th>Display Name</th>
            <th>User Principal Name</th>
            <th>User Type</th>
            <th>Account Status</th>
            <th title="$(ConvertTo-HtmlSafe $SyncTypeNote)">Sync Type</th>
            <th>Reason</th>
            <th>On-premises Domain</th>
            <th>On-premises SAM Account</th>
            <th title="ISO 8601, UTC">Last Sync (UTC)</th>
            <th title="ISO 8601, UTC">Created (UTC)</th>
        </tr>
    </thead>
    <tbody>
$rowsHtml
    </tbody>
</table>
</div>

<script>
(function () {
    'use strict';
    var searchBox = document.getElementById('searchBox');
    var selectIds = ['syncFilter', 'userTypeFilter', 'statusFilter', 'domainFilter'];
    var selects = {};
    selectIds.forEach(function (id) { selects[id] = document.getElementById(id); });
    var rowCount = document.getElementById('rowCount');
    var moreRows = document.getElementById('moreRows');
    var tbody = document.querySelector('#reportTable tbody');
    var rowElements = tbody ? tbody.rows : [];
    var total = rowElements.length;
    var pageSize = $HtmlPageSize;
    var limit = pageSize;

    // Cache row values once.
    var data = new Array(total);
    for (var i = 0; i < total; i++) {
        var row = rowElements[i];
        var d = row.dataset;
        data[i] = {
            row: row,
            hidden: row.hidden,
            text: (row.cells[0].textContent + ' ' + row.cells[1].textContent + ' ' + row.cells[7].textContent).toLowerCase(),
            sync: d.sync, usertype: d.usertype, status: d.status, domain: d.domain || ''
        };
    }

    function applyFilters(keepLimit) {
        if (keepLimit !== true) { limit = pageSize; }
        var search = searchBox.value.toLowerCase();
        var sync = selects.syncFilter.value;
        var userType = selects.userTypeFilter.value;
        var status = selects.statusFilter.value;
        var domain = selects.domainFilter.value;
        var matched = 0;
        var shown = 0;

        // One pass; only rows whose visibility changes are touched.
        for (var i = 0; i < total; i++) {
            var item = data[i];
            var matches = !(
                (search && item.text.indexOf(search) === -1) ||
                (sync && item.sync !== sync) ||
                (userType && item.usertype !== userType) ||
                (status && item.status !== status) ||
                (domain === '__none' && item.domain !== '') ||
                (domain && domain !== '__none' && item.domain !== domain)
            );
            var show = false;
            if (matches) {
                matched++;
                if (shown < limit) { show = true; shown++; }
            }
            if (item.hidden === show) {
                item.hidden = !show;
                item.row.hidden = !show;
            }
        }

        if (shown < matched) {
            rowCount.textContent = matched + ' of ' + total + ' users match, first ' + shown + ' shown';
        }
        else {
            rowCount.textContent = matched + ' of ' + total + ' users shown';
        }
        moreRows.hidden = (shown >= matched);
    }

    document.getElementById('showMore').addEventListener('click', function () { limit += pageSize; applyFilters(true); });
    document.getElementById('showAll').addEventListener('click', function () { limit = total; applyFilters(true); });

    // Debounce typing; dropdowns apply immediately.
    var timer = null;
    function applyNow() {
        if (timer !== null) { clearTimeout(timer); timer = null; }
        applyFilters();
    }
    function applyDebounced() {
        if (timer !== null) { clearTimeout(timer); }
        timer = setTimeout(applyNow, total > 2000 ? 250 : 100);
    }
    searchBox.addEventListener('input', applyDebounced);
    searchBox.addEventListener('change', applyNow);
    selectIds.forEach(function (id) { selects[id].addEventListener('change', applyNow); });

    applyFilters();
})();
</script>

</body>
</html>
"@

    return $html
}

$exitCode = $ExitCodeSuccess
$step = 'SignIn'
try {
    $tenant = Connect-EntraUsersGraph -RequiredScopes $RequiredScopes -TenantId $TenantId -UseWAM:$UseWAM

    Write-Verbose "Get-EntraUsers version $ScriptVersion"
    $step = 'Users'
    Write-Information 'Reading users from Microsoft Graph...'
    $usersUri = 'https://graph.microsoft.com/v1.0/users?$select=' + ($UserSelect -join ',') + '&$top=999'
    $graphUsers = Get-MgGraphAllPage -Uri $usersUri
    $step = 'Other'

    $report = foreach ($user in $graphUsers) {
        $classification = Get-EntraUserSyncType -User $user
        [PSCustomObject]@{
            UserPrincipalName          = $user.userPrincipalName
            DisplayName                = $user.displayName
            UserType                   = $user.userType
            AccountEnabled             = $user.accountEnabled
            AccountStatus              = Get-AccountStatus -AccountEnabled $user.accountEnabled
            SyncType                   = $classification.SyncType
            SyncTypeReason             = $classification.Reason
            OnPremisesSyncEnabled      = $user.onPremisesSyncEnabled
            OnPremisesDomainName       = $user.onPremisesDomainName
            OnPremisesSamAccountName   = $user.onPremisesSamAccountName
            OnPremisesLastSyncDateTime = ConvertTo-UtcTimestamp -Value $user.onPremisesLastSyncDateTime
            CreatedDateTime            = ConvertTo-UtcTimestamp -Value $user.createdDateTime
            Id                         = $user.id
        }
    }
    $report = @($report | Sort-Object -Property DisplayName, UserPrincipalName)
    $readCount = $report.Count

    $filterParts = @()
    if ($UserType -ne 'All') {
        $report = @($report | Where-Object { $_.SyncType -eq $UserType })
        $filterParts += "Sync type: $($SyncTypeLabels[$UserType])"
    }
    if ($ExcludeGuests) {
        $report = @($report | Where-Object { [string]$_.UserType -ne 'Guest' })
        $filterParts += 'guests excluded'
    }
    if ($ExcludeDisabled) {
        $report = @($report | Where-Object { $_.AccountStatus -ne 'Disabled' })
        $filterParts += 'disabled accounts excluded'
    }
    $filterText = if ($filterParts.Count -gt 0) { 'Filter: ' + ($filterParts -join ', ') } else { 'Filter: none (all users)' }
    Write-Verbose "$readCount user(s) read, $($report.Count) after filters. $filterText"

    $summary = foreach ($key in $SyncTypeLabels.Keys) {
        "$($SyncTypeLabels[$key]): $(@($report | Where-Object { $_.SyncType -eq $key }).Count)"
    }
    Write-Information "Report contains $($report.Count) user(s) ($($summary -join ', ')). $filterText."

    if ($OutputPath) {
        if ($PSCmdlet.ShouldProcess($OutputPath, 'Export Entra users report as CSV')) {
            Export-EntraUsersCsv -Report $report -Path $OutputPath -Columns $ReportColumns
            if ($report.Count -eq 0) {
                Write-Warning "The report contains no users. The CSV report $OutputPath contains the header row only."
            }
            Write-Information "CSV report exported to $OutputPath"
            Write-Warning "The CSV report $OutputPath $SensitiveReportWarning"
        }
    }

    if ($HtmlPath) {
        if ($PSCmdlet.ShouldProcess($HtmlPath, 'Export Entra users report as HTML')) {
            $htmlContent = ConvertTo-EntraUsersHtml -Report $report -TenantDisplayName $tenant.DisplayName -TenantIdValue $tenant.Id -FilterText $filterText
            Set-Content -Path $HtmlPath -Value $htmlContent -Encoding UTF8
            Write-Information "HTML report exported to $HtmlPath"
            if ($report.Count -eq 0) {
                Write-Warning "The report contains no users. The HTML report $HtmlPath has no rows."
            }
            Write-Warning "The HTML report $HtmlPath $SensitiveReportWarning"
        }
    }

    if ($PassThru -or (-not $OutputPath -and -not $HtmlPath)) {
        Write-Output $report
    }
}
catch {
    $failure = Get-EntraUsersFailure -ErrorRecord $_ -Step $step
    $exitCode = $failure.ExitCode
    Write-Error -Message $failure.Message -Category $failure.Category -ErrorId $failure.ErrorId -ErrorAction Continue
}
finally {
    Restore-EntraUsersWam
}
exit $exitCode

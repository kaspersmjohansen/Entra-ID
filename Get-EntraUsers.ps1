#Requires -Version 5.1

<#
.SYNOPSIS
    Lists all Entra ID users and identifies each user's sync type: Hybrid, Cloud-only or Previously
    synced, using Microsoft Graph.
.DESCRIPTION
    Reads all users from Microsoft Graph (GET /users with $select and paging, read-only) and
    classifies each user by sync type:
    - Hybrid: synced from on-premises Active Directory (onPremisesSyncEnabled is true), by
      Microsoft Entra Connect Sync or Cloud Sync.
    - PreviouslySynced: not synced now (onPremisesSyncEnabled is false or empty), but the user still
      has on-premises attributes from an earlier sync: onPremisesImmutableId or
      onPremisesSecurityIdentifier, or other on-premises values (onPremisesSamAccountName,
      onPremisesDomainName, onPremisesUserPrincipalName, onPremisesDistinguishedName,
      onPremisesLastSyncDateTime). Typical causes: the user was moved out of the sync scope and
      restored, sync was disabled for the tenant, or the AD account was soft-matched/converted
      to cloud.
    - CloudOnly: created in Entra ID, no on-premises attributes.
    The SyncTypeReason column shows which attributes led to the classification.
    The report also shows user type (Member/Guest), account status, UPN, display name,
    onPremisesDomainName, onPremisesSamAccountName, onPremisesLastSyncDateTime and
    createdDateTime. Results can be exported to CSV and to an interactive HTML report with
    summary cards per sync type and client side filtering, and are written to the pipeline.
    Only read-only Graph calls (GET) are used. Required permission: User.Read.All (least
    privileged permission that returns the on-premises properties; User.ReadBasic.All does not).
    An existing Microsoft Graph session is only reused if it belongs to the requested tenant and has
    the required scope; otherwise the script connects again. The connected tenant name and id are
    always shown before any data is read.
    Use -UseWAM to sign in with the Windows Web Account Manager (WAM) broker, e.g. when a passkey /
    FIDO2 sign-in fails in the Windows PowerShell 5.1 sign-in window.
    The exported reports contain sensitive information (e.g. account names, on-premises domain and
    sign-in names, disabled accounts). Store them in a secure location with restricted access and
    delete them when no longer needed.
    If a Graph call fails, a clear error is shown and the script ends with a non-zero exit code (see
    Exit codes in the notes); no partial report is written.
    Progress and status messages are written to the information stream (Write-Information) and are
    shown by default; hide them with -InformationAction SilentlyContinue. Details are written with
    Write-Verbose (-Verbose) and warnings with Write-Warning.
    Timestamps (OnPremisesLastSyncDateTime, CreatedDateTime) are ISO 8601 UTC, e.g.
    2026-11-01T10:00:00Z. The HTML report shows the generation time in local time with its UTC
    offset and in UTC.
.PARAMETER UserType
    Sync type to include: Hybrid, CloudOnly, PreviouslySynced or All (default). Alias: -SyncType.
    Note: this is the sync type, not the Graph userType (Member/Guest); use -ExcludeGuests to leave
    out guests.
.PARAMETER OutputPath
    Optional path to export the results as CSV. If omitted, no CSV is created. The CSV is written
    as UTF-8 with BOM (in Windows PowerShell 5.1 and PowerShell 7), so Excel shows characters
    such as ae, oe and aa (Danish letters) correctly. To protect against CSV formula injection,
    text values starting with =, +, -, @, tab or carriage return are prefixed with a single quote
    (') in the CSV only; the output objects and the HTML report keep the original values.
.PARAMETER HtmlPath
    Optional path to export the results as an interactive HTML report with summary cards per sync
    type and client side filtering (search, sync type, user type, account status, on-premises
    domain). All values are HTML encoded and the report has a Content-Security-Policy. Filtering is
    done in one pass over cached row data, text search is debounced, and at most 1000 matching rows
    are shown at a time ('Show 1000 more' / 'Show all' buttons), so the report stays fast for large
    tenants.
.PARAMETER TenantId
    Optional tenant to connect to, as a tenant ID (GUID) or a verified domain name
    (e.g. contoso.onmicrosoft.com). If an existing Graph session belongs to another tenant, the
    script connects to this tenant instead. A domain name is compared against the verified domains
    of the connected tenant.
.PARAMETER ExcludeGuests
    Leaves guest users (userType Guest) out of the report rows, CSV, HTML and output.
.PARAMETER ExcludeDisabled
    Leaves disabled accounts (accountEnabled false) out of the report rows, CSV, HTML and output.
.PARAMETER UseWAM
    Signs in with the Windows Web Account Manager (WAM) broker instead of the embedded/browser
    sign-in window. WAM uses the Windows sign-in dialog, which supports passkeys and FIDO2 security
    keys (including passkeys in Microsoft Authenticator and Windows Hello). Use it when a passkey or
    FIDO2 sign-in with an admin account does not work in Windows PowerShell 5.1, where the older
    embedded sign-in window may not support passkeys.
    Behaviour depends on the installed Microsoft.Graph.Authentication module:
    - 2.0.0 - 2.33.x: Set-MgGraphOption -EnableLoginByWAM $true is called right before
      Connect-MgGraph (also when the script reconnects because of the tenant or scope check). This
      option is persisted per user (~/.mg/mg.graphoptions.json), so the previous value is restored
      when the script ends.
    - 2.34.0 and later: WAM is already the default on Windows and is always used with the default
      Microsoft Graph PowerShell app, so -UseWAM changes nothing (an informational note is shown).
    - Older than 2.0.0 (no Set-MgGraphOption -EnableLoginByWAM): the script stops with an error
      before signing in. Update with Update-Module Microsoft.Graph.Authentication.
    On Windows a warning recommending Update-Module Microsoft.Graph.Authentication is always shown
    (with or without -UseWAM) when the module used is older than 2.34.0.
    If several versions of Microsoft.Graph.Authentication are installed, an older version may be
    loaded, e.g. because another Microsoft.Graph module already loaded it in the session. Check
    the loaded version with Get-Module Microsoft.Graph.Authentication and the installed versions
    with Get-Module Microsoft.Graph.Authentication -ListAvailable; start a new PowerShell session
    (or Import-Module Microsoft.Graph.Authentication -RequiredVersion <version>) to load the
    newest version, and remove old versions with Uninstall-Module if needed.
    WAM is only available on Windows; on other platforms -UseWAM is ignored with a warning. If an
    existing session is reused or the session is app-only, no sign-in happens and -UseWAM has no
    effect (verbose note).
.PARAMETER PassThru
    Writes the report objects to the pipeline also when -OutputPath or -HtmlPath is used. Without
    -OutputPath and -HtmlPath the objects are always written to the pipeline.
.EXAMPLE
    .\Get-EntraUsers.ps1 -HtmlPath C:\Reports\EntraUsers.html
    Writes an HTML report of all users with their sync type.
.EXAMPLE
    .\Get-EntraUsers.ps1 -UserType PreviouslySynced -ExcludeGuests -OutputPath C:\Reports\PreviouslySynced.csv
    Exports members that were synced from AD earlier but are no longer synced.
.EXAMPLE
    .\Get-EntraUsers.ps1 -UserType CloudOnly -ExcludeDisabled | Select-Object UserPrincipalName, CreatedDateTime
    Lists enabled cloud-only users in the console.
.EXAMPLE
    $users = .\Get-EntraUsers.ps1 -TenantId contoso.onmicrosoft.com -HtmlPath C:\Reports\EntraUsers.html -PassThru -UseWAM
    Signs in with WAM, writes the HTML report and returns the objects.
.EXAMPLE
    .\Get-EntraUsers.ps1 -OutputPath C:\Reports\EntraUsers.csv
    if ($LASTEXITCODE -ne 0) { Write-Warning "Report failed with exit code $LASTEXITCODE" }
    Checks the exit code, e.g. in a scheduled task (powershell.exe -File returns the same code).
.OUTPUTS
    PSCustomObject, one per user (see the CSV columns). Written to the pipeline when neither
    -OutputPath nor -HtmlPath is used, or when -PassThru is used.
.NOTES
    Kasper Johansen | Apento
    kmj@apento.com

    Version: 1.0.0
    Updated: 2026-11-23

    Changelog
    1.0.0 - 2026-11-23
        Rewritten from scratch (replaces the 0.9.0 beta) in the style of
        Get-EntraUserAuthMethods.ps1 1.6.0. Classifies users as Hybrid, CloudOnly or
        PreviouslySynced from onPremisesSyncEnabled and the on-premises attributes, with the
        reason per user. Fixes from the 0.9.0 review: no undefined variables or dead / commented
        out code, and hybrid users are no longer counted as Entra-only (the old filter
        'OnPremisesSyncEnabled ne true' was not evaluated as intended). Read-only, least privilege
        (User.Read.All), tenant and scope check with reconnect, -TenantId as GUID or domain,
        -UseWAM, clear errors with exit codes, CSV (UTF-8 BOM, formula injection protection), HTML
        report (HTML encoded, CSP, sensitive data notice, cards per sync type, fast filtering and
        paging), -UserType, -ExcludeGuests, -ExcludeDisabled, -PassThru, Write-Information, UTC
        timestamps. The sign-in activity columns, -UserAge, -ListUser and -DisabledUsers of the
        beta are not part of 1.0.0 (sign-in activity needs AuditLog.Read.All and Entra ID P1).
    0.9.0
        Beta.

    Required Graph permission (delegated or application): User.Read.All
    User.Read.All grants read access to all users including the on-premises properties. An
    existing session with Directory.Read.All, User.ReadWrite.All or Directory.ReadWrite.All is
    accepted too. With delegated sign-in, member users can read users by default; if the tenant
    restricts this, use a role such as Global Reader or Directory Readers.
    No write, update or delete calls are made anywhere in this script.

    Caveats
    onPremisesImmutableId can also be set on cloud users in a federated domain (e.g. for AD FS);
    such users are reported as PreviouslySynced with the reason 'onPremisesImmutableId set'.
    onPremisesSecurityIdentifier is the strongest sign of an earlier AD sync.

    Exit codes
    0 - Success (also when the report contains no users).
    1 - Microsoft Graph or other error (e.g. throttling, network, export failure).
    2 - Not used by this script (reserved, same codes as Get-EntraUserAuthMethods.ps1).
    3 - Access denied (HTTP 403): the signed-in account or app is missing a required role or
        permission.
    4 - Sign-in or session error: Connect-MgGraph failed, the session belongs to another tenant,
        an app-only session is missing permissions, or the Microsoft.Graph.Authentication module
        is too old for -UseWAM.
    The error message shows the Graph error code and HTTP status when available.
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
# Information messages (progress and status) are shown by default. A caller can hide them with
# -InformationAction SilentlyContinue.
if (-not $PSBoundParameters.ContainsKey('InformationAction')) {
    $InformationPreference = 'Continue'
}
# Previous persisted WAM option (Get-MgGraphOption EnableWAMForMSGraph) to restore at the end, set by
# Enable-EntraUsersWam when it changes the option.
$script:WamRestoreValue = $null
$RequiredScopes = @('User.Read.All')
# Exit codes (documented in the notes). 2 (license) is not used by this script.
$ExitCodeSuccess = 0
$ExitCodeError = 1
$ExitCodePermission = 3
$ExitCodeSignIn = 4
# Properties read from Graph (GET /users?$select=...). On-premises properties require $select.
$UserSelect = @('id', 'displayName', 'userPrincipalName', 'userType', 'accountEnabled', 'createdDateTime',
    'onPremisesSyncEnabled', 'onPremisesImmutableId', 'onPremisesSecurityIdentifier', 'onPremisesDomainName',
    'onPremisesSamAccountName', 'onPremisesUserPrincipalName', 'onPremisesDistinguishedName',
    'onPremisesLastSyncDateTime')
# Report columns in CSV order. Used to write the CSV header when the report has no rows.
$ReportColumns = @('UserPrincipalName', 'DisplayName', 'UserType', 'AccountEnabled', 'AccountStatus', 'SyncType',
    'SyncTypeReason', 'OnPremisesSyncEnabled', 'OnPremisesDomainName', 'OnPremisesSamAccountName',
    'OnPremisesLastSyncDateTime', 'CreatedDateTime', 'Id')
# Display names for the sync types (HTML report and messages).
$SyncTypeLabels = [ordered]@{ Hybrid = 'Hybrid'; CloudOnly = 'Cloud-only'; PreviouslySynced = 'Previously synced' }
$SyncTypeNote = 'Hybrid: synced from on-premises AD now (onPremisesSyncEnabled true). Previously synced: not synced now, but on-premises attributes from an earlier sync remain (e.g. onPremisesImmutableId or onPremisesSecurityIdentifier). Cloud-only: no on-premises attributes. onPremisesImmutableId alone can also be set on cloud users in federated domains.'
# Maximum number of matching rows the HTML report shows at a time ('Show more' / 'Show all').
$HtmlPageSize = 1000
$SensitiveReportWarning = 'contains sensitive information about user accounts (e.g. on-premises sign-in names and disabled accounts). Store it in a secure location with restricted access and delete it when it is no longer needed.'

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
    # Converts accountEnabled to Enabled / Disabled / Unknown. $null (user not found in the users
    # lookup) is Unknown, not Disabled.
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
    # Returns the required scopes that are not present in the granted scopes. A ReadWrite scope
    # (e.g. User.ReadWrite.All) is accepted in place of the matching Read scope (User.Read.All).
    # Higher privileged scopes listed in $alternativeScopes are accepted too, so an existing
    # session with e.g. Directory.Read.All does not force a reconnect.
    param(
        [Parameter()]
        [AllowNull()]
        [string[]]$GrantedScopes,

        [Parameter(Mandatory)]
        [string[]]$RequiredScopes
    )

    # Higher privileged scopes that also grant the required scope (Microsoft Learn permissions
    # table for GET /users).
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
    # Reads the connected tenant's display name, id and verified domains (read-only GET).
    # Returns $null if the organization cannot be read.
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
    # Returns $true if the Graph context belongs to the requested tenant, $false if it does not,
    # or $null if it cannot be determined (domain name given and verified domains not readable).
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
    # True on Windows (Windows PowerShell 5.1 and PowerShell 7 on Windows).
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Get-GraphAuthModuleVersion {
    # Version of the Microsoft.Graph.Authentication module that provides Connect-MgGraph (the
    # loaded module, or the one PowerShell would auto-load). $null if it is not found.
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
    # On Windows, warns when Microsoft.Graph.Authentication is older than 2.34.0, where sign-in by
    # the Web Account Manager (WAM) is not the default and passkey / FIDO2 sign-in may fail.
    # Shown with or without -UseWAM. Returns $true if the warning was shown.
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Test-WindowsPlatform)) {
        return $false
    }
    $moduleVersion = Get-GraphAuthModuleVersion
    if ($moduleVersion -and $moduleVersion -lt [version]'2.34.0') {
        Write-Warning "Microsoft.Graph.Authentication $moduleVersion is used. Update to 2.34.0 or later with Update-Module Microsoft.Graph.Authentication: from 2.34.0 sign-in uses the Web Account Manager (WAM) by default on Windows, which supports passkey / FIDO2 sign-in. If a newer version is installed, an older one may still be loaded; check with Get-Module Microsoft.Graph.Authentication (loaded) and Get-Module Microsoft.Graph.Authentication -ListAvailable (installed), or start a new PowerShell session."
        return $true
    }
    return $false
}

function Enable-EntraUsersWam {
    # Enables sign-in with the Windows Web Account Manager (WAM) before Connect-MgGraph.
    # Set-MgGraphOption persists the option per user, so the previous value is stored in
    # $script:WamRestoreValue and restored by Restore-EntraUsersWam when the script ends.
    # Returns a short status: NotWindows, Default, AlreadyEnabled or Enabled. Throws if the
    # Microsoft.Graph.Authentication module is too old.
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not (Test-WindowsPlatform)) {
        Write-Warning '-UseWAM is ignored: the Web Account Manager (WAM) is only available on Windows. The normal interactive sign-in is used.'
        return 'NotWindows'
    }

    $moduleVersion = Get-GraphAuthModuleVersion

    if ($moduleVersion -and $moduleVersion -ge [version]'2.34.0') {
        Write-Information "-UseWAM: Microsoft.Graph.Authentication $moduleVersion already uses the Web Account Manager (WAM) by default on Windows. No setting was changed."
        return 'Default'
    }

    $setOptionCommand = Get-Command -Name Set-MgGraphOption -ErrorAction SilentlyContinue
    if (-not $setOptionCommand -or -not $setOptionCommand.Parameters.ContainsKey('EnableLoginByWAM')) {
        $foundVersion = if ($moduleVersion) { [string]$moduleVersion } else { 'not found' }
        throw "-UseWAM requires Microsoft.Graph.Authentication 2.0.0 or later (Set-MgGraphOption -EnableLoginByWAM), found version $foundVersion. Update the module with Update-Module Microsoft.Graph.Authentication or run the script without -UseWAM. No data has been read."
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
    Write-Information 'Web Account Manager (WAM) sign-in enabled for this run. The previous setting is restored when the script ends.'
    return 'Enabled'
}

function Restore-EntraUsersWam {
    # Restores the persisted WAM option changed by Enable-EntraUsersWam.
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
    # Extracts the HTTP status code, Graph error code and message from an error record thrown by
    # Invoke-MgGraphRequest (or any other error). Missing values are $null.
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
    # Reuses an existing Graph session only if it belongs to the requested tenant and has the
    # required scopes. Otherwise connects with the required scopes (and -TenantId). Shows and
    # returns the connected tenant.
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
                    throw "Cannot reuse the app-only Microsoft Graph session: $reason. Connect the app to the correct tenant with Connect-MgGraph -TenantId and run the script again."
                }
            }
        }

        if (-not $reason) {
            $missingScopes = @(Get-MissingGraphScope -GrantedScopes $context.Scopes -RequiredScopes $RequiredScopes)
            if ($missingScopes.Count -gt 0) {
                if ($isAppOnly) {
                    throw "The app-only Microsoft Graph session is missing the application permission(s): $($missingScopes -join ', '). Grant them (with admin consent) to the app registration and run the script again."
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
            # Reconnecting only because of missing scopes: stay in the same tenant.
            $connectParams['TenantId'] = $context.TenantId
        }
        if ($UseWAM) {
            # Applies to every Connect-MgGraph call in this script, including the reconnect after a
            # failed tenant or scope check.
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
            Write-Warning "Could not verify that tenant $($context.TenantId) has the verified domain '$TenantId', because the tenant's verified domains could not be read."
        }
    }

    if ($tenantInfo) {
        $tenantDisplayName = $tenantInfo.DisplayName
        $tenantIdValue = $tenantInfo.Id
    }
    else {
        $tenantDisplayName = '(name not available)'
        $tenantIdValue = [string]$context.TenantId
        Write-Warning "The tenant name could not be read from /organization. Verify that tenant $tenantIdValue is the expected tenant."
    }
    Write-Information "Connected to tenant: $tenantDisplayName ($tenantIdValue) as $($context.Account)"

    return [PSCustomObject]@{
        DisplayName = $tenantDisplayName
        Id          = $tenantIdValue
    }
}

function ConvertTo-UtcTimestamp {
    # Normalizes a timestamp (DateTime, DateTimeOffset or ISO 8601 string from Graph) to ISO 8601
    # UTC, e.g. 2026-11-01T10:00:00Z. A DateTime without kind is treated as UTC (Graph returns UTC).
    # Empty values return ''. Values that cannot be parsed are returned unchanged.
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
    # Returns a copy of a report row for CSV export where text values starting with =, +, -, @,
    # tab or carriage return are prefixed with a single quote, so spreadsheet applications do not
    # evaluate them as formulas (CSV formula injection). Other values are unchanged.
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
    # Writes the report as CSV, UTF-8 with BOM (same result in Windows PowerShell 5.1 and
    # PowerShell 7, so Excel detects the encoding), with CSV formula injection protection. An
    # empty report writes the header row only.
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
    # HTML encodes a value so it can be safely inserted into HTML element content and quoted
    # attribute values. Null returns an empty string.
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
    # Classifies a Graph user object as Hybrid, PreviouslySynced or CloudOnly and returns the type
    # and the reason (which on-premises values were found).
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
    # Classifies an error from a script step into an exit code and a clear message.
    # Steps: SignIn, Users, Other.
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
            Message  = "Access denied reading $stepText$codeText. The signed-in account (or app) needs the User.Read.All permission and, if the tenant restricts reading users, a Microsoft Entra role such as Global Reader or Directory Readers. Guest accounts cannot list users. For app-only sessions grant the application permission with admin consent. No report was created. Graph message: $graphMessage"
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
    # Builds the HTML report. All user values are HTML encoded.
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

    # Rows are built with a StringBuilder and HtmlEncode directly (same encoding as
    # ConvertTo-HtmlSafe) because per-value function calls are slow for large tenants.
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
            # Rows after the first page are hidden until the user asks for more (fast initial load).
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
        $noUsersHtml = '<div class="empty" id="noUsers" role="status">No users in this report. No users were returned, or all users were left out by -UserType / -ExcludeGuests / -ExcludeDisabled.</div>'
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
<div class="notice" id="sensitiveNotice" role="note"><strong>Sensitive report:</strong> this report contains sensitive information about user accounts, e.g. on-premises sign-in names and disabled accounts. Store it in a secure location with restricted access, do not share it unencrypted and delete it when it is no longer needed.</div>

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
<div class="more" id="moreRows" hidden><button type="button" id="showMore">Show $HtmlPageSize more</button> <button type="button" id="showAll">Show all</button> <span class="more-note">Large report: at most $HtmlPageSize matching rows are shown at a time to keep the page fast. Use the filters, or show more rows. The browser's find (Ctrl+F) only searches shown rows.</span></div>
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

    // Read every row once and cache the values used for filtering (no DOM reads while filtering).
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

        // One pass over the cached data; only rows whose visibility changes are touched. At most
        // 'limit' matching rows are shown.
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

    // Text search is debounced while typing; change events and dropdowns apply immediately.
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
# Current step, used to classify a failure (see Get-EntraUsersFailure).
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

    # Optional row filters (default: all users).
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

    # Without an export path the objects are the result; with an export path only with -PassThru.
    if ($PassThru -or (-not $OutputPath -and -not $HtmlPath)) {
        Write-Output $report
    }
}
catch {
    $failure = Get-EntraUsersFailure -ErrorRecord $_ -Step $step
    $exitCode = $failure.ExitCode
    # Non-terminating so the finally block and the exit code below always run.
    Write-Error -Message $failure.Message -Category $failure.Category -ErrorId $failure.ErrorId -ErrorAction Continue
}
finally {
    # Restore the persisted WAM option if -UseWAM changed it (runs on every exit path).
    Restore-EntraUsersWam
}
exit $exitCode

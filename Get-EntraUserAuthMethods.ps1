#Requires -Version 5.1

<#
.SYNOPSIS
    Retrieves all Entra ID users' registered and preferred authentication methods using Microsoft Graph.
.DESCRIPTION
    Uses the Microsoft Graph authentication methods registration report to list all users along with
    their registered authentication methods, preferred authentication method, and MFA/SSPR status.
    Account enabled/disabled status is added from the users endpoint, and registered methods that are
    disabled in the tenant Authentication Methods policy are reported as non-usable. Registered
    methods whose policy configuration is not returned by Graph are reported as '<method> (unknown)'.
    Results can be exported to CSV and to an interactive HTML report with client side filtering.
    Each user is also classified as phishing-resistant MFA registered or not, based only on the
    registered methods (passkeys/FIDO2, Windows Hello for Business, Platform Credential for macOS and
    certificate-based authentication). Synced passkeys are accepted, but device-bound passkeys
    (FIDO2 security keys, passkeys in Microsoft Authenticator) are recommended for admins.
    Certificate-based authentication (CBA) only counts as phishing-resistant MFA when it is
    configured as multifactor; the CBA binding is not evaluated by this script. Users not found in the users lookup get account status
    'Unknown'. The HTML summary cards count active members only (enabled accounts with user type
    member); guests, disabled accounts and accounts with unknown status are shown in the table but
    excluded from the cards. Use -ExcludeGuests and -ExcludeDisabled to leave them out of the report.
    Only read-only Graph calls (GET) are used.
    An existing Microsoft Graph session is only reused if it belongs to the requested tenant and has
    the required scopes; otherwise the script connects again. The connected tenant name and id are
    always shown before any data is read.
    Use -UseWAM to sign in with the Windows Web Account Manager (WAM) broker, e.g. when a passkey /
    FIDO2 sign-in fails in the Windows PowerShell 5.1 sign-in window.
    The exported reports contain sensitive information (e.g. which admins have no MFA registered).
    Store them in a secure location with restricted access and delete them when no longer needed.
    If a required Graph call fails, a clear error is shown and the script ends with a non-zero exit
    code (see Exit codes in the notes); no partial report is written. The registration report
    requires a Microsoft Entra ID P1 or P2 license in the tenant.
.PARAMETER OutputPath
    Optional path to export the results as CSV. If omitted, no CSV is created.
.PARAMETER HtmlPath
    Optional path to export the results as an interactive HTML report with client side filtering.
.PARAMETER TenantId
    Optional tenant to connect to, as a tenant ID (GUID) or a verified domain name
    (e.g. contoso.onmicrosoft.com). If an existing Graph session belongs to another tenant, the
    script connects to this tenant instead. A domain name is compared against the verified domains
    of the connected tenant.
.PARAMETER ExcludeGuests
    Leaves guest users (userType guest, e.g. B2B guests) out of the report rows, CSV, HTML and output.
    Default off: guests are included in the rows but never counted in the HTML summary cards.
.PARAMETER ExcludeDisabled
    Leaves disabled accounts (accountEnabled false) out of the report rows, CSV, HTML and output.
    Accounts with unknown status (not found in the users lookup) are kept. Default off: disabled
    accounts are included in the rows but never counted in the HTML summary cards.
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
.EXAMPLE
    .\Get-EntraUserAuthMethods.ps1 -OutputPath C:\Reports\AuthMethods.csv
.EXAMPLE
    .\Get-EntraUserAuthMethods.ps1 -HtmlPath C:\Reports\AuthMethods.html
.EXAMPLE
    .\Get-EntraUserAuthMethods.ps1 -HtmlPath C:\Reports\AuthMethods.html -ExcludeGuests -ExcludeDisabled
.EXAMPLE
    .\Get-EntraUserAuthMethods.ps1 -HtmlPath C:\Reports\AuthMethods.html -TenantId contoso.onmicrosoft.com -UseWAM
    Signs in with the Windows Web Account Manager (e.g. with a passkey) in Windows PowerShell 5.1.
.EXAMPLE
    .\Get-EntraUserAuthMethods.ps1 -OutputPath C:\Reports\AuthMethods.csv
    if ($LASTEXITCODE -ne 0) { Write-Warning "Report failed with exit code $LASTEXITCODE" }
    Checks the exit code, e.g. in a scheduled task (powershell.exe -File returns the same code).
.NOTES
    Kasper Johansen | Apento
    kmj@apento.com

    Version: 1.5.6
    Updated: 2026-11-23

    Changelog
    1.5.6 - 2026-11-23
        Least privilege: the Policy.Read.All scope is replaced by Policy.Read.AuthenticationMethod,
        the least privileged permission for reading the Authentication Methods policy (v1.0) and
        the HardwareOath configuration (beta). An existing session with Policy.Read.All (or
        Policy.ReadWrite.AuthenticationMethod) is still accepted and does not force a reconnect.
        Clear errors and exit codes: a failing userRegistrationDetails call is reported as a
        missing Microsoft Entra ID P1/P2 license (exit 2) or missing role/permission (exit 3, e.g.
        Reports Reader, Security Reader or Global Reader), with the Graph error code and HTTP
        status. Other failures end with exit 1 (Graph or other errors) or exit 4 (sign-in, tenant
        or session check); a successful run ends with exit 0. The persisted WAM option is restored
        on every exit path. Get-Help now shows the comment-based help (blank line after #Requires).
    1.5.5 - 2026-11-23
        Added -UseWAM switch: sign in with the Windows Web Account Manager (WAM), e.g. for passkey /
        FIDO2 sign-in in Windows PowerShell 5.1. With Microsoft.Graph.Authentication 2.0.0 - 2.33.x,
        Set-MgGraphOption -EnableLoginByWAM $true is set right before Connect-MgGraph (including the
        tenant/scope check reconnect) and the previous persisted value is restored when the script
        ends. With 2.34.0 and later WAM is already the default on Windows and nothing is changed.
        Ignored with a warning on non-Windows; stops with an error if the module is too old; no
        effect when an existing or app-only session is reused. On Windows a warning recommending
        Update-Module Microsoft.Graph.Authentication (2.34.0 or later: WAM by default, passkey /
        FIDO2 sign-in) is always shown when an older module version is used, with or without
        -UseWAM. Help explains how to check the loaded and installed module versions.
    1.5.4 - 2026-11-23
        Report accuracy: users not found in the users lookup (accountEnabled null) are shown as
        account status 'Unknown' instead of 'Disabled', with their own status filter option and a new
        AccountStatus column. Added IsPhishingResistantRegistered (derived only from methodsRegistered)
        and MFA capable / phishing-resistant columns and filters to the HTML report. HTML summary cards
        now count active members only (enabled members, no guests, disabled or unknown status) and
        show the totals per group; new cards for MFA capable, phishing-resistant MFA and admins
        without phishing-resistant MFA, with notes that device-bound passkeys are recommended for
        admins and that CBA must be configured as multifactor. Added -ExcludeGuests and
        -ExcludeDisabled switches. System Preferred Method is now read from the documented
        systemPreferredAuthenticationMethods collection (joined with '; ') instead of the
        non-existent singular property, so the column is populated. An empty report (e.g. all rows
        removed by the switches) no longer crashes: the HTML report renders with zero rows and a
        'No users' message, and the CSV is written with the header row only.
    1.5.3 - 2026-11-23
        Tenant and scope check: an existing Graph session is only reused if it belongs to -TenantId
        (tenant ID or verified domain name) and has the required scopes, otherwise Connect-MgGraph
        is called again. The connected tenant name and id are shown before data is read and added
        to the HTML report header. App-only sessions in the wrong tenant or with missing permissions
        stop with an error instead of reconnecting. Sensitive report handling: a warning is shown
        when a CSV or HTML report is exported, and the HTML report shows a sensitive data notice.
    1.5.2 - 2026-11-23
        NonUsableMethods fix: a registered method whose policy configuration is missing from the
        policy response is now reported as '<method> (unknown)' instead of non-usable. HardwareOath
        is not part of the v1.0 policy, so it is read from the beta endpoint as a best-effort
        fallback (read-only). Method mapping updated: added email, passKeySynced, fido2SecurityKey,
        qrCode and x509Certificate. alternateMobilePhone now maps to Voice only (SMS is not
        supported on the alternate phone). windowsHelloForBusiness, macOsSecureEnclaveKey and
        securityQuestion are not governed by the Authentication Methods policy and are not flagged.
    1.5.1 - 2026-11-23
        Security fix: all user data in the HTML report (table cells, data-* attributes and filter
        dropdown options) is now HTML encoded via ConvertTo-HtmlSafe to prevent stored XSS from
        e.g. malicious display names. Added a Content-Security-Policy meta tag to the HTML report.
    1.5.0 - 2026-10-08
        Non-usable methods filter changed from free text to a dropdown: All, has non-usable methods,
        no non-usable methods, or a specific non-usable method found in the report.
    1.4.0 - 2026-10-08
        Added NonUsableMethods column: registered methods disabled in the tenant Authentication
        Methods policy. Reads /policies/authenticationMethodsPolicy. Added Policy.Read.All scope.
        Only the tenant wide enabled/disabled state is evaluated, not group targeting.
    1.3.1 - 2026-10-08
        Account status column in the HTML report shows Enabled/Disabled instead of True/False.
    1.3.0 - 2026-10-08
        Added AccountEnabled column and account status filter. Reads /users accountEnabled.
        Added User.Read.All scope.
    1.2.0 - 2026-10-08
        Added methods registered search filter to the HTML report.
    1.1.0 - 2026-10-08
        Added -HtmlPath parameter with summary cards and client side filters for name/UPN,
        user type, admin, MFA registered, SSPR registered and preferred method.
    1.0.0 - 2026-10-08
        Initial version. Reads /reports/authenticationMethods/userRegistrationDetails.
        CSV export via -OutputPath.

    Required Graph permission (delegated or application): AuditLog.Read.All, User.Read.All,
    Policy.Read.AuthenticationMethod
    AuditLog.Read.All grants read access to the authentication methods registration report.
    User.Read.All grants read access to each user's enabled/disabled account status.
    Policy.Read.AuthenticationMethod grants read access to the tenant Authentication Methods
    policy (v1.0) and the HardwareOath configuration (beta), used to determine which registered
    methods are disabled in the tenant and therefore non-usable. It is the least privileged
    permission for these calls. An existing session with the higher privileged Policy.Read.All or
    Policy.ReadWrite.AuthenticationMethod is accepted too (Microsoft Learn does not list
    Policy.Read.All for the beta HardwareOath call; if that call fails, hardware OATH tokens are
    reported as '(unknown)').
    With delegated sign-in the account also needs a Microsoft Entra role:
    - Registration report: Reports Reader, Security Reader, Security Administrator or Global Reader.
    - Authentication Methods policy: Global Reader or Authentication Policy Administrator.
    Global Reader covers all calls. The registration report also requires a Microsoft Entra ID P1
    or P2 license in the tenant.
    No write, update or delete calls are made anywhere in this script.

    Exit codes
    0 - Success (also when the report contains no users).
    1 - Microsoft Graph or other error (e.g. throttling, network, export failure).
    2 - The tenant has no Microsoft Entra ID P1 or P2 license (required by the registration
        report), Graph error code Authentication_RequestFromNonPremiumTenantOrB2CTenant.
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
    [switch]$UseWAM
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.5.6'
# Previous persisted WAM option (Get-MgGraphOption EnableWAMForMSGraph) to restore at the end, set by
# Enable-AuthMethodsWam when it changes the option.
$script:WamRestoreValue = $null
$RequiredScopes = @('AuditLog.Read.All', 'User.Read.All', 'Policy.Read.AuthenticationMethod')
# Exit codes (documented in the notes).
$ExitCodeSuccess = 0
$ExitCodeError = 1
$ExitCodeLicense = 2
$ExitCodePermission = 3
$ExitCodeSignIn = 4
# Report columns in CSV order. Used to write the CSV header when the report has no rows.
$ReportColumns = @('UserPrincipalName', 'DisplayName', 'UserType', 'AccountEnabled', 'AccountStatus', 'IsAdmin',
    'IsMfaRegistered', 'IsMfaCapable', 'IsPhishingResistantRegistered', 'IsSsprRegistered', 'IsSsprEnabled',
    'IsPasswordlessCapable', 'MethodsRegistered', 'NonUsableMethods', 'PreferredAuthMethod',
    'SystemPreferredMethod', 'LastUpdated')
$PhishingResistantNote = 'Phishing-resistant MFA is based on the registered methods only: passkeys (device-bound and synced), FIDO2 security keys, Windows Hello for Business, Platform Credential for macOS and certificate-based authentication. Device-bound passkeys (FIDO2 security keys, passkeys in Microsoft Authenticator) are recommended for admins. Certificate-based authentication (CBA) only counts as phishing-resistant MFA when it is configured as multifactor.'
$SensitiveReportWarning = 'contains sensitive information about user authentication methods (e.g. which admins have no MFA registered). Store it in a secure location with restricted access and delete it when it is no longer needed.'

function Get-MgGraphAllPages {
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

function Get-NonUsableMethods {
    param(
        [Parameter()]
        [array]$RegisteredMethods,

        [Parameter(Mandatory)]
        [hashtable]$PolicyState
    )

    # Maps registered method names (userRegistrationDetails.methodsRegistered) to the
    # Authentication Methods policy configuration id(s) (authenticationMethodConfiguration.id)
    # that govern them. A method is usable if at least one of its governing configurations is
    # enabled. Only the tenant wide enabled/disabled state is evaluated, not group targeting or
    # passkey profiles (e.g. whether a profile allows synced passkeys).
    #
    # If none of a method's governing configurations is present in the policy state, the state is
    # unknown and the method is reported as '<method> (unknown)' rather than non-usable. This
    # happens e.g. for HardwareOath when the beta fallback is unavailable, since the v1.0
    # authenticationMethodsPolicy does not include the HardwareOath configuration.
    #
    # Not governed by the Authentication Methods policy and therefore never flagged:
    #   windowsHelloForBusiness, macOsSecureEnclaveKey (device / platform credentials) and
    #   securityQuestion (controlled by the SSPR policy, not the Authentication Methods policy).
    #   Unknown future method names are also ignored.
    $methodMap = @{
        'mobilePhone'                        = @('Sms', 'Voice')
        # SMS is only supported on the primary mobile phone; the alternate phone supports voice only.
        'alternateMobilePhone'               = @('Voice')
        'officePhone'                        = @('Voice')
        'email'                              = @('Email')
        'microsoftAuthenticatorPush'         = @('MicrosoftAuthenticator')
        'microsoftAuthenticatorPasswordless' = @('MicrosoftAuthenticator')
        'softwareOneTimePasscode'            = @('SoftwareOath', 'MicrosoftAuthenticator')
        'hardwareOneTimePasscode'            = @('HardwareOath')
        'fido2'                              = @('Fido2')
        'fido2SecurityKey'                   = @('Fido2')
        'passKeyDeviceBound'                 = @('Fido2')
        'passKeyDeviceBoundAuthenticator'    = @('Fido2')
        'passKeyDeviceBoundWindowsHello'     = @('Fido2')
        # Synced passkeys are governed by the Passkey (FIDO2) configuration (passkey profiles).
        'passKeySynced'                      = @('Fido2')
        'temporaryAccessPass'                = @('TemporaryAccessPass')
        'qrCode'                             = @('QRCodePin')
        'x509Certificate'                    = @('X509Certificate')
    }

    $nonUsable = foreach ($method in $RegisteredMethods) {
        if ($methodMap.ContainsKey($method)) {
            $usable = $false
            $known = $false
            foreach ($policyId in $methodMap[$method]) {
                if ($PolicyState.ContainsKey($policyId)) {
                    $known = $true
                    if ($PolicyState[$policyId] -eq 'enabled') {
                        $usable = $true
                    }
                }
            }
            if (-not $known) {
                "$method (unknown)"
            }
            elseif (-not $usable) {
                $method
            }
        }
    }

    return ($nonUsable -join '; ')
}

function Test-PhishingResistantRegistered {
    # Returns $true if at least one registered method (userRegistrationDetails.methodsRegistered)
    # is phishing-resistant. Derived only from the registered methods; the Authentication Methods
    # policy, passkey profiles and Conditional Access authentication strengths are not evaluated.
    #
    # Counted as phishing-resistant:
    #   fido2, fido2SecurityKey, passKeyDeviceBound, passKeyDeviceBoundAuthenticator,
    #   passKeyDeviceBoundWindowsHello - device-bound passkeys / FIDO2 security keys.
    #   passKeySynced - synced passkeys (e.g. iCloud Keychain, Google Password Manager). Microsoft
    #     documents passkeys, including synced passkeys, as phishing-resistant. They do not support
    #     attestation, so organisations requiring device-bound keys for admins should check the
    #     MethodsRegistered column.
    #   windowsHelloForBusiness, macOsSecureEnclaveKey (Platform Credential for macOS).
    #   x509Certificate - certificate-based authentication. Only phishing-resistant MFA when the
    #     CBA authentication binding is multifactor; single-factor binding is not evaluated here.
    # Not counted: phone, email, Microsoft Authenticator push/passwordless, OATH, TAP, QR code and
    # security questions. Unknown future method names are not counted.
    param(
        [Parameter()]
        [AllowNull()]
        [array]$RegisteredMethods
    )

    $phishingResistantMethods = @(
        'fido2'
        'fido2SecurityKey'
        'passKeyDeviceBound'
        'passKeyDeviceBoundAuthenticator'
        'passKeyDeviceBoundWindowsHello'
        'passKeySynced'
        'windowsHelloForBusiness'
        'macOsSecureEnclaveKey'
        'x509Certificate'
    )

    foreach ($method in $RegisteredMethods) {
        if ($phishingResistantMethods -contains [string]$method) {
            return $true
        }
    }
    return $false
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

function Test-ActiveMember {
    # Active member = enabled account (accountEnabled true) with user type member.
    # Guests, disabled accounts and accounts with unknown status are not active members.
    param(
        [Parameter(Mandatory)]
        [object]$User
    )

    return ((Get-AccountStatus -AccountEnabled $User.AccountEnabled) -eq 'Enabled') -and ([string]$User.UserType -eq 'member')
}

function Get-MissingGraphScope {
    # Returns the required scopes that are not present in the granted scopes. A ReadWrite scope
    # (e.g. User.ReadWrite.All) is accepted in place of the matching Read scope (User.Read.All).
    # Higher privileged scopes listed in $alternativeScopes are accepted too, so an existing
    # session with e.g. Policy.Read.All does not force a reconnect.
    param(
        [Parameter()]
        [AllowNull()]
        [string[]]$GrantedScopes,

        [Parameter(Mandatory)]
        [string[]]$RequiredScopes
    )

    # Higher privileged scopes that also grant the required scope (Microsoft Learn permissions
    # tables for the API calls used by this script).
    $alternativeScopes = @{
        'Policy.Read.AuthenticationMethod' = @('Policy.Read.All')
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

function Enable-AuthMethodsWam {
    # Enables sign-in with the Windows Web Account Manager (WAM) before Connect-MgGraph.
    # Set-MgGraphOption persists the option per user, so the previous value is stored in
    # $script:WamRestoreValue and restored by Restore-AuthMethodsWam when the script ends.
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
        Write-Information "-UseWAM: Microsoft.Graph.Authentication $moduleVersion already uses the Web Account Manager (WAM) by default on Windows. No setting was changed." -InformationAction Continue
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
    Write-Information 'Web Account Manager (WAM) sign-in enabled for this run. The previous setting is restored when the script ends.' -InformationAction Continue
    return 'Enabled'
}

function Restore-AuthMethodsWam {
    # Restores the persisted WAM option changed by Enable-AuthMethodsWam.
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

function Get-AuthMethodsFailure {
    # Classifies an error from a script step into an exit code and a clear message.
    # Steps: SignIn, Report (userRegistrationDetails), Users, Policy, Other.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [ValidateSet('SignIn', 'Report', 'Users', 'Policy', 'Other')]
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

    $isLicense = ([string]$detail.Code -match 'NonPremium') -or ($detail.Text -match 'premium licen[cs]e')
    $isPermission = ($detail.StatusCode -eq 403) -or ([string]$detail.Code -in @('Authorization_RequestDenied', 'Authentication_RequestDenied', 'accessDenied', 'Forbidden'))

    $stepText = switch ($Step) {
        'Report' { 'the authentication methods registration report (/reports/authenticationMethods/userRegistrationDetails)' }
        'Users' { 'the users account status (/users)' }
        'Policy' { 'the tenant Authentication Methods policy (/policies/authenticationMethodsPolicy)' }
        'SignIn' { 'Microsoft Graph sign-in' }
        default { 'the report' }
    }

    if ($isLicense) {
        return [PSCustomObject]@{
            ExitCode = $ExitCodeLicense
            ErrorId  = 'EntraIdPremiumLicenseRequired'
            Category = [System.Management.Automation.ErrorCategory]::PermissionDenied
            Message  = "Cannot read $stepText$codeText. The report requires a Microsoft Entra ID P1 or P2 license in the tenant (Azure AD B2C tenants are not supported). Assign an Entra ID P1/P2 license in the tenant and run the script again. No report was created. Graph message: $graphMessage"
        }
    }
    if ($isPermission) {
        $roleText = switch ($Step) {
            'Report' { 'a Microsoft Entra role that can read the report, such as Reports Reader, Security Reader, Security Administrator or Global Reader, and the AuditLog.Read.All permission' }
            'Users' { 'the User.Read.All permission and a role that can read users, such as Global Reader' }
            'Policy' { 'the Policy.Read.AuthenticationMethod permission and a Microsoft Entra role such as Global Reader or Authentication Policy Administrator' }
            default { 'the required permissions and a Microsoft Entra role such as Global Reader' }
        }
        return [PSCustomObject]@{
            ExitCode = $ExitCodePermission
            ErrorId  = 'GraphAccessDenied'
            Category = [System.Management.Automation.ErrorCategory]::PermissionDenied
            Message  = "Access denied reading $stepText$codeText. The signed-in account (or app) needs $roleText. For app-only sessions grant the application permission with admin consent. Activate the role (e.g. in PIM) and run the script again. No report was created. Graph message: $graphMessage"
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
        ErrorId  = 'AuthMethodsReportFailed'
        Category = [System.Management.Automation.ErrorCategory]::NotSpecified
        Message  = "Failed to retrieve authentication method report while reading $stepText$codeText. No report was created. $($ErrorRecord.Exception.Message)"
    }
}

function Connect-AuthMethodsGraph {
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
        Write-Information "Connecting to Microsoft Graph: $reason." -InformationAction Continue
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
            $null = Enable-AuthMethodsWam
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
    Write-Information "Connected to tenant: $tenantDisplayName ($tenantIdValue) as $($context.Account)" -InformationAction Continue

    return [PSCustomObject]@{
        DisplayName = $tenantDisplayName
        Id          = $tenantIdValue
    }
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

function New-AuthMethodsHtmlReport {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$Report,

        [Parameter()]
        [string]$TenantDisplayName,

        [Parameter()]
        [string]$TenantIdValue
    )

    $generatedOn = Get-Date -Format "yyyy-MM-dd HH:mm"
    # Totals for all rows in the report.
    $totalUsers = @($Report).Count
    $guestTotal = @($Report | Where-Object { [string]$_.UserType -eq 'guest' }).Count
    $disabledTotal = @($Report | Where-Object { (Get-AccountStatus -AccountEnabled $_.AccountEnabled) -eq 'Disabled' }).Count
    $unknownStatusTotal = @($Report | Where-Object { (Get-AccountStatus -AccountEnabled $_.AccountEnabled) -eq 'Unknown' }).Count

    # Summary cards count active members only: enabled accounts with user type member. Guests
    # register their methods in their home tenant and disabled accounts cannot sign in, so
    # including them would inflate the number of users without MFA.
    $activeMembers = @($Report | Where-Object { Test-ActiveMember -User $_ })
    $activeMemberCount = $activeMembers.Count
    $mfaRegisteredCount = @($activeMembers | Where-Object { $_.IsMfaRegistered }).Count
    $mfaCapableCount = @($activeMembers | Where-Object { $_.IsMfaCapable }).Count
    $ssprRegisteredCount = @($activeMembers | Where-Object { $_.IsSsprRegistered }).Count
    $passwordlessCount = @($activeMembers | Where-Object { $_.IsPasswordlessCapable }).Count
    $phishingResistantCount = @($activeMembers | Where-Object { $_.IsPhishingResistantRegistered }).Count
    $activeAdmins = @($activeMembers | Where-Object { $_.IsAdmin })
    $activeAdminCount = $activeAdmins.Count
    $adminsWithoutPhishingResistantCount = @($activeAdmins | Where-Object { -not $_.IsPhishingResistantRegistered }).Count

    $userTypes = $Report | Select-Object -ExpandProperty UserType -Unique | Sort-Object
    $preferredMethods = $Report | Select-Object -ExpandProperty PreferredAuthMethod -Unique | Sort-Object

    $userTypeOptions = ($userTypes | ForEach-Object { $safeValue = ConvertTo-HtmlSafe $_; "<option value=`"$safeValue`">$safeValue</option>" }) -join ""
    $preferredMethodOptions = ($preferredMethods | ForEach-Object { $safeValue = ConvertTo-HtmlSafe $_; "<option value=`"$safeValue`">$safeValue</option>" }) -join ""

    $nonUsableMethodList = $Report |
        Where-Object { $_.NonUsableMethods } |
        ForEach-Object { $_.NonUsableMethods -split '; ' } |
        Select-Object -Unique |
        Sort-Object
    $nonUsableOptions = ($nonUsableMethodList | ForEach-Object { "<option value=`"$(ConvertTo-HtmlSafe ([string]$_).ToLower())`">$(ConvertTo-HtmlSafe $_)</option>" }) -join ""

    $rows = foreach ($user in $Report) {
        $mfaClass = if ($user.IsMfaRegistered) { "yes" } else { "no" }
        $ssprClass = if ($user.IsSsprRegistered) { "yes" } else { "no" }
        $adminClass = if ($user.IsAdmin) { "yes" } else { "no" }
        $statusText = Get-AccountStatus -AccountEnabled $user.AccountEnabled
        $statusClass = switch ($statusText) { 'Enabled' { 'yes' } 'Disabled' { 'no' } default { 'unknown' } }
        $mfaCapableClass = if ($user.IsMfaCapable) { "yes" } else { "no" }
        $phishingResistantClass = if ($user.IsPhishingResistantRegistered) { "yes" } else { "no" }
        $nonUsableClass = if ($user.NonUsableMethods) { "no" } else { "" }
        $passwordlessClass = if ($user.IsPasswordlessCapable) { "yes" } else { "no" }

        @"
        <tr data-usertype="$(ConvertTo-HtmlSafe $user.UserType)" data-admin="$(ConvertTo-HtmlSafe $user.IsAdmin)" data-status="$(ConvertTo-HtmlSafe $statusText)" data-mfa="$(ConvertTo-HtmlSafe $user.IsMfaRegistered)" data-mfacapable="$(ConvertTo-HtmlSafe $user.IsMfaCapable)" data-phishres="$(ConvertTo-HtmlSafe $user.IsPhishingResistantRegistered)" data-sspr="$(ConvertTo-HtmlSafe $user.IsSsprRegistered)" data-preferred="$(ConvertTo-HtmlSafe $user.PreferredAuthMethod)" data-methods="$(ConvertTo-HtmlSafe ([string]$user.MethodsRegistered).ToLower())" data-nonusable="$(ConvertTo-HtmlSafe ([string]$user.NonUsableMethods).ToLower())">
            <td>$(ConvertTo-HtmlSafe $user.DisplayName)</td>
            <td>$(ConvertTo-HtmlSafe $user.UserPrincipalName)</td>
            <td>$(ConvertTo-HtmlSafe $user.UserType)</td>
            <td class="$adminClass">$(ConvertTo-HtmlSafe $user.IsAdmin)</td>
            <td class="$statusClass">$statusText</td>
            <td class="$mfaClass">$(ConvertTo-HtmlSafe $user.IsMfaRegistered)</td>
            <td class="$mfaCapableClass">$(ConvertTo-HtmlSafe $user.IsMfaCapable)</td>
            <td class="$phishingResistantClass">$(ConvertTo-HtmlSafe $user.IsPhishingResistantRegistered)</td>
            <td class="$ssprClass">$(ConvertTo-HtmlSafe $user.IsSsprRegistered)</td>
            <td class="$passwordlessClass">$(ConvertTo-HtmlSafe $user.IsPasswordlessCapable)</td>
            <td>$(ConvertTo-HtmlSafe $user.MethodsRegistered)</td>
            <td class="$nonUsableClass">$(ConvertTo-HtmlSafe $user.NonUsableMethods)</td>
            <td>$(ConvertTo-HtmlSafe $user.PreferredAuthMethod)</td>
            <td>$(ConvertTo-HtmlSafe $user.SystemPreferredMethod)</td>
            <td>$(ConvertTo-HtmlSafe $user.LastUpdated)</td>
        </tr>
"@
    }
    $rowsHtml = @($rows) -join "`n"
    $noUsersHtml = ''
    if ($totalUsers -eq 0) {
        $noUsersHtml = '<div class="empty" id="noUsers" role="status">No users in this report. No users were returned, or all users were left out by -ExcludeGuests / -ExcludeDisabled.</div>'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Entra Authentication Methods Report</title>
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
    th { background: var(--head); color: #fff; position: sticky; top: 0; cursor: pointer; user-select: none; }
    tr:nth-child(even) { background: #fafbfc; }
    td.yes { color: var(--yes); font-weight: 600; }
    td.no { color: var(--no); font-weight: 600; }
    td.unknown { color: #6b7280; font-style: italic; }
    .card.warn .num { color: var(--no); }
    .method-note { color: #6b7280; font-size: 12px; margin: -12px 0 20px 0; }
    .empty { background: #fff; border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 14px; color: #6b7280; font-size: 14px; }
    .summary-note { color: #6b7280; font-size: 12px; margin: -12px 0 20px 0; }
    .table-wrap { max-height: 70vh; overflow: auto; border: 1px solid var(--border); border-radius: 6px; }
    #rowCount { font-size: 12px; color: #6b7280; margin: 8px 0; }
</style>
</head>
<body>

<h1>Entra ID Authentication Methods Report</h1>
<div class="meta">Tenant $(ConvertTo-HtmlSafe $TenantDisplayName) ($(ConvertTo-HtmlSafe $TenantIdValue)) | Generated $generatedOn | Script version $ScriptVersion</div>
<div class="notice" id="sensitiveNotice" role="note"><strong>Sensitive report:</strong> this report contains sensitive information about user authentication methods, e.g. which admins have no MFA registered. Store it in a secure location with restricted access, do not share it unencrypted and delete it when it is no longer needed.</div>

<div class="summary" id="summaryCards">
    <div class="card"><div class="num" id="cardActiveMembers">$activeMemberCount</div><div class="label">Active members</div></div>
    <div class="card"><div class="num" id="cardMfaRegistered">$mfaRegisteredCount</div><div class="label">MFA registered</div></div>
    <div class="card"><div class="num" id="cardMfaCapable">$mfaCapableCount</div><div class="label">MFA capable</div></div>
    <div class="card" title="$(ConvertTo-HtmlSafe $PhishingResistantNote)"><div class="num" id="cardPhishingResistant">$phishingResistantCount</div><div class="label">Phishing-resistant MFA registered</div></div>
    <div class="card"><div class="num" id="cardSsprRegistered">$ssprRegisteredCount</div><div class="label">SSPR registered</div></div>
    <div class="card"><div class="num" id="cardPasswordless">$passwordlessCount</div><div class="label">Passwordless capable</div></div>
    <div class="card"><div class="num" id="cardActiveAdmins">$activeAdminCount</div><div class="label">Admins</div></div>
    <div class="card warn" title="$(ConvertTo-HtmlSafe $PhishingResistantNote)"><div class="num" id="cardAdminsNoPhishingResistant">$adminsWithoutPhishingResistantCount</div><div class="label">Admins without phishing-resistant MFA</div></div>
</div>
<div class="summary-note" id="summaryNote">Summary cards count active members only (enabled accounts with user type member). Guests, disabled accounts and accounts with unknown status are shown in the table but not counted in the cards. All users in report: <span id="totalUsers">$totalUsers</span> | Guests: <span id="totalGuests">$guestTotal</span> | Disabled: <span id="totalDisabled">$disabledTotal</span> | Unknown status: <span id="totalUnknownStatus">$unknownStatusTotal</span></div>
<div class="method-note" id="phishingResistantNote">$(ConvertTo-HtmlSafe $PhishingResistantNote)</div>

<div class="filters">
    <div>
        <label for="searchBox">Search name / UPN</label>
        <input type="text" id="searchBox" placeholder="Type to search...">
    </div>
    <div>
        <label for="userTypeFilter">User type</label>
        <select id="userTypeFilter"><option value="">All</option>$userTypeOptions</select>
    </div>
    <div>
        <label for="adminFilter">Admin</label>
        <select id="adminFilter"><option value="">All</option><option value="True">Admins only</option><option value="False">Non-admins only</option></select>
    </div>
    <div>
        <label for="statusFilter">Account status</label>
        <select id="statusFilter"><option value="">All</option><option value="Enabled">Enabled</option><option value="Disabled">Disabled</option><option value="Unknown">Unknown</option></select>
    </div>
    <div>
        <label for="mfaFilter">MFA registered</label>
        <select id="mfaFilter"><option value="">All</option><option value="True">Yes</option><option value="False">No</option></select>
    </div>
    <div>
        <label for="mfaCapableFilter">MFA capable</label>
        <select id="mfaCapableFilter"><option value="">All</option><option value="True">Yes</option><option value="False">No</option></select>
    </div>
    <div>
        <label for="phishResFilter">Phishing-resistant MFA</label>
        <select id="phishResFilter"><option value="">All</option><option value="True">Yes</option><option value="False">No</option></select>
    </div>
    <div>
        <label for="ssprFilter">SSPR registered</label>
        <select id="ssprFilter"><option value="">All</option><option value="True">Yes</option><option value="False">No</option></select>
    </div>
    <div>
        <label for="preferredFilter">Preferred method</label>
        <select id="preferredFilter"><option value="">All</option>$preferredMethodOptions</select>
    </div>
    <div>
        <label for="methodsFilter">Methods registered contains</label>
        <input type="text" id="methodsFilter" placeholder="e.g. fido2, sms...">
    </div>
    <div>
        <label for="nonUsableFilter">Non-usable methods</label>
        <select id="nonUsableFilter">
            <option value="">All</option>
            <option value="__any">Has non-usable methods</option>
            <option value="__none">No non-usable methods</option>
            $nonUsableOptions
        </select>
    </div>
</div>

<div id="rowCount"></div>
$noUsersHtml

<div class="table-wrap">
<table id="reportTable">
    <thead>
        <tr>
            <th>Display Name</th>
            <th>User Principal Name</th>
            <th>User Type</th>
            <th>Admin</th>
            <th>Account Status</th>
            <th>MFA Registered</th>
            <th>MFA Capable</th>
            <th title="$(ConvertTo-HtmlSafe $PhishingResistantNote)">Phishing-resistant MFA</th>
            <th>SSPR Registered</th>
            <th>Passwordless Capable</th>
            <th>Methods Registered</th>
            <th>Non-usable Methods</th>
            <th>Preferred Method</th>
            <th>System Preferred Method</th>
            <th>Last Updated</th>
        </tr>
    </thead>
    <tbody>
$rowsHtml
    </tbody>
</table>
</div>

<script>
    var searchBox = document.getElementById('searchBox');
    var userTypeFilter = document.getElementById('userTypeFilter');
    var adminFilter = document.getElementById('adminFilter');
    var statusFilter = document.getElementById('statusFilter');
    var mfaFilter = document.getElementById('mfaFilter');
    var mfaCapableFilter = document.getElementById('mfaCapableFilter');
    var phishResFilter = document.getElementById('phishResFilter');
    var ssprFilter = document.getElementById('ssprFilter');
    var preferredFilter = document.getElementById('preferredFilter');
    var methodsFilter = document.getElementById('methodsFilter');
    var nonUsableFilter = document.getElementById('nonUsableFilter');
    var rows = document.querySelectorAll('#reportTable tbody tr');
    var rowCount = document.getElementById('rowCount');

    function applyFilters() {
        var search = searchBox.value.toLowerCase();
        var userType = userTypeFilter.value;
        var admin = adminFilter.value;
        var status = statusFilter.value;
        var mfa = mfaFilter.value;
        var mfaCapable = mfaCapableFilter.value;
        var phishRes = phishResFilter.value;
        var sspr = ssprFilter.value;
        var preferred = preferredFilter.value;
        var methods = methodsFilter.value.toLowerCase();
        var nonUsable = nonUsableFilter.value;
        var visible = 0;

        rows.forEach(function (row) {
            var text = row.cells[0].textContent.toLowerCase() + " " + row.cells[1].textContent.toLowerCase();
            var matches = true;

            if (search && text.indexOf(search) === -1) { matches = false; }
            if (userType && row.dataset.usertype !== userType) { matches = false; }
            if (admin && row.dataset.admin !== admin) { matches = false; }
            if (status && row.dataset.status !== status) { matches = false; }
            if (mfa && row.dataset.mfa !== mfa) { matches = false; }
            if (mfaCapable && row.dataset.mfacapable !== mfaCapable) { matches = false; }
            if (phishRes && row.dataset.phishres !== phishRes) { matches = false; }
            if (sspr && row.dataset.sspr !== sspr) { matches = false; }
            if (preferred && row.dataset.preferred !== preferred) { matches = false; }
            if (methods && row.dataset.methods.indexOf(methods) === -1) { matches = false; }
            if (nonUsable) {
                var rowNonUsable = row.dataset.nonusable ? row.dataset.nonusable.split('; ') : [];
                if (nonUsable === '__any' && rowNonUsable.length === 0) { matches = false; }
                else if (nonUsable === '__none' && rowNonUsable.length > 0) { matches = false; }
                else if (nonUsable !== '__any' && nonUsable !== '__none' && rowNonUsable.indexOf(nonUsable) === -1) { matches = false; }
            }

            row.style.display = matches ? "" : "none";
            if (matches) { visible++; }
        });

        rowCount.textContent = visible + " of " + rows.length + " users shown";
    }

    [searchBox, userTypeFilter, adminFilter, statusFilter, mfaFilter, mfaCapableFilter, phishResFilter, ssprFilter, preferredFilter, methodsFilter, nonUsableFilter].forEach(function (el) {
        el.addEventListener('input', applyFilters);
        el.addEventListener('change', applyFilters);
    });

    applyFilters();
</script>

</body>
</html>
"@

    return $html
}

$exitCode = $ExitCodeSuccess
# Current step, used to classify a failure (see Get-AuthMethodsFailure).
$step = 'SignIn'
try {
    $tenant = Connect-AuthMethodsGraph -RequiredScopes $RequiredScopes -TenantId $TenantId -UseWAM:$UseWAM

    Write-Verbose "Get-EntraUserAuthMethods version $ScriptVersion"
    Write-Verbose "Retrieving user authentication method registration details"
    $step = 'Report'
    $uri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    $registrationDetails = Get-MgGraphAllPages -Uri $uri

    Write-Verbose "Retrieving user account enabled/disabled status"
    $step = 'Users'
    $usersUri = 'https://graph.microsoft.com/v1.0/users?$select=id,accountEnabled&$top=999'
    $userAccountDetails = Get-MgGraphAllPages -Uri $usersUri

    $accountStatusLookup = @{}
    foreach ($accountUser in $userAccountDetails) {
        $accountStatusLookup[$accountUser.id] = $accountUser.accountEnabled
    }

    Write-Verbose "Retrieving tenant authentication methods policy"
    $step = 'Policy'
    $policyUri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    $authMethodsPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri

    $policyState = @{}
    foreach ($methodConfig in $authMethodsPolicy.authenticationMethodConfigurations) {
        $policyState[$methodConfig.id] = $methodConfig.state
    }

    # The v1.0 policy does not include the HardwareOath configuration. Read it from beta as a
    # best-effort, read-only fallback. If that fails, hardware OATH tokens are reported as unknown.
    if (-not $policyState.ContainsKey('HardwareOath')) {
        try {
            $hardwareOathUri = 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/HardwareOath'
            $hardwareOathConfig = Invoke-MgGraphRequest -Method GET -Uri $hardwareOathUri
            if ($hardwareOathConfig.state) {
                $policyState['HardwareOath'] = $hardwareOathConfig.state
            }
        }
        catch {
            Write-Verbose "HardwareOath policy state could not be read from beta (requires Policy.Read.AuthenticationMethod), reported as unknown: $($_.Exception.Message)"
        }
    }
    $step = 'Other'

    $report = foreach ($user in $registrationDetails) {
        $accountEnabled = $accountStatusLookup[$user.id]

        [PSCustomObject]@{
            UserPrincipalName     = $user.userPrincipalName
            DisplayName           = $user.userDisplayName
            UserType              = $user.userType
            AccountEnabled        = $accountEnabled
            AccountStatus         = Get-AccountStatus -AccountEnabled $accountEnabled
            IsAdmin               = $user.isAdmin
            IsMfaRegistered       = $user.isMfaRegistered
            IsMfaCapable          = $user.isMfaCapable
            IsPhishingResistantRegistered = Test-PhishingResistantRegistered -RegisteredMethods $user.methodsRegistered
            IsSsprRegistered      = $user.isSsprRegistered
            IsSsprEnabled         = $user.isSsprEnabled
            IsPasswordlessCapable = $user.isPasswordlessCapable
            MethodsRegistered     = ($user.methodsRegistered -join '; ')
            NonUsableMethods      = Get-NonUsableMethods -RegisteredMethods $user.methodsRegistered -PolicyState $policyState
            PreferredAuthMethod   = $user.userPreferredMethodForSecondaryAuthentication
            SystemPreferredMethod = (@($user.systemPreferredAuthenticationMethods) -join '; ')
            LastUpdated           = $user.lastUpdatedDateTime
        }
    }
    $report = @($report)

    # Optional row filters (default off, all users are included).
    if ($ExcludeGuests) {
        $guestCount = @($report | Where-Object { [string]$_.UserType -eq 'guest' }).Count
        $report = @($report | Where-Object { [string]$_.UserType -ne 'guest' })
        Write-Verbose "ExcludeGuests: $guestCount guest user(s) left out of the report"
    }
    if ($ExcludeDisabled) {
        $disabledCount = @($report | Where-Object { $_.AccountStatus -eq 'Disabled' }).Count
        $report = @($report | Where-Object { $_.AccountStatus -ne 'Disabled' })
        Write-Verbose "ExcludeDisabled: $disabledCount disabled account(s) left out of the report"
    }

    if ($OutputPath) {
        if ($PSCmdlet.ShouldProcess($OutputPath, "Export authentication method report as CSV")) {
            if ($report.Count -gt 0) {
                $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            }
            else {
                # Export-Csv writes nothing for an empty report; write the header row only.
                $csvHeader = ($ReportColumns | ForEach-Object { '"' + $_ + '"' }) -join ','
                Set-Content -Path $OutputPath -Value $csvHeader -Encoding UTF8
                Write-Warning "The report contains no users. The CSV report $OutputPath contains the header row only."
            }
            Write-Host "CSV report exported to $OutputPath"
            Write-Warning "The CSV report $OutputPath $SensitiveReportWarning"
        }
    }

    if ($HtmlPath) {
        if ($PSCmdlet.ShouldProcess($HtmlPath, "Export authentication method report as HTML")) {
            $htmlContent = New-AuthMethodsHtmlReport -Report $report -TenantDisplayName $tenant.DisplayName -TenantIdValue $tenant.Id
            Set-Content -Path $HtmlPath -Value $htmlContent -Encoding UTF8
            Write-Host "HTML report exported to $HtmlPath"
            if ($report.Count -eq 0) {
                Write-Warning "The report contains no users. The HTML report $HtmlPath has no rows."
            }
            Write-Warning "The HTML report $HtmlPath $SensitiveReportWarning"
        }
    }

    Write-Output $report
}
catch {
    $failure = Get-AuthMethodsFailure -ErrorRecord $_ -Step $step
    $exitCode = $failure.ExitCode
    # Non-terminating so the finally block and the exit code below always run.
    Write-Error -Message $failure.Message -Category $failure.Category -ErrorId $failure.ErrorId -ErrorAction Continue
}
finally {
    # Restore the persisted WAM option if -UseWAM changed it (runs on every exit path).
    Restore-AuthMethodsWam
}
exit $exitCode

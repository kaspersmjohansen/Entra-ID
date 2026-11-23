#Requires -Version 5.1

<#
.SYNOPSIS
    Creates PIM security groups from a text file. Safe to re-run: existing groups are skipped.
.DESCRIPTION
    One group name per line (UTF-8). Blank lines and lines starting with # are ignored.
    Names are de-duplicated case-insensitively after prefix/suffix are applied.
    Groups are created as cloud-only security groups (mailEnabled false, assigned membership, no owners).
    A group whose name already exists is skipped (Exists) or reported as ExistsMismatch if it is not
    a cloud-only, non-mail, assigned security group (or not role-assignable with -RoleAssignable).
    The script only creates groups. A group is onboarded to PIM for Groups at its first PIM assignment.
.PARAMETER InputFile
    Text file with one group name per line (UTF-8, with or without BOM).
.PARAMETER Prefix
    Added in front of each name unless the name already starts with it.
.PARAMETER Suffix
    Added after each name unless the name already ends with it.
.PARAMETER Description
    Description for all created groups.
.PARAMETER RoleAssignable
    Creates role-assignable groups (needed to assign Entra roles to the group). Cannot be changed later.
    Requires Privileged Role Administrator and RoleManagement.ReadWrite.Directory. Max 500 per tenant.
.PARAMETER OutputPath
    CSV result file (UTF-8 with BOM, formula injection protected).
.PARAMETER TenantId
    Tenant ID (GUID) or verified domain name. Reconnects if the current session is another tenant.
.PARAMETER UseWAM
    Signs in with the Windows Web Account Manager (passkey / FIDO2 in Windows PowerShell 5.1).
.PARAMETER PassThru
    Also returns the result objects when -OutputPath is used.
.EXAMPLE
    .\New-EntraGroupsFromFile.ps1 -InputFile .\pim-groups.txt -Prefix 'PIM-' -TenantId contoso.onmicrosoft.com -WhatIf
.EXAMPLE
    .\New-EntraGroupsFromFile.ps1 -InputFile .\pim-groups.txt -Prefix 'PIM-' -RoleAssignable -OutputPath .\pim-groups.csv
.NOTES
    Kasper Johansen | Apento | kmj@apento.com
    Version: 2.0.0 (2026-11-23)

    Changelog
    2.0.0 - 2026-11-23 Rewritten: idempotent, tenant check, -RoleAssignable, -WhatIf results, CSV, exit codes.

    Permission: Group.ReadWrite.All (+ RoleManagement.ReadWrite.Directory with -RoleAssignable).

    Exit codes
    0 = success (also Exists / ExistsMismatch / -WhatIf), 1 = a group failed or other error,
    3 = access denied, 4 = sign-in/session error
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$InputFile,

    [Parameter()]
    [string]$Prefix = '',

    [Parameter()]
    [string]$Suffix = '',

    [Parameter()]
    [string]$Description = '',

    [Parameter()]
    [switch]$RoleAssignable,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$UseWAM,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '2.0.0'
if (-not $PSBoundParameters.ContainsKey('InformationAction')) {
    $InformationPreference = 'Continue'
}
$script:WamRestoreValue = $null
$RequiredScopes = @('Group.ReadWrite.All')
if ($RoleAssignable) {
    $RequiredScopes += 'RoleManagement.ReadWrite.Directory'
}
$ExitCodeSuccess = 0
$ExitCodeError = 1
$ExitCodePermission = 3
$ExitCodeSignIn = 4
$GraphBase = 'https://graph.microsoft.com/v1.0'
$GroupSelect = 'id,displayName,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,onPremisesSyncEnabled'
$MaxDisplayNameLength = 256
$MaxRoleAssignableGroups = 500
$MaxRetries = 5
$MaxRetryAfterSeconds = 120
$ResultColumns = @('DisplayName', 'Status', 'GroupId', 'RoleAssignable', 'MailNickname', 'Owners', 'InputName', 'Detail')

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
        'Group.ReadWrite.All' = @('Directory.ReadWrite.All')
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

function Enable-EntraGroupsWam {
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
        throw "-UseWAM requires Microsoft.Graph.Authentication 2.0.0 or later, found version $foundVersion. Run Update-Module Microsoft.Graph.Authentication. No groups have been created."
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

function Restore-EntraGroupsWam {
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

function Connect-EntraGroupsGraph {
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
            $null = Enable-EntraGroupsWam
        }
        Connect-MgGraph @connectParams | Out-Null

        $context = Get-MgContext
        if (-not $context) {
            throw 'Connect-MgGraph did not establish a Microsoft Graph session.'
        }
        $tenantInfo = $null

        $missingScopes = @(Get-MissingGraphScope -GrantedScopes $context.Scopes -RequiredScopes $RequiredScopes)
        if ($missingScopes.Count -gt 0) {
            Write-Warning "The Microsoft Graph session is missing the scope(s): $($missingScopes -join ', '). Creating groups may fail."
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
            throw "The Microsoft Graph session belongs to tenant $($context.TenantId), not '$TenantId'. No groups have been created."
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

function Export-EntraGroupsCsv {
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
function Read-EntraGroupsInputFile {
    # Returns the trimmed names (no blank lines or # comments). Throws on non-UTF-8 (ANSI) files.
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    # Detects UTF-8/UTF-16/UTF-32 BOM; no BOM = UTF-8. Invalid UTF-8 bytes become U+FFFD.
    $text = [System.IO.File]::ReadAllText($fullPath, [System.Text.Encoding]::UTF8)
    $lines = $text -split "`r`n|`n|`r"
    $names = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line.IndexOf([char]0xFFFD) -ge 0) {
            throw "Line $($i + 1) in '$Path' is not valid UTF-8 (ANSI file?). Save the file as UTF-8 and run again."
        }
        $line = $line.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) {
            continue
        }
        $names.Add($line)
    }
    return , $names.ToArray()
}

function Get-EntraGroupDisplayName {
    # Adds prefix/suffix unless already present (case-insensitive).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Prefix = '',

        [Parameter()]
        [AllowEmptyString()]
        [string]$Suffix = ''
    )

    $result = $Name.Trim()
    $ignoreCase = [System.StringComparison]::OrdinalIgnoreCase
    if ($Prefix -and -not $result.StartsWith($Prefix, $ignoreCase)) {
        $result = $Prefix + $result
    }
    if ($Suffix -and -not $result.EndsWith($Suffix, $ignoreCase)) {
        $result = $result + $Suffix
    }
    return $result.Trim()
}

function Test-EntraGroupDisplayName {
    # Returns $null if valid, otherwise the reason.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$DisplayName
    )

    if ($DisplayName -eq '') {
        return 'Empty name.'
    }
    if ($DisplayName.Length -gt $MaxDisplayNameLength) {
        return "Name is $($DisplayName.Length) characters (max $MaxDisplayNameLength incl. prefix/suffix)."
    }
    if ($DisplayName -match '[\x00-\x1F\x7F]') {
        return 'Name contains control characters.'
    }
    return $null
}

function Get-EntraGroupMailNickname {
    # ASCII mailNickname (max 64). ae/oe/aa transliteration, accents removed, GUID fallback.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $map = @{
        [char]0x00C6 = 'Ae'; [char]0x00E6 = 'ae'; [char]0x00D8 = 'Oe'; [char]0x00F8 = 'oe'
        [char]0x00C5 = 'Aa'; [char]0x00E5 = 'aa'; [char]0x00C4 = 'Ae'; [char]0x00E4 = 'ae'
        [char]0x00D6 = 'Oe'; [char]0x00F6 = 'oe'; [char]0x00DC = 'Ue'; [char]0x00FC = 'ue'
        [char]0x00DF = 'ss'
    }
    $builder = [System.Text.StringBuilder]::new()
    foreach ($ch in $Name.ToCharArray()) {
        if ($map.ContainsKey($ch)) {
            [void]$builder.Append($map[$ch])
        }
        else {
            [void]$builder.Append($ch)
        }
    }
    $decomposed = $builder.ToString().Normalize([System.Text.NormalizationForm]::FormD)
    $plain = [System.Text.StringBuilder]::new()
    foreach ($ch in $decomposed.ToCharArray()) {
        if ([System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch) -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$plain.Append($ch)
        }
    }
    $nick = ($plain.ToString() -replace '[^A-Za-z0-9_.-]', '-' -replace '-{2,}', '-' -replace '\.{2,}', '.').Trim('-', '_', '.').ToLowerInvariant()
    if ($nick.Length -gt 64) {
        $nick = $nick.Substring(0, 64).Trim('-', '_', '.')
    }
    if (-not $nick) {
        $nick = 'group-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    }
    return $nick
}

function Get-EntraGroupsFilterUri {
    # $filter=displayName eq '...' with quotes doubled and the value percent-encoded.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    $filter = "displayName eq '" + $DisplayName.Replace("'", "''") + "'"
    return "$GraphBase/groups?`$filter=" + [uri]::EscapeDataString($filter) + "&`$select=$GroupSelect&`$top=2"
}

function ConvertTo-AsciiJson {
    # JSON with non-ASCII characters escaped as \uXXXX (same request bytes in PS 5.1 and 7).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Body
    )

    $json = $Body | ConvertTo-Json -Depth 3 -Compress
    return [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
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

function Invoke-EntraGroupsGraph {
    # Invoke-MgGraphRequest with retry on 429 (GET also 503/504; optional 404 for new objects).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [string]$Body,

        [Parameter()]
        [hashtable]$Headers,

        [Parameter()]
        [switch]$RetryNotFound
    )

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
            # POST is only retried on 429 (request not processed) to avoid duplicates.
            $retryable = ($status -eq 429) -or ($Method -eq 'GET' -and $status -in @(503, 504)) -or ($RetryNotFound -and $status -eq 404)
            if (-not $retryable -or $attempt -gt $MaxRetries) {
                throw
            }
            $wait = Get-RetryAfterSecond -ErrorRecord $_ -Attempt $attempt
            Write-Verbose "HTTP $status from Graph, retry $attempt of $MaxRetries in $wait s: $Method $Uri"
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-EntraGroupMismatch {
    # Returns why an existing group does not fit (empty = fits).
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [object]$Group,

        [Parameter()]
        [switch]$RoleAssignable
    )

    $reasons = @()
    if ($Group.securityEnabled -ne $true) { $reasons += 'not security enabled' }
    if ($Group.mailEnabled -eq $true) { $reasons += 'mail enabled' }
    $types = @($Group.groupTypes)
    if ($types -contains 'Unified') { $reasons += 'Microsoft 365 group' }
    if ($types -contains 'DynamicMembership') { $reasons += 'dynamic membership' }
    if ($Group.onPremisesSyncEnabled -eq $true) { $reasons += 'synced from on-premises AD' }
    if ($RoleAssignable -and $Group.isAssignableToRole -ne $true) { $reasons += 'not role-assignable' }
    return $reasons
}

function Get-EntraGroupsFailure {
    # Maps an error to exit code and message.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [ValidateSet('Input', 'SignIn', 'Groups', 'Other')]
        [string]$Step
    )

    $detail = Get-GraphErrorDetail -ErrorRecord $ErrorRecord
    $codeParts = @()
    if ($detail.Code) { $codeParts += "Graph error code: $($detail.Code)" }
    if ($detail.StatusCode) { $codeParts += "HTTP $($detail.StatusCode)" }
    $codeText = if ($codeParts.Count -gt 0) { " ($($codeParts -join ', '))" } else { '' }
    $graphMessage = if ($detail.Message) { $detail.Message } else { $ErrorRecord.Exception.Message }
    $isPermission = ($Step -ne 'Input') -and (($detail.StatusCode -eq 403) -or ([string]$detail.Code -in @('Authorization_RequestDenied', 'Authentication_RequestDenied', 'accessDenied', 'Forbidden')))

    if ($isPermission) {
        $need = 'Group.ReadWrite.All and a role that can create groups (e.g. Groups Administrator)'
        if ($RoleAssignable) {
            $need = 'Group.ReadWrite.All, RoleManagement.ReadWrite.Directory and the Privileged Role Administrator role'
        }
        return [PSCustomObject]@{
            ExitCode = $ExitCodePermission; ErrorId = 'GraphAccessDenied'
            Category = [System.Management.Automation.ErrorCategory]::PermissionDenied
            Message  = "Access denied$codeText. Requires $need. Graph message: $graphMessage"
        }
    }
    if ($Step -eq 'SignIn' -or ($Step -ne 'Input' -and $detail.StatusCode -eq 401)) {
        return [PSCustomObject]@{
            ExitCode = $ExitCodeSignIn; ErrorId = 'GraphSignInFailed'
            Category = [System.Management.Automation.ErrorCategory]::AuthenticationError
            Message  = "Microsoft Graph sign-in or session check failed$codeText. $($ErrorRecord.Exception.Message)"
        }
    }
    $prefixText = if ($Step -eq 'Input') { 'Input file error' } else { "Failed$codeText" }
    return [PSCustomObject]@{
        ExitCode = $ExitCodeError; ErrorId = 'NewEntraGroupsFailed'
        Category = [System.Management.Automation.ErrorCategory]::NotSpecified
        Message  = "$prefixText. $graphMessage"
    }
}

function ConvertTo-EntraGroupsResult {
    param(
        [Parameter(Mandatory)]
        [string]$InputName,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$DisplayName
    )

    [PSCustomObject]@{
        DisplayName    = $DisplayName
        Status         = ''
        GroupId        = ''
        RoleAssignable = $null
        MailNickname   = ''
        Owners         = ''
        InputName      = $InputName
        Detail         = ''
    }
}

$exitCode = $ExitCodeSuccess
$results = [System.Collections.Generic.List[object]]::new()
$step = 'Input'
try {
    Write-Verbose "New-EntraGroupsFromFile version $ScriptVersion"
    $names = Read-EntraGroupsInputFile -Path $InputFile
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $duplicates = @()
    foreach ($name in $names) {
        $displayName = Get-EntraGroupDisplayName -Name $name -Prefix $Prefix -Suffix $Suffix
        if (-not $seen.Add($displayName)) {
            $duplicates += $displayName
            continue
        }
        $row = ConvertTo-EntraGroupsResult -InputName $name -DisplayName $displayName
        $invalid = Test-EntraGroupDisplayName -DisplayName $displayName
        if ($invalid) {
            $row.Status = 'Failed'
            $row.Detail = $invalid
        }
        $results.Add($row)
    }
    if ($duplicates.Count -gt 0) {
        Write-Information "$($duplicates.Count) duplicate name(s) in the file ignored: $(($duplicates | Select-Object -Unique) -join ', ')"
    }
    if ($results.Count -eq 0) {
        Write-Warning "No group names found in '$InputFile'."
    }
    else {
        Write-Information "$($results.Count) unique group name(s) in '$InputFile'. Prefix: '$Prefix' Suffix: '$Suffix' RoleAssignable: $([bool]$RoleAssignable)"

        $step = 'SignIn'
        $null = Connect-EntraGroupsGraph -RequiredScopes $RequiredScopes -TenantId $TenantId -UseWAM:$UseWAM

        $step = 'Groups'
        # Phase 1: check all names before creating anything.
        $toCreate = [System.Collections.Generic.List[object]]::new()
        foreach ($row in $results) {
            if ($row.Status) {
                continue
            }
            try {
                $response = Invoke-EntraGroupsGraph -Method GET -Uri (Get-EntraGroupsFilterUri -DisplayName $row.DisplayName)
            }
            catch {
                $failure = Get-EntraGroupsFailure -ErrorRecord $_ -Step 'Groups'
                if ($failure.ExitCode -ne $ExitCodeError) {
                    throw
                }
                $row.Status = 'Failed'
                $row.Detail = "Existence check failed, group not created. $($failure.Message)"
                continue
            }
            $existing = @($response.value | Where-Object { $_ })
            if ($existing.Count -eq 0) {
                $row.MailNickname = Get-EntraGroupMailNickname -Name $row.DisplayName
                $row.RoleAssignable = [bool]$RoleAssignable
                $toCreate.Add($row)
                continue
            }
            $group = $existing[0]
            $row.GroupId = [string]$group.id
            $row.RoleAssignable = $group.isAssignableToRole
            $reasons = @(Get-EntraGroupMismatch -Group $group -RoleAssignable:$RoleAssignable)
            if ($existing.Count -gt 1) {
                $reasons += 'more than one group with this name'
                $row.GroupId = (@($existing | ForEach-Object { [string]$_.id })) -join ';'
            }
            if ([string]$group.displayName -cne $row.DisplayName) {
                $row.Detail = "Existing name: '$($group.displayName)'. "
            }
            if ($reasons.Count -gt 0) {
                $row.Status = 'ExistsMismatch'
                $row.Detail += ($reasons -join ', ')
            }
            else {
                $row.Status = 'Exists'
                $row.Detail = $row.Detail.Trim()
            }
        }

        # Role-assignable limit (500 per tenant).
        if ($RoleAssignable -and $toCreate.Count -gt 0) {
            try {
                $countUri = "$GraphBase/groups?`$filter=" + [uri]::EscapeDataString('isAssignableToRole eq true') + '&$count=true&$top=1&$select=id'
                $countResponse = Invoke-EntraGroupsGraph -Method GET -Uri $countUri -Headers @{ ConsistencyLevel = 'eventual' }
                $current = [int]$countResponse.'@odata.count'
                Write-Verbose "Role-assignable groups in tenant: $current"
                if ($current + $toCreate.Count -gt $MaxRoleAssignableGroups) {
                    throw "The tenant has $current role-assignable groups; creating $($toCreate.Count) more exceeds the limit of $MaxRoleAssignableGroups. No groups have been created."
                }
            }
            catch {
                if ($_.Exception.Message -like '*exceeds the limit*') {
                    throw
                }
                $failure = Get-EntraGroupsFailure -ErrorRecord $_ -Step 'Groups'
                if ($failure.ExitCode -ne $ExitCodeError) {
                    throw
                }
                Write-Warning "Could not count role-assignable groups (limit $MaxRoleAssignableGroups): $($failure.Message)"
            }
        }

        # Phase 2: create.
        foreach ($row in $toCreate) {
            $action = if ($RoleAssignable) { 'Create role-assignable security group' } else { 'Create security group' }
            if (-not $PSCmdlet.ShouldProcess($row.DisplayName, $action)) {
                if ($WhatIfPreference) {
                    $row.Status = 'WouldCreate'
                }
                else {
                    $row.Status = 'Declined'
                }
                continue
            }
            $body = [ordered]@{
                displayName     = $row.DisplayName
                mailNickname    = $row.MailNickname
                mailEnabled     = $false
                securityEnabled = $true
            }
            if ($Description) { $body['description'] = $Description }
            if ($RoleAssignable) { $body['isAssignableToRole'] = $true }
            try {
                $created = Invoke-EntraGroupsGraph -Method POST -Uri "$GraphBase/groups" -Body (ConvertTo-AsciiJson -Body $body)
            }
            catch {
                $failure = Get-EntraGroupsFailure -ErrorRecord $_ -Step 'Groups'
                if ($failure.ExitCode -ne $ExitCodeError) {
                    throw
                }
                $row.Status = 'Failed'
                $row.Detail = $failure.Message
                continue
            }
            $row.Status = 'Created'
            $row.GroupId = [string]$created.id
            try {
                $ownersUri = "$GraphBase/groups/$($created.id)/owners?`$select=id,displayName,userPrincipalName"
                $owners = @((Invoke-EntraGroupsGraph -Method GET -Uri $ownersUri -RetryNotFound).value | Where-Object { $_ })
                if ($owners.Count -gt 0) {
                    $row.Owners = (@($owners | ForEach-Object { if ($_.userPrincipalName) { [string]$_.userPrincipalName } else { [string]$_.id } })) -join ';'
                    Write-Warning "Group '$($row.DisplayName)' has owner(s): $($row.Owners). Owners can change membership outside PIM; remove them if not intended."
                }
            }
            catch {
                $row.Detail = 'Owners could not be read.'
                Write-Warning "Could not read owners of '$($row.DisplayName)': $($_.Exception.Message)"
            }
        }
    }
}
catch {
    $failure = Get-EntraGroupsFailure -ErrorRecord $_ -Step $step
    $exitCode = $failure.ExitCode
    Write-Error -Message $failure.Message -Category $failure.Category -ErrorId $failure.ErrorId -ErrorAction Continue
}
finally {
    Restore-EntraGroupsWam
}

foreach ($row in $results) {
    if (-not $row.Status) {
        $row.Status = 'Failed'
        $row.Detail = 'Not processed: the run stopped.'
    }
    Write-Information ("[{0}] {1}{2}" -f $row.Status, $row.DisplayName, $(if ($row.Detail) { " - $($row.Detail)" } else { '' }))
}
$statusOrder = @('Created', 'WouldCreate', 'Exists', 'ExistsMismatch', 'Declined', 'Failed')
$summary = foreach ($status in $statusOrder) {
    $count = @($results | Where-Object { $_.Status -eq $status }).Count
    if ($count -gt 0 -or $status -in @('Created', 'Exists', 'Failed')) { "${status}: $count" }
}
Write-Information "Done. $($summary -join ', ')"
$mismatchCount = @($results | Where-Object { $_.Status -eq 'ExistsMismatch' }).Count
if ($mismatchCount -gt 0) {
    Write-Warning "$mismatchCount existing group(s) do not match the expected type (ExistsMismatch). Check them manually."
}
if ($exitCode -eq $ExitCodeSuccess -and @($results | Where-Object { $_.Status -eq 'Failed' }).Count -gt 0) {
    $exitCode = $ExitCodeError
}

if ($OutputPath) {
    try {
        if ($PSCmdlet.ShouldProcess($OutputPath, 'Export results as CSV')) {
            Export-EntraGroupsCsv -Report @($results) -Path $OutputPath -Columns $ResultColumns
            Write-Information "Results exported to $OutputPath"
        }
    }
    catch {
        Write-Error -Message "Could not write $OutputPath. $($_.Exception.Message)" -ErrorAction Continue
        if ($exitCode -eq $ExitCodeSuccess) {
            $exitCode = $ExitCodeError
        }
    }
}
if ($PassThru -or -not $OutputPath) {
    Write-Output $results.ToArray()
}
exit $exitCode

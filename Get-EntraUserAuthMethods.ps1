#Requires -Version 5.1
<#
.SYNOPSIS
    Retrieves all Entra ID users' registered and preferred authentication methods using Microsoft Graph.
.DESCRIPTION
    Uses the Microsoft Graph authentication methods registration report to list all users along with
    their registered authentication methods, preferred authentication method, and MFA/SSPR status.
    Account enabled/disabled status is added from the users endpoint, and registered methods that are
    disabled in the tenant Authentication Methods policy are reported as non-usable.
    Results can be exported to CSV and to an interactive HTML report with client side filtering.
    Only read-only Graph calls (GET) are used.
.PARAMETER OutputPath
    Optional path to export the results as CSV. If omitted, no CSV is created.
.PARAMETER HtmlPath
    Optional path to export the results as an interactive HTML report with client side filtering.
.PARAMETER TenantId
    Optional tenant ID to connect to a specific tenant.
.EXAMPLE
    .\Get-EntraUserAuthMethods.ps1 -OutputPath C:\Reports\AuthMethods.csv
.EXAMPLE
    .\Get-EntraUserAuthMethods.ps1 -HtmlPath C:\Reports\AuthMethods.html
.NOTES
    Kasper Johansen | Apento
    kmj@apento.com

    Version: 1.5.0
    Updated: 2026-10-08

    Changelog
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

    Required Graph permission (delegated or application): AuditLog.Read.All, User.Read.All, Policy.Read.All
    AuditLog.Read.All grants read access to the authentication methods registration report.
    User.Read.All grants read access to each user's enabled/disabled account status.
    Policy.Read.All grants read access to the tenant Authentication Methods policy, used to
    determine which registered methods are disabled in the tenant and therefore non-usable.
    No write, update or delete calls are made anywhere in this script.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$HtmlPath,

    [Parameter()]
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '1.5.0'

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

    # Maps registered method names to the Authentication Methods policy configuration(s) that govern them.
    # A method is usable if at least one of its governing configurations is enabled.
    $methodMap = @{
        'mobilePhone'                        = @('Sms', 'Voice')
        'alternateMobilePhone'               = @('Sms', 'Voice')
        'officePhone'                        = @('Voice')
        'microsoftAuthenticatorPush'         = @('MicrosoftAuthenticator')
        'microsoftAuthenticatorPasswordless' = @('MicrosoftAuthenticator')
        'softwareOneTimePasscode'            = @('SoftwareOath', 'MicrosoftAuthenticator')
        'hardwareOneTimePasscode'            = @('HardwareOath')
        'fido2'                              = @('Fido2')
        'passKeyDeviceBound'                 = @('Fido2')
        'passKeyDeviceBoundAuthenticator'    = @('Fido2')
        'passKeyDeviceBoundWindowsHello'     = @('Fido2')
        'temporaryAccessPass'                = @('TemporaryAccessPass')
    }

    $nonUsable = foreach ($method in $RegisteredMethods) {
        if ($methodMap.ContainsKey($method)) {
            $usable = $false
            foreach ($policyId in $methodMap[$method]) {
                if ($PolicyState[$policyId] -eq 'enabled') {
                    $usable = $true
                }
            }
            if (-not $usable) {
                $method
            }
        }
    }

    return ($nonUsable -join '; ')
}

function New-AuthMethodsHtmlReport {
    param(
        [Parameter(Mandatory)]
        [array]$Report
    )

    $generatedOn = Get-Date -Format "yyyy-MM-dd HH:mm"
    $totalUsers = $Report.Count
    $mfaRegisteredCount = ($Report | Where-Object { $_.IsMfaRegistered }).Count
    $ssprRegisteredCount = ($Report | Where-Object { $_.IsSsprRegistered }).Count
    $passwordlessCount = ($Report | Where-Object { $_.IsPasswordlessCapable }).Count

    $userTypes = $Report | Select-Object -ExpandProperty UserType -Unique | Sort-Object
    $preferredMethods = $Report | Select-Object -ExpandProperty PreferredAuthMethod -Unique | Sort-Object

    $userTypeOptions = ($userTypes | ForEach-Object { "<option value=`"$_`">$_</option>" }) -join ""
    $preferredMethodOptions = ($preferredMethods | ForEach-Object { "<option value=`"$_`">$_</option>" }) -join ""

    $nonUsableMethodList = $Report |
        Where-Object { $_.NonUsableMethods } |
        ForEach-Object { $_.NonUsableMethods -split '; ' } |
        Select-Object -Unique |
        Sort-Object
    $nonUsableOptions = ($nonUsableMethodList | ForEach-Object { "<option value=`"$($_.ToLower())`">$_</option>" }) -join ""

    $rows = foreach ($user in $Report) {
        $mfaClass = if ($user.IsMfaRegistered) { "yes" } else { "no" }
        $ssprClass = if ($user.IsSsprRegistered) { "yes" } else { "no" }
        $adminClass = if ($user.IsAdmin) { "yes" } else { "no" }
        $statusClass = if ($user.AccountEnabled) { "yes" } else { "no" }
        $statusText = if ($user.AccountEnabled) { "Enabled" } else { "Disabled" }
        $nonUsableClass = if ($user.NonUsableMethods) { "no" } else { "" }
        $passwordlessClass = if ($user.IsPasswordlessCapable) { "yes" } else { "no" }

        @"
        <tr data-usertype="$($user.UserType)" data-admin="$($user.IsAdmin)" data-status="$($user.AccountEnabled)" data-mfa="$($user.IsMfaRegistered)" data-sspr="$($user.IsSsprRegistered)" data-preferred="$($user.PreferredAuthMethod)" data-methods="$($user.MethodsRegistered.ToLower())" data-nonusable="$($user.NonUsableMethods.ToLower())">
            <td>$($user.DisplayName)</td>
            <td>$($user.UserPrincipalName)</td>
            <td>$($user.UserType)</td>
            <td class="$adminClass">$($user.IsAdmin)</td>
            <td class="$statusClass">$statusText</td>
            <td class="$mfaClass">$($user.IsMfaRegistered)</td>
            <td class="$ssprClass">$($user.IsSsprRegistered)</td>
            <td class="$passwordlessClass">$($user.IsPasswordlessCapable)</td>
            <td>$($user.MethodsRegistered)</td>
            <td class="$nonUsableClass">$($user.NonUsableMethods)</td>
            <td>$($user.PreferredAuthMethod)</td>
            <td>$($user.SystemPreferredMethod)</td>
            <td>$($user.LastUpdated)</td>
        </tr>
"@
    }
    $rowsHtml = $rows -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Entra Authentication Methods Report</title>
<style>
    :root { --border: #d9dde3; --head: #1f2937; --yes: #1a7f37; --no: #b42318; }
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f7f8fa; }
    h1 { font-size: 20px; margin-bottom: 4px; }
    .meta { color: #6b7280; font-size: 13px; margin-bottom: 20px; }
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
    .table-wrap { max-height: 70vh; overflow: auto; border: 1px solid var(--border); border-radius: 6px; }
    #rowCount { font-size: 12px; color: #6b7280; margin: 8px 0; }
</style>
</head>
<body>

<h1>Entra ID Authentication Methods Report</h1>
<div class="meta">Generated $generatedOn | Script version $ScriptVersion</div>

<div class="summary">
    <div class="card"><div class="num">$totalUsers</div><div class="label">Total users</div></div>
    <div class="card"><div class="num">$mfaRegisteredCount</div><div class="label">MFA registered</div></div>
    <div class="card"><div class="num">$ssprRegisteredCount</div><div class="label">SSPR registered</div></div>
    <div class="card"><div class="num">$passwordlessCount</div><div class="label">Passwordless capable</div></div>
</div>

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
        <select id="statusFilter"><option value="">All</option><option value="True">Enabled</option><option value="False">Disabled</option></select>
    </div>
    <div>
        <label for="mfaFilter">MFA registered</label>
        <select id="mfaFilter"><option value="">All</option><option value="True">Yes</option><option value="False">No</option></select>
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

    [searchBox, userTypeFilter, adminFilter, statusFilter, mfaFilter, ssprFilter, preferredFilter, methodsFilter, nonUsableFilter].forEach(function (el) {
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

try {
    if (-not (Get-MgContext)) {
        $connectParams = @{
            Scopes = @('AuditLog.Read.All', 'User.Read.All', 'Policy.Read.All')
        }
        if ($TenantId) {
            $connectParams['TenantId'] = $TenantId
        }
        Connect-MgGraph @connectParams
    }

    Write-Verbose "Get-EntraUserAuthMethods version $ScriptVersion"
    Write-Verbose "Retrieving user authentication method registration details"
    $uri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999'
    $registrationDetails = Get-MgGraphAllPages -Uri $uri

    Write-Verbose "Retrieving user account enabled/disabled status"
    $usersUri = 'https://graph.microsoft.com/v1.0/users?$select=id,accountEnabled&$top=999'
    $userAccountDetails = Get-MgGraphAllPages -Uri $usersUri

    $accountStatusLookup = @{}
    foreach ($accountUser in $userAccountDetails) {
        $accountStatusLookup[$accountUser.id] = $accountUser.accountEnabled
    }

    Write-Verbose "Retrieving tenant authentication methods policy"
    $policyUri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    $authMethodsPolicy = Invoke-MgGraphRequest -Method GET -Uri $policyUri

    $policyState = @{}
    foreach ($methodConfig in $authMethodsPolicy.authenticationMethodConfigurations) {
        $policyState[$methodConfig.id] = $methodConfig.state
    }

    $report = foreach ($user in $registrationDetails) {
        $accountEnabled = $accountStatusLookup[$user.id]

        [PSCustomObject]@{
            UserPrincipalName     = $user.userPrincipalName
            DisplayName           = $user.userDisplayName
            UserType              = $user.userType
            AccountEnabled        = $accountEnabled
            IsAdmin               = $user.isAdmin
            IsMfaRegistered       = $user.isMfaRegistered
            IsMfaCapable          = $user.isMfaCapable
            IsSsprRegistered      = $user.isSsprRegistered
            IsSsprEnabled         = $user.isSsprEnabled
            IsPasswordlessCapable = $user.isPasswordlessCapable
            MethodsRegistered     = ($user.methodsRegistered -join '; ')
            NonUsableMethods      = Get-NonUsableMethods -RegisteredMethods $user.methodsRegistered -PolicyState $policyState
            PreferredAuthMethod   = $user.userPreferredMethodForSecondaryAuthentication
            SystemPreferredMethod = $user.systemPreferredAuthenticationMethod
            LastUpdated           = $user.lastUpdatedDateTime
        }
    }

    if ($OutputPath) {
        if ($PSCmdlet.ShouldProcess($OutputPath, "Export authentication method report as CSV")) {
            $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            Write-Host "CSV report exported to $OutputPath"
        }
    }

    if ($HtmlPath) {
        if ($PSCmdlet.ShouldProcess($HtmlPath, "Export authentication method report as HTML")) {
            $htmlContent = New-AuthMethodsHtmlReport -Report $report
            Set-Content -Path $HtmlPath -Value $htmlContent -Encoding UTF8
            Write-Host "HTML report exported to $HtmlPath"
        }
    }

    return $report
}
catch {
    Write-Error "Failed to retrieve authentication method report: $($_.Exception.Message)"
}

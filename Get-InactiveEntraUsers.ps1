#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Reports inactive Entra ID user accounts based on sign-in and/or activity thresholds.

.DESCRIPTION
    Retrieves users from Microsoft Graph and flags those inactive beyond the specified
    thresholds. Inactivity is measured via the signInActivity property, which requires
    Entra ID P1 or P2 licensing.

    When both -InactiveDaysSignIn and -InactiveDaysActivity are supplied, the default
    logic is OR: a user is flagged if either threshold is exceeded. Use -RequireAll
    to switch to AND (both thresholds must be exceeded).

    Required scopes  : AuditLog.Read.All, User.Read.All
    Disable accounts : also requires User.EnableDisableAccount.All

.PARAMETER UserType
    Scope results to Member, Guest, or All (default) user types.

.PARAMETER SyncType
    Scope results by identity source: CloudOnly (Entra-only accounts),
    Synced (AD-synced accounts), or All (default).

.PARAMETER InactiveDaysSignIn
    Flag users whose last interactive sign-in is older than this many days.

.PARAMETER InactiveDaysActivity
    Flag users whose last activity (most recent of interactive or non-interactive
    sign-in) is older than this many days.

.PARAMETER RequireAll
    When both thresholds are specified, require BOTH to be exceeded (AND logic).
    Default when both are specified is OR.

.PARAMETER IncludeNeverSignedIn
    Include accounts that have no sign-in record at all.

.PARAMETER DisableUsers
    Disable matched accounts. Supports -WhatIf and -Confirm.

.PARAMETER ExportCsv
    Full path to write a CSV export of the results.

.OUTPUTS
    PSCustomObject with DisplayName, UserPrincipalName, UserType, OnPremisesSynced,
    AccountEnabled, Mail, CreatedDateTime, DaysSinceCreated, LastSignInDateTime,
    DaysSinceSignIn, LastNonInteractiveSignInDateTime, LastActivityDateTime,
    DaysSinceActivity, ObjectId.

.EXAMPLE
    .\Find-InactiveEntraUsers.ps1 -InactiveDaysSignIn 90 -UserType Guest
    Flag guest users with no interactive sign-in in the last 90 days.

.EXAMPLE
    .\Find-InactiveEntraUsers.ps1 -InactiveDaysActivity 60 -SyncType CloudOnly -IncludeNeverSignedIn
    Flag cloud-only users with no activity in 60 days, including never-signed-in accounts.

.EXAMPLE
    .\Find-InactiveEntraUsers.ps1 -InactiveDaysActivity 60 -IncludeNeverSignedIn -ExportCsv "C:\Reports\inactive.csv"
    Flag all users with no activity in 60 days, include never-signed-in, export to CSV.

.EXAMPLE
    .\Find-InactiveEntraUsers.ps1 -InactiveDaysSignIn 90 -InactiveDaysActivity 90 -RequireAll -SyncType Synced -DisableUsers -WhatIf
    Preview disabling AD-synced accounts inactive by both metrics for 90+ days.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [ValidateSet("Member", "Guest", "All")]
    [string]$UserType = "All",

    [ValidateSet("CloudOnly", "Synced", "All")]
    [string]$SyncType = "All",

    [ValidateRange(1, 3650)]
    [int]$InactiveDaysSignIn,

    [ValidateRange(1, 3650)]
    [int]$InactiveDaysActivity,

    [switch]$RequireAll,
    [switch]$IncludeNeverSignedIn,
    [switch]$DisableUsers,
    [string]$ExportCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Parameter validation ----
$filterBySignIn   = $PSBoundParameters.ContainsKey("InactiveDaysSignIn")
$filterByActivity = $PSBoundParameters.ContainsKey("InactiveDaysActivity")

if (-not $filterBySignIn -and -not $filterByActivity) {
    throw "Specify at least one of -InactiveDaysSignIn or -InactiveDaysActivity."
}

if ($ExportCsv) {
    $csvParent = Split-Path -Path $ExportCsv -Parent
    if ($csvParent -and -not (Test-Path -Path $csvParent)) {
        throw "CSV export directory does not exist: $csvParent"
    }
}

# ---- Graph connection and scope validation ----
$neededScopes = [System.Collections.Generic.List[string]]@("AuditLog.Read.All", "User.Read.All")
if ($DisableUsers) { $neededScopes.Add("User.EnableDisableAccount.All") }

$ctx = Get-MgContext
if (-not $ctx) {
    Write-Verbose "No active Graph session - connecting..."
    Connect-MgGraph -Scopes $neededScopes -NoWelcome
    $ctx = Get-MgContext
}

$missingScopes = $neededScopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missingScopes) {
    throw "Active session is missing required scope(s): $($missingScopes -join ', '). Reconnect with the required scopes."
}

# ---- Build Graph query URI ----
$selectProps = "id,displayName,userPrincipalName,userType,accountEnabled,mail,createdDateTime,signInActivity,onPremisesSyncEnabled"
$queryParts  = [System.Collections.Generic.List[string]]@(
    "`$select=$selectProps",
    "`$top=999",
    "`$count=true"
)

$filterClauses = [System.Collections.Generic.List[string]]::new()
if ($UserType -ne "All") {
    $filterClauses.Add("userType eq '$UserType'")
}
switch ($SyncType) {
    "CloudOnly" { $filterClauses.Add("onPremisesSyncEnabled eq null") }
    "Synced"    { $filterClauses.Add("onPremisesSyncEnabled eq true") }
}
if ($filterClauses.Count -gt 0) {
    $queryParts.Add("`$filter=" + ($filterClauses -join " and "))
}
$baseUri = "https://graph.microsoft.com/v1.0/users?" + ($queryParts -join "&")

# ---- Paginated retrieval with retry ----
$allUsers = [System.Collections.Generic.List[object]]::new()
$nextUri  = $baseUri
$page     = 0

Write-Verbose "Retrieving users from Entra ID..."

do {
    $page++
    $attempt  = 0
    $response = $null

    while ($null -eq $response) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri `
                -Headers @{ ConsistencyLevel = "eventual" }
        } catch {
            $attempt++
            if ($attempt -le 3 -and $_.Exception.Message -match "429|503|throttl") {
                $delay = [math]::Pow(2, $attempt) + (Get-Random -Maximum 3)
                Write-Warning "Throttled on page $page - retry $attempt in ${delay}s..."
                Start-Sleep -Seconds $delay
            } else {
                throw "Graph request failed (page $($page)): $($_.Exception.Message)"
            }
        }
    }

    foreach ($u in $response.value) { $allUsers.Add($u) }
    $nextUri = $response['@odata.nextLink']
    Write-Verbose "Page $page - $($response.value.Count) users (running total: $($allUsers.Count))"

} while ($nextUri)

Write-Verbose "Total users retrieved: $($allUsers.Count)"

# ---- Cutoff dates ----
$now            = [datetime]::UtcNow
$signInCutoff   = if ($filterBySignIn)   { $now.AddDays(-$InactiveDaysSignIn) }   else { $null }
$activityCutoff = if ($filterByActivity) { $now.AddDays(-$InactiveDaysActivity) } else { $null }

# ---- Evaluate users ----
$results = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($user in $allUsers) {
    $sia = $user.signInActivity

    # Parse sign-in timestamps (PS 5.1-compatible null checks)
    $dtInteractive    = if ($sia -and $sia.lastSignInDateTime)              { [datetime]$sia.lastSignInDateTime }              else { $null }
    $dtNonInteractive = if ($sia -and $sia.lastNonInteractiveSignInDateTime) { [datetime]$sia.lastNonInteractiveSignInDateTime } else { $null }

    $hasAnySignIn = ($null -ne $dtInteractive) -or ($null -ne $dtNonInteractive)
    if (-not $hasAnySignIn -and -not $IncludeNeverSignedIn) { continue }

    # Most recent activity across both sign-in types
    $dtActivity = if ($dtInteractive -and $dtNonInteractive) {
        if ($dtInteractive -gt $dtNonInteractive) { $dtInteractive } else { $dtNonInteractive }
    } elseif ($dtInteractive)    { $dtInteractive }
    elseif ($dtNonInteractive)   { $dtNonInteractive }
    else                         { $null }

    # Threshold evaluation
    $failsSignIn   = $filterBySignIn   -and ((-not $dtInteractive) -or ($dtInteractive -lt $signInCutoff))
    $failsActivity = $filterByActivity -and ((-not $dtActivity)    -or ($dtActivity    -lt $activityCutoff))

    $matched = if ($filterBySignIn -and $filterByActivity) {
        if ($RequireAll) { $failsSignIn -and $failsActivity } else { $failsSignIn -or $failsActivity }
    } elseif ($filterBySignIn) {
        $failsSignIn
    } else {
        $failsActivity
    }

    if (-not $matched) { continue }

    $results.Add([pscustomobject]@{
        DisplayName                      = $user.displayName
        UserPrincipalName                = $user.userPrincipalName
        UserType                         = $user.userType
        OnPremisesSynced                 = ($user.onPremisesSyncEnabled -eq $true)
        AccountEnabled                   = $user.accountEnabled
        Mail                             = $user.mail
        CreatedDateTime                  = $user.createdDateTime
        DaysSinceCreated                 = [int][math]::Round(($now - [datetime]$user.createdDateTime).TotalDays)
        LastSignInDateTime               = $dtInteractive
        DaysSinceSignIn                  = if ($dtInteractive)    { [int][math]::Round(($now - $dtInteractive).TotalDays) }    else { $null }
        LastNonInteractiveSignInDateTime = $dtNonInteractive
        LastActivityDateTime             = $dtActivity
        DaysSinceActivity                = if ($dtActivity)        { [int][math]::Round(($now - $dtActivity).TotalDays) }      else { $null }
        ObjectId                         = $user.id
    })
}

Write-Verbose "Matched: $($results.Count) inactive user(s)."

# ---- Console output ----
if ($results.Count -eq 0) {
    Write-Host "No users matched the inactive criteria." -ForegroundColor Yellow
} else {
    $results | Format-Table DisplayName, UserPrincipalName, UserType, OnPremisesSynced,
        AccountEnabled, DaysSinceSignIn, DaysSinceActivity -AutoSize | Out-Host
    Write-Host "Matched: $($results.Count) inactive user(s)." -ForegroundColor Cyan
}

# ---- Optional: disable accounts ----
if ($DisableUsers -and $results.Count -gt 0) {
    $disabled = 0
    $errors   = 0

    foreach ($r in $results) {
        if (-not $r.AccountEnabled) {
            Write-Verbose "Already disabled, skipping: $($r.UserPrincipalName)"
            continue
        }

        if ($PSCmdlet.ShouldProcess($r.UserPrincipalName, "Disable Entra ID account")) {
            try {
                Invoke-MgGraphRequest -Method PATCH `
                    -Uri "https://graph.microsoft.com/v1.0/users/$($r.ObjectId)" `
                    -Body (@{ accountEnabled = $false } | ConvertTo-Json -Compress) `
                    -ContentType "application/json"
                $disabled++
                Write-Verbose "Disabled: $($r.UserPrincipalName)"
            } catch {
                Write-Warning "Failed to disable $($r.UserPrincipalName): $($_.Exception.Message)"
                $errors++
            }
        }
    }

    Write-Host "Disabled: $disabled | Errors: $errors" -ForegroundColor Cyan
}

# ---- Optional: CSV export ----
if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $($results.Count) record(s) to: $ExportCsv" -ForegroundColor Green
}

# Pipeline output for programmatic use
$results
#Requires -Version 5.1
<#
.SYNOPSIS
    Creates Entra ID security groups from a plain-text input file.
.DESCRIPTION
    Reads group display names from a UTF-8 text file (one name per line).
    Blank lines and lines beginning with '#' are ignored.
    Each group is created as a cloud-only, assigned-membership security group.
    Groups whose display name already exists in the tenant are skipped.
    MailNickname is auto-derived from the final display name (after prefix/suffix are applied).
.PARAMETER InputFile
    Path to the input file. One group display name per line.
    Lines starting with '#' are treated as comments.
.PARAMETER Description
    Optional description applied to every created group.
.PARAMETER Prefix
    Optional string prepended to every group display name (e.g. 'SG-').
.PARAMETER Suffix
    Optional string appended to every group display name (e.g. '-Prod').
.EXAMPLE
    .\New-EntraGroupsFromFile.ps1 -InputFile .\groups.txt
.EXAMPLE
    .\New-EntraGroupsFromFile.ps1 -InputFile .\groups.txt -Prefix "SG-" -Suffix "-Prod"
.EXAMPLE
    .\New-EntraGroupsFromFile.ps1 -InputFile .\groups.txt -Prefix "SG-" -Description "Managed by Intune" -WhatIf
.NOTES
    Author      : Kasper Johansen - Apento
    Email       : kmj@apento.com
    Requires    : Microsoft.Graph.Authentication
    Permissions : Group.ReadWrite.All
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$InputFile,

    [Parameter()]
    [string]$Description = '',

    [Parameter()]
    [string]$Prefix = '',

    [Parameter()]
    [string]$Suffix = '',

    [Parameter()]
    [string]$TenantId = ''
)

$ErrorActionPreference = 'Stop'

function Get-MailNickname {
    param([string]$Name)
    # Replace everything except alphanumeric, underscore, hyphen with underscore; collapse runs
    $nick = ($Name -replace '[^a-zA-Z0-9_-]', '_' -replace '_+', '_').Trim('_-').ToLower()
    # mailNickname must start with a letter
    if ($nick -notmatch '^[a-z]') { $nick = 'g_' + $nick }
    if ($nick.Length -gt 64) { $nick = $nick.Substring(0, 64).TrimEnd('_-') }
    if (-not $nick) { $nick = 'g_' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8) }
    return $nick
}

#region Connect
$requiredScopes = @('Group.ReadWrite.All')
$needConnect = $false

try {
    $ctx = Get-MgContext
    if (-not $ctx) {
        $needConnect = $true
    } else {
        $missing = @($requiredScopes | Where-Object { $_ -notin $ctx.Scopes })
        if ($missing.Count -gt 0) { $needConnect = $true }
    }
} catch {
    $needConnect = $true
}

if ($needConnect) {
    $connectParams = @{ Scopes = $requiredScopes; NoWelcome = $true }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }
    Connect-MgGraph @connectParams
}
#endregion

#region Parse input file
$names = @(
    Get-Content -LiteralPath $InputFile -Encoding UTF8 |
        Where-Object { $_ -and $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith('#') } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
)

if ($names.Count -eq 0) {
    Write-Warning "No valid group names found in '$InputFile'."
    return
}
Write-Host "Found $($names.Count) unique group name(s)." -ForegroundColor Cyan
if ($Prefix -or $Suffix) {
    Write-Host "Applying prefix: '$Prefix'  suffix: '$Suffix'" -ForegroundColor Cyan
}
#endregion

#region Create groups
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($name in $names) {
    $displayName = ($Prefix + $name + $Suffix).Trim()

    # Escape single quotes for OData filter
    $oDataName = $displayName -replace "'", "''"

    # Check whether the group already exists
    $existingId = $null
    try {
        $check = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$oDataName'&`$select=id&`$top=1" `
            -Headers @{ ConsistencyLevel = 'eventual' }
        if ($check.value -and $check.value.Count -gt 0) {
            $existingId = $check.value[0].id
        }
    } catch {
        Write-Warning "  [WARN] Existence check failed for '$displayName': $($_.Exception.Message)"
    }

    if ($existingId) {
        Write-Host "  [SKIP] $displayName" -ForegroundColor Yellow
        $results.Add([PSCustomObject]@{ DisplayName = $displayName; Status = 'Skipped'; GroupId = $existingId })
        continue
    }

    $body = [ordered]@{
        displayName     = $displayName
        mailNickname    = Get-MailNickname -Name $displayName
        mailEnabled     = $false
        securityEnabled = $true
        groupTypes      = @()
    }
    if ($Description) { $body['description'] = $Description }

    if ($PSCmdlet.ShouldProcess($displayName, 'Create security group')) {
        try {
            $group = Invoke-MgGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/v1.0/groups' `
                -Body ($body | ConvertTo-Json -Depth 3) `
                -ContentType 'application/json'

            Write-Host "  [OK]   $displayName  ($($group.id))" -ForegroundColor Green
            $results.Add([PSCustomObject]@{ DisplayName = $displayName; Status = 'Created'; GroupId = $group.id })
        } catch {
            Write-Warning "  [FAIL] '$displayName': $($_.Exception.Message)"
            $results.Add([PSCustomObject]@{ DisplayName = $displayName; Status = 'Failed'; GroupId = '' })
        }
    }
}
#endregion

#region Summary
$created = @($results | Where-Object { $_.Status -eq 'Created' }).Count
$skipped = @($results | Where-Object { $_.Status -eq 'Skipped' }).Count
$failed  = @($results | Where-Object { $_.Status -eq 'Failed' }).Count

Write-Host "`nDone. Created: $created  Skipped: $skipped  Failed: $failed" -ForegroundColor Cyan
$results | Format-Table -AutoSize
#endregion
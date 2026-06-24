<#PSScriptInfo
.VERSION
    4.5

.GUID
    e3b2f1a7-4c8d-4e9f-b1d2-7a6c5e8f3b2d

.AUTHOR
    Kasper Johansen

.COMPANYNAME
    KMJ-Consulting

.COPYRIGHT
    (c) Kasper Johansen. All rights reserved.

.TAGS
    Intune, EntraID, AzureAD, GraphAPI, DeviceManagement, StaleDevices, MDM, MEM

.LICENSEURI

.PROJECTURI
    https://kasperjohansen.net

.ICONURI

.EXTERNALMODULEDEPENDENCIES
    Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
    v4.5 - Added signed-in user name, UPN and assigned directory roles to the
           connection status card. The /me call is expanded to include displayName
           and userPrincipalName. Role displayNames are fetched alongside roleTemplateIds
           in the transitiveMemberOf call and passed through /status as the roles array.
           Roles that grant write access are shown with an accent-coloured pill;
           read-only roles use the default muted pill style.
    v4.4 - Fixed permission indicator showing Read/Write for Global Reader accounts.
           The previous check used OAuth scopes (Device.ReadWrite.All) which are
           granted at the app consent level and do not reflect the signed-in user's
           Entra directory role. Replaced with a GET /v1.0/me/transitiveMemberOf
           role check against the known roleTemplateIds for Cloud Device Admin,
           Intune Admin, Windows 365 Admin, Global Admin, and Privileged Role Admin.
           Updated tooltips to reference the Entra directory role rather than scopes.
    v4.3 - Added permission indicator to the connection status banner. After auth,
           the actual granted scopes are checked via Get-MgContext. If
           Device.ReadWrite.All was not granted (consent denied or insufficient
           Entra role), a Read-only amber pill is shown and the Disable and Remove
           buttons are disabled with a tooltip explaining why. A Read/Write green
           pill is shown when write access is confirmed. The readOnly flag is
           passed from the PS listener to the browser via the /status endpoint.
    v4.2 - Added Last check-in date column to the results table showing the
           absolute locale date of the last sign-in alongside the existing
           relative age column. Also added to the CSV export as LastSignInDate.
    v4.1 - Fixed pendingAction being nulled by closeConfirm() before executeAction()
           could read it, causing "Starting null on N device(s)" and "Unknown action"
           errors when removing or disabling devices from the UI.
           Fixed raw Unicode characters (tick, cross, em-dash) being mangled in the
           HTTP response by replacing them with HTML entities (&#10003;, &#10007;,
           &mdash;) which are ASCII-safe regardless of encoding.
           Fixed Ctrl+C not stopping the listener by replacing the blocking
           GetContext() call with async BeginGetContext() polled every 500 ms.
           Fixed double login prompt by moving Connect-MgGraph before the HTTP
           listener starts so the auth flow cannot block the listener thread.
           Fixed last sign-in and registered dates not displaying by casting Graph
           datetime values to ISO 8601 strings before ConvertTo-Json serialisation,
           avoiding the legacy /Date(...)/ format emitted by PowerShell 5.1.
           Fixed null-coalescing operator (??) on line 45 replaced with PS 5.1
           compatible if/else for Retry-After handling.
           Changed Connected status banner to show the tenant primary domain name
           instead of the tenant GUID, resolved via GET /v1.0/organization.
    v4.0 - Added browser-based UI via embedded HTTP listener. Authentication now
           happens before the listener starts to avoid thread-blocking issues.
           Ctrl+C handled cleanly via async BeginGetContext polling.
    v3.0 - Implemented -DisableDevice and -RemoveDevice actions. Added pagination
           via Get-GraphPagedResults. Added WhatIf/Confirm support. Moved to
           Graph API v1.0. Fixed DeviceId vs ObjectId for mutations.
    v2.0 - Added -DisabledDevices scope, -ExportToCSV, and Graph session reuse.
    v1.0 - Initial release.
#>

<#
.SYNOPSIS
    Identifies and manages stale or disabled devices in Microsoft Entra ID via
    a browser-based UI backed by a local Microsoft Graph API HTTP listener.

.DESCRIPTION
    Cleanup-StaleDevices launches a local HTTP server and opens a browser UI
    for querying, reviewing, and acting on stale or disabled Entra ID devices
    without requiring any parameters to be typed on the command line.

    Authentication to Microsoft Graph is handled before the UI starts. The script
    requests Device.ReadWrite.All so both read and write operations are covered
    by a single cached token, avoiding double login prompts.

    The UI supports:
      - Filtering by join type (Entra joined, Hybrid joined, Registered)
      - Filtering by operating system
      - Querying stale devices by inactivity threshold (days since last sign-in)
      - Querying all disabled devices regardless of last sign-in
      - Selecting individual or all devices for bulk action
      - Disabling selected devices (accountEnabled = false)
      - Permanently removing selected devices from Entra ID
      - Exporting results to a CSV file directly from the browser
      - Colour-coded last sign-in ages (amber > 90 days, red > 180 days)

    Disable and Remove operations include a confirmation dialog in the UI and use
    a retry loop with Retry-After handling for Graph API throttling (HTTP 429).

    Press Ctrl+C in the PowerShell window to stop the listener and exit.

.PARAMETER Port
    TCP port for the local HTTP listener. Default is 8734.
    Change this if the default port is already in use on the machine.

.EXAMPLE
    .\Cleanup-StaleDevices-v4.ps1

    Connects to Microsoft Graph (browser auth prompt), then opens the UI at
    http://localhost:8734. Use the UI to set filters and query devices.

.EXAMPLE
    .\Cleanup-StaleDevices-v4.ps1 -Port 9000

    Starts the listener on port 9000 instead of the default 8734. Useful if
    another process is already bound to 8734.

.EXAMPLE
    # Typical stale device cleanup workflow:
    # 1. Run the script - authenticate in the browser window that opens first.
    # 2. In the UI, set Join type = Entra joined, OS = Windows, threshold = 90 days.
    # 3. Click Query devices to retrieve matching devices.
    # 4. Review the table - last sign-in ages are colour-coded for quick triage.
    # 5. Select devices to act on, click Disable selected, confirm in the dialog.
    # 6. Once satisfied, select remaining and click Remove selected.
    # 7. Press Ctrl+C in the PowerShell window to stop the listener.

.EXAMPLE
    # Reviewing disabled devices before removal:
    # 1. Run the script and authenticate.
    # 2. In the UI, set Device scope = Disabled devices.
    # 3. Click Query devices - returns all disabled devices regardless of age.
    # 4. Use Export CSV to save the list before taking any action.
    # 5. Select all, click Remove selected, confirm.

.NOTES
    Version : 4.1
    Author  : Kasper Johansen | KMJ-Consulting

    Requires PowerShell 5.1 or later.
    Requires the following Microsoft Graph PowerShell SDK modules:
      - Microsoft.Graph.Authentication
      - Microsoft.Graph.Identity.DirectoryManagement

    The Graph connection uses Device.ReadWrite.All. If an existing session already
    has this scope for the target tenant it is reused without prompting again.

    The HTTP listener uses BeginGetContext() polled at 500 ms intervals rather than
    the blocking GetContext(), so Ctrl+C in the PowerShell window stops the script
    cleanly within half a second.

    Date values (last sign-in, registered) are cast to ISO 8601 UTC strings before
    JSON serialisation to avoid the legacy /Date(...)/ format emitted by
    ConvertTo-Json in Windows PowerShell 5.1 when serialising [datetime] objects.

    The connected tenant banner resolves the primary domain via
    GET /v1.0/organization?$select=verifiedDomains and falls back to the tenant
    GUID if no default domain is found.

    All Unicode characters in the embedded HTML are expressed as HTML entities to
    ensure correct rendering regardless of HTTP response encoding.

.LINK
    https://kasperjohansen.net

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/device
#>

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Int32]$Port = 8734
)

# ── helpers ──────────────────────────────────────────────────────────────────

$JoinTypeMap = @{
    EntraJoined  = "AzureAD"
    HybridJoined = "ServerAD"
    Registered   = "Workplace"
}

function Get-GraphPagedResults {
    param([string]$Uri)
    $Results = [System.Collections.Generic.List[Object]]::new()
    do {
        $Response = Invoke-MgGraphRequest -Method Get -Uri $Uri -Headers @{ ConsistencyLevel = "eventual" }
        if ($Response.value) { $Results.AddRange([Object[]]$Response.value) }
        $Uri = $Response.'@odata.nextLink'
    } while ($Uri)
    return $Results
}

function Invoke-MgGraphRequestWithRetry {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Body,
        [int]$MaxRetries = 3
    )
    $Attempt = 0
    do {
        try {
            $Params = @{ Method = $Method; Uri = $Uri; ErrorAction = "Stop" }
            if ($Body) { $Params.Body = ($Body | ConvertTo-Json); $Params.ContentType = "application/json" }
            Invoke-MgGraphRequest @Params
            return
        }
        catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429 -and $Attempt -lt $MaxRetries) {
                $RetryAfter = $_.Exception.Response.Headers['Retry-After']
                $Wait = if ($RetryAfter) { [int]$RetryAfter } else { 10 }
                Start-Sleep -Seconds $Wait
            }
            else { throw }
        }
        $Attempt++
    } while ($Attempt -le $MaxRetries)
}

function Get-StaleDevices {
    param([Int32]$Age, [string]$JoinType, [string]$OS, [switch]$DisabledDevices)
    $Base   = "https://graph.microsoft.com/v1.0"
    $Select = "id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,registrationDateTime,accountEnabled"
    if ($DisabledDevices) {
        $Uri = "$Base/devices?`$filter=operatingSystem eq '$OS' AND trustType eq '$JoinType' AND accountEnabled eq false&`$count=true&`$select=$Select"
    }
    else {
        $DevAge = (Get-Date).AddDays(-$Age).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $Uri = "$Base/devices?`$filter=approximateLastSignInDateTime le $DevAge AND operatingSystem eq '$OS' AND trustType eq '$JoinType'&`$count=true&`$select=$Select"
    }
    $Raw = Get-GraphPagedResults -Uri $Uri
    return $Raw | ForEach-Object {
        [PSCustomObject]@{
            objectId               = $_.id
            deviceId               = $_.deviceId
            displayName            = $_.displayName
            operatingSystem        = $_.operatingSystem
            operatingSystemVersion = $_.operatingSystemVersion
            trustType              = $_.trustType
            lastSignIn             = if ($_.approximateLastSignInDateTime) { ([datetime]$_.approximateLastSignInDateTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            registered             = if ($_.registrationDateTime) { ([datetime]$_.registrationDateTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            accountEnabled         = $_.accountEnabled
        }
    } | Sort-Object lastSignIn
}

function Write-JsonResponse {
    param($Context, [int]$Status = 200, $Body)
    $Json  = $Body | ConvertTo-Json -Depth 5 -Compress
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
    $Context.Response.StatusCode        = $Status
    $Context.Response.ContentType       = "application/json"
    $Context.Response.ContentLength64   = $Bytes.Length
    $Context.Response.Headers.Add("Access-Control-Allow-Origin", "*")
    $Context.Response.OutputStream.Write($Bytes, 0, $Bytes.Length)
    $Context.Response.OutputStream.Close()
}

function Write-HtmlResponse {
    param($Context, [string]$Html)
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Html)
    $Context.Response.StatusCode        = 200
    $Context.Response.ContentType       = "text/html; charset=utf-8"
    $Context.Response.ContentLength64   = $Bytes.Length
    $Context.Response.OutputStream.Write($Bytes, 0, $Bytes.Length)
    $Context.Response.OutputStream.Close()
}

# ── embedded HTML ─────────────────────────────────────────────────────────────

$Html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Cleanup-StaleDevices</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#ffffff;--bg2:#f5f5f4;--bg3:#eeede9;
  --border:rgba(0,0,0,.10);--border2:rgba(0,0,0,.18);
  --text:#1a1a18;--text2:#5a5a56;--text3:#9a9a95;
  --radius:8px;--radius-lg:12px;
  --mono:'Consolas','Menlo',monospace;
  --accent:#185FA5;--accent-bg:#E6F1FB;
  --warn:#BA7517;--warn-bg:#FAEEDA;
  --danger:#A32D2D;--danger-bg:#FCEBEB;--danger-bd:#F09595;
  --success:#0F6E56;--success-bg:#E1F5EE;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#1c1c1a;--bg2:#252523;--bg3:#2e2e2b;
  --border:rgba(255,255,255,.10);--border2:rgba(255,255,255,.18);
  --text:#e8e8e4;--text2:#a0a09a;--text3:#6a6a65;
  --accent:#85B7EB;--accent-bg:#0C447C;
  --warn:#FAC775;--warn-bg:#633806;
  --danger:#F09595;--danger-bg:#501313;--danger-bd:#791F1F;
  --success:#5DCAA5;--success-bg:#04342C;
}}
body{font-family:-apple-system,'Segoe UI',sans-serif;background:var(--bg3);color:var(--text);font-size:14px;line-height:1.5;min-height:100vh;padding:2rem 1rem}
.shell{max-width:900px;margin:0 auto;display:flex;flex-direction:column;gap:12px}
.header{display:flex;align-items:baseline;gap:10px;padding-bottom:4px}
.header h1{font-size:17px;font-weight:600}
.header span{font-size:12px;color:var(--text3)}
.card{background:var(--bg);border:.5px solid var(--border);border-radius:var(--radius-lg);padding:1rem 1.25rem}
.section-label{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px}
.field{display:flex;flex-direction:column;gap:4px}
.field label{font-size:12px;color:var(--text2)}
input[type=text],input[type=number],select{font-family:inherit;font-size:13px;color:var(--text);background:var(--bg2);border:.5px solid var(--border2);border-radius:var(--radius);padding:7px 10px;width:100%;outline:none;transition:border-color .15s;appearance:none}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 18%,transparent)}
select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23888' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px;cursor:pointer}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.age-row{display:flex;align-items:center;gap:10px;margin-top:2px}
input[type=range]{flex:1;height:4px;cursor:pointer;accent-color:var(--accent)}
.age-num-wrap{display:flex;align-items:center;gap:5px}
.age-num-wrap input{width:64px;text-align:right}
.age-unit{font-size:12px;color:var(--text2);white-space:nowrap}
.run-btn{display:inline-flex;align-items:center;gap:7px;font-family:inherit;font-size:13px;font-weight:500;padding:8px 18px;border-radius:var(--radius);border:none;background:var(--accent);color:#fff;cursor:pointer;transition:opacity .15s}
.run-btn:hover{opacity:.88}
.run-btn:disabled{opacity:.45;cursor:not-allowed}
.status-bar{font-size:12px;color:var(--text3);display:flex;align-items:center;gap:7px}
.spinner{width:13px;height:13px;border:2px solid var(--border2);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0;display:none}
@keyframes spin{to{transform:rotate(360deg)}}
.connect-row{display:flex;align-items:flex-end;gap:10px}
.connect-row .field{flex:1}
.connect-pill{font-size:11px;padding:3px 9px;border-radius:20px;font-weight:500;white-space:nowrap}
.pill-ok{background:var(--success-bg);color:var(--success)}
.pill-no{background:var(--danger-bg);color:var(--danger)}
.pill-readonly{background:var(--warn-bg);color:var(--warn)}
.role-pill{font-size:11px;padding:2px 8px;border-radius:20px;background:var(--bg2);color:var(--text2);border:.5px solid var(--border);white-space:nowrap}
.role-pill.write{background:var(--accent-bg);color:var(--accent);border-color:var(--accent)}

/* results area */
.results-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap;gap:8px}
.results-title{font-size:13px;font-weight:500}
.count-badge{font-size:11px;padding:2px 8px;border-radius:20px;background:var(--bg2);color:var(--text2);border:.5px solid var(--border)}
.action-bar{display:flex;gap:6px;flex-wrap:wrap}
.action-btn{display:inline-flex;align-items:center;gap:5px;font-family:inherit;font-size:12px;padding:5px 11px;border-radius:var(--radius);border:.5px solid var(--border2);background:var(--bg);color:var(--text2);cursor:pointer;transition:background .1s}
.action-btn:hover{background:var(--bg2)}
.action-btn.danger{border-color:var(--danger-bd);color:var(--danger)}
.action-btn.danger:hover{background:var(--danger-bg)}
.action-btn.warn{border-color:var(--warn);color:var(--warn)}
.action-btn.warn:hover{background:var(--warn-bg)}
.action-btn:disabled{opacity:.4;cursor:not-allowed}

/* table */
.tbl-wrap{overflow-x:auto;border-radius:var(--radius);border:.5px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
thead th{background:var(--bg2);padding:7px 10px;text-align:left;font-weight:500;font-size:11.5px;color:var(--text2);white-space:nowrap;border-bottom:.5px solid var(--border);position:sticky;top:0}
tbody tr{border-bottom:.5px solid var(--border);transition:background .1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--bg2)}
tbody tr.selected{background:var(--accent-bg)}
tbody td{padding:7px 10px;color:var(--text);vertical-align:middle}
.td-check{width:32px;text-align:center}
input[type=checkbox]{accent-color:var(--accent);width:14px;height:14px;cursor:pointer}
.badge-enabled{font-size:11px;padding:2px 7px;border-radius:20px;background:var(--success-bg);color:var(--success)}
.badge-disabled{font-size:11px;padding:2px 7px;border-radius:20px;background:var(--danger-bg);color:var(--danger)}
.stale-age{color:var(--danger);font-weight:500}
.old-age{color:var(--warn)}
.empty-state{padding:2rem;text-align:center;color:var(--text3);font-size:13px}
.confirm-overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:100;display:none}
.confirm-card{background:var(--bg);border:.5px solid var(--border2);border-radius:var(--radius-lg);padding:1.5rem;width:380px;max-width:90vw}
.confirm-card h2{font-size:15px;font-weight:600;margin-bottom:6px}
.confirm-card p{font-size:13px;color:var(--text2);margin-bottom:1.25rem;line-height:1.6}
.confirm-btns{display:flex;gap:8px;justify-content:flex-end}
.btn-cancel{font-family:inherit;font-size:13px;padding:7px 14px;border-radius:var(--radius);border:.5px solid var(--border2);background:var(--bg);color:var(--text2);cursor:pointer}
.btn-cancel:hover{background:var(--bg2)}
.btn-confirm-danger{font-family:inherit;font-size:13px;font-weight:500;padding:7px 14px;border-radius:var(--radius);border:none;background:var(--danger);color:#fff;cursor:pointer}
.btn-confirm-warn{font-family:inherit;font-size:13px;font-weight:500;padding:7px 14px;border-radius:var(--radius);border:none;background:var(--warn);color:#fff;cursor:pointer}
.log-list{display:flex;flex-direction:column;gap:3px;max-height:180px;overflow-y:auto;margin-top:10px}
.log-item{font-size:12px;font-family:var(--mono);padding:4px 8px;border-radius:4px;background:var(--bg2)}
.log-ok{color:var(--success)}
.log-err{color:var(--danger)}
.log-info{color:var(--text2)}
</style>
</head>
<body>
<div class="shell">
  <div class="header">
    <h1>Cleanup-StaleDevices</h1>
    <span>v4</span>
  </div>

  <!-- Connection status -->
  <div class="card" id="statusCard">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <div class="spinner" id="statusSpinner" style="display:block"></div>
      <span id="statusMsg" style="font-size:13px;color:var(--text2)">Checking connection...</span>
      <span id="connectPill" class="connect-pill" style="display:none"></span>
      <span id="permPill" class="connect-pill" style="display:none"></span>
    </div>
    <div id="userRow" style="display:none;margin-top:8px">
      <div style="font-size:12px;color:var(--text2);margin-bottom:4px">
        <span id="userNameSpan" style="font-weight:500;color:var(--text)"></span>
        <span id="upnSpan" style="margin-left:5px;color:var(--text3)"></span>
      </div>
      <div id="rolesRow" style="display:flex;flex-wrap:wrap;gap:4px"></div>
    </div>
  </div>

  <!-- Filters -->
  <div class="card">
    <div class="section-label">Device filter</div>
    <div class="grid3" style="margin-bottom:12px">
      <div class="field">
        <label>Join type</label>
        <select id="joinType">
          <option value="EntraJoined">Entra joined</option>
          <option value="HybridJoined">Hybrid joined</option>
          <option value="Registered">Registered</option>
        </select>
      </div>
      <div class="field">
        <label>Operating system</label>
        <select id="os">
          <option value="Windows">Windows</option>
          <option value="iOS">iOS</option>
          <option value="Android">Android</option>
          <option value="MacMDM">macOS MDM</option>
          <option value="Ipad">iPad</option>
          <option value="Iphone">iPhone</option>
          <option value="Unknown">Unknown</option>
        </select>
      </div>
      <div class="field">
        <label>Device scope</label>
        <select id="scope" onchange="toggleAgeRow()">
          <option value="stale">Stale devices</option>
          <option value="disabled">Disabled devices</option>
        </select>
      </div>
    </div>
    <div id="ageRow" class="field">
      <label>Inactivity threshold</label>
      <div class="age-row">
        <input type="range" id="ageSlider" min="1" max="365" value="90" step="1" oninput="syncAge(this.value,false)" />
        <div class="age-num-wrap">
          <input type="number" id="ageNum" min="1" max="5475" value="90" oninput="syncAge(this.value,true)" />
          <span class="age-unit">days</span>
        </div>
      </div>
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-top:14px">
      <div class="status-bar">
        <div class="spinner" id="querySpinner"></div>
        <span id="queryStatusMsg"></span>
      </div>
      <button class="run-btn" id="queryBtn" onclick="runQuery()" disabled>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        Query devices
      </button>
    </div>
  </div>

  <!-- Results -->
  <div class="card" id="resultsCard" style="display:none">
    <div class="results-header">
      <div style="display:flex;align-items:center;gap:8px">
        <span class="results-title">Results</span>
        <span class="count-badge" id="countBadge">0 devices</span>
        <span class="count-badge" id="selBadge" style="display:none">0 selected</span>
      </div>
      <div class="action-bar">
        <button class="action-btn" onclick="selectAll()">Select all</button>
        <button class="action-btn" onclick="clearSel()">Clear</button>
        <button class="action-btn warn" id="disableBtn" onclick="confirmAction('disable')" disabled>Disable selected</button>
        <button class="action-btn danger" id="removeBtn" onclick="confirmAction('remove')" disabled>Remove selected</button>
        <button class="action-btn" onclick="exportCSV()">Export CSV</button>
      </div>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th class="td-check"><input type="checkbox" id="checkAll" onchange="toggleAll(this.checked)" /></th>
            <th>Device name</th>
            <th>OS</th>
            <th>Version</th>
            <th>Join type</th>
            <th>Last sign-in</th>
            <th>Last check-in date</th>
            <th>Registered</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody id="tblBody"></tbody>
      </table>
    </div>
    <div class="log-list" id="logList" style="display:none"></div>
  </div>
</div>

<!-- Confirm overlay -->
<div class="confirm-overlay" id="confirmOverlay">
  <div class="confirm-card">
    <h2 id="confirmTitle"></h2>
    <p id="confirmMsg"></p>
    <div class="confirm-btns">
      <button class="btn-cancel" onclick="closeConfirm()">Cancel</button>
      <button id="confirmOkBtn" onclick="executeAction()">Confirm</button>
    </div>
  </div>
</div>

<script>
let devices = [];
let pendingAction = null;

function syncAge(val, fromNum) {
  const n = Math.max(1, Math.min(5475, parseInt(val) || 1));
  document.getElementById('ageSlider').value = Math.min(n, 365);
  document.getElementById('ageNum').value = n;
}

function toggleAgeRow() {
  document.getElementById('ageRow').style.display =
    document.getElementById('scope').value === 'disabled' ? 'none' : '';
}

function setQueryStatus(msg, spinning) {
  document.getElementById('queryStatusMsg').textContent = msg;
  document.getElementById('querySpinner').style.display = spinning ? 'block' : 'none';
}

let isReadOnly = true;

async function checkStatus() {
  try {
    const r = await fetch('/status');
    const d = await r.json();
    if (d.ok) {
      // Store read-only flag globally so updateSelectionUI can gate the action buttons
      isReadOnly = d.readOnly;
      document.getElementById('statusSpinner').style.display = 'none';
      document.getElementById('statusMsg').textContent = 'Connected to tenant ' + d.tenant;
      document.getElementById('statusMsg').style.color = 'var(--success)';
      const pill = document.getElementById('connectPill');
      pill.textContent = 'Connected';
      pill.className = 'connect-pill pill-ok';
      pill.style.display = '';
      // Permission indicator - warns the user if write operations are unavailable
      const perm = document.getElementById('permPill');
      perm.textContent = isReadOnly ? 'Read-only' : 'Read/Write';
      perm.className   = 'connect-pill ' + (isReadOnly ? 'pill-readonly' : 'pill-ok');
      perm.title       = isReadOnly
        ? 'Your Entra directory role does not include device write permissions. Disable and Remove actions are unavailable.'
        : 'Your Entra directory role includes device write permissions. All actions available.';
      perm.style.display = '';
      // Render signed-in user name, UPN and assigned directory roles
      document.getElementById('userNameSpan').textContent = d.userName || '';
      document.getElementById('upnSpan').textContent = d.upn ? '(' + d.upn + ')' : '';
      const rolesRow = document.getElementById('rolesRow');
      rolesRow.innerHTML = '';
      (d.roles || []).forEach(role => {
        const span = document.createElement('span');
        span.className = 'role-pill' + (!isReadOnly ? ' write' : '');
        span.textContent = role;
        rolesRow.appendChild(span);
      });
      if (!d.roles || d.roles.length === 0) {
        const span = document.createElement('span');
        span.className = 'role-pill';
        span.textContent = 'No directory roles assigned';
        rolesRow.appendChild(span);
      }
      document.getElementById('userRow').style.display = '';
      document.getElementById('queryBtn').disabled = false;
      // Disable action buttons immediately if read-only; re-evaluated on each selection change
      if (isReadOnly) {
        const disableBtn = document.getElementById('disableBtn');
        const removeBtn  = document.getElementById('removeBtn');
        disableBtn.disabled = true;
        disableBtn.title    = 'Unavailable: your Entra directory role does not include device write permissions.';
        removeBtn.disabled  = true;
        removeBtn.title     = 'Unavailable: your Entra directory role does not include device write permissions.';
      }
    }
  } catch (e) {
    document.getElementById('statusSpinner').style.display = 'none';
    document.getElementById('statusMsg').innerHTML = 'Not connected &mdash; restart the script.';
    document.getElementById('statusMsg').style.color = 'var(--danger)';
  }
}

window.addEventListener('load', checkStatus);

async function runQuery() {
  document.getElementById('queryBtn').disabled = true;
  document.getElementById('resultsCard').style.display = 'none';
  setQueryStatus('Querying Graph...', true);
  const body = {
    joinType:  document.getElementById('joinType').value,
    os:        document.getElementById('os').value,
    scope:     document.getElementById('scope').value,
    age:       parseInt(document.getElementById('ageNum').value) || 90
  };
  try {
    const r = await fetch('/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const d = await r.json();
    if (d.ok) {
      devices = d.devices;
      renderTable(devices);
      setQueryStatus(`Found ${devices.length} device${devices.length !== 1 ? 's' : ''}.`, false);
    } else {
      setQueryStatus('Query failed: ' + d.error, false);
    }
  } catch (e) {
    setQueryStatus('Query failed: ' + e.message, false);
  }
  document.getElementById('queryBtn').disabled = false;
}

function renderTable(devs) {
  const tbody = document.getElementById('tblBody');
  if (!devs.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No devices found.</td></tr>';
    document.getElementById('countBadge').textContent = '0 devices';
    document.getElementById('resultsCard').style.display = '';
    document.getElementById('logList').style.display = 'none';
    return;
  }
  tbody.innerHTML = devs.map((d, i) => {
    const parseDate = v => { if (!v) return null; const d = new Date(v); return isNaN(d.getTime()) ? null : d; };
    const lastSignIn = parseDate(d.lastSignIn);
    const registered = parseDate(d.registered);
    const daysSince  = lastSignIn ? Math.floor((Date.now() - lastSignIn.getTime()) / 86400000) : null;
    const ageClass   = daysSince === null ? '' : daysSince > 180 ? 'stale-age' : daysSince > 90 ? 'old-age' : '';
    // ageStr  = relative age e.g. "92d ago", colour-coded by threshold
    // lastSignInDate = absolute locale date shown in the adjacent "Last check-in date" column
    const ageStr          = daysSince === null ? '&mdash;' : `<span class="${ageClass}">${daysSince}d ago</span>`;
    const lastSignInDate  = lastSignIn ? lastSignIn.toLocaleDateString() : '&mdash;';
    const regStr          = registered ? registered.toLocaleDateString() : '&mdash;';
    const statusBadge = d.accountEnabled
      ? '<span class="badge-enabled">Enabled</span>'
      : '<span class="badge-disabled">Disabled</span>';
    const jt = { AzureAD: 'Entra joined', ServerAD: 'Hybrid joined', Workplace: 'Registered' };
    return `<tr id="row-${i}">
      <td class="td-check"><input type="checkbox" data-idx="${i}" onchange="onRowCheck(${i},this.checked)" /></td>
      <td style="font-weight:500">${esc(d.displayName)}</td>
      <td>${esc(d.operatingSystem||'&mdash;')}</td>
      <td style="color:var(--text2)">${esc(d.operatingSystemVersion||'&mdash;')}</td>
      <td>${jt[d.trustType]||esc(d.trustType)||'&mdash;'}</td>
      <td>${ageStr}</td>
      <td style="color:var(--text2)">${lastSignInDate}</td>
      <td style="color:var(--text2)">${regStr}</td>
      <td>${statusBadge}</td>
    </tr>`;
  }).join('');
  document.getElementById('countBadge').textContent = `${devs.length} device${devs.length !== 1 ? 's' : ''}`;
  document.getElementById('resultsCard').style.display = '';
  document.getElementById('logList').style.display = 'none';
  document.getElementById('logList').innerHTML = '';
  updateSelectionUI();
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function getSelected() {
  return [...document.querySelectorAll('#tblBody input[type=checkbox]:checked')]
    .map(cb => parseInt(cb.dataset.idx));
}

function onRowCheck(i, checked) {
  document.getElementById('row-' + i).classList.toggle('selected', checked);
  updateSelectionUI();
}

function toggleAll(checked) {
  document.querySelectorAll('#tblBody input[type=checkbox]').forEach(cb => {
    cb.checked = checked;
    const i = parseInt(cb.dataset.idx);
    document.getElementById('row-' + i).classList.toggle('selected', checked);
  });
  updateSelectionUI();
}

function selectAll() { document.getElementById('checkAll').checked = true; toggleAll(true); }
function clearSel()  { document.getElementById('checkAll').checked = false; toggleAll(false); }

function updateSelectionUI() {
  const sel = getSelected();
  const n   = sel.length;
  const sb  = document.getElementById('selBadge');
  sb.textContent = `${n} selected`;
  sb.style.display = n ? '' : 'none';
  // Only enable action buttons when there is a selection AND the session has write permissions
  document.getElementById('disableBtn').disabled = n === 0 || isReadOnly;
  document.getElementById('removeBtn').disabled  = n === 0 || isReadOnly;
}

function confirmAction(action) {
  const sel  = getSelected();
  const n    = sel.length;
  pendingAction = action;
  document.getElementById('confirmTitle').textContent =
    action === 'disable' ? `Disable ${n} device${n !== 1 ? 's' : ''}?` : `Remove ${n} device${n !== 1 ? 's' : ''}?`;
  document.getElementById('confirmMsg').textContent =
    action === 'disable'
      ? `This will set accountEnabled = false on ${n} device${n !== 1 ? 's' : ''} in Entra ID. This can be undone.`
      : `This will permanently delete ${n} device${n !== 1 ? 's' : ''} from Entra ID. This cannot be undone.`;
  const okBtn = document.getElementById('confirmOkBtn');
  okBtn.className = action === 'disable' ? 'btn-confirm-warn' : 'btn-confirm-danger';
  okBtn.textContent = action === 'disable' ? 'Disable' : 'Remove';
  document.getElementById('confirmOverlay').style.display = 'flex';
}

function closeConfirm() {
  document.getElementById('confirmOverlay').style.display = 'none';
  pendingAction = null;
}

async function executeAction() {
  const action = pendingAction;
  closeConfirm();
  const sel     = getSelected();
  const targets = sel.map(i => devices[i]);
  const logList = document.getElementById('logList');
  logList.style.display = 'flex';
  logList.innerHTML = `<div class="log-item log-info">Starting ${action} on ${targets.length} device(s)...</div>`;

  document.getElementById('disableBtn').disabled = true;
  document.getElementById('removeBtn').disabled  = true;

  for (const dev of targets) {
    try {
      const r = await fetch('/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: action, objectId: dev.objectId, displayName: dev.displayName })
      });
      const d = await r.json();
      const item = document.createElement('div');
      item.className = 'log-item ' + (d.ok ? 'log-ok' : 'log-err');
      item.textContent = d.ok
        ? '&#10003; ' + dev.displayName
        : '&#10007; ' + dev.displayName + ' &mdash; ' + d.error;
      item.innerHTML = item.textContent;
      logList.appendChild(item);
      logList.scrollTop = logList.scrollHeight;
      if (d.ok) {
        const idx = devices.indexOf(dev);
        const row = document.getElementById('row-' + idx);
        if (row) row.style.opacity = '0.4';
      }
    } catch (e) {
      const item = document.createElement('div');
      item.className = 'log-item log-err';
      item.innerHTML = '&#10007; ' + dev.displayName + ' &mdash; ' + e.message;
      logList.appendChild(item);
    }
  }

  const done = document.createElement('div');
  done.className = 'log-item log-info';
  done.textContent = 'Done.';
  logList.appendChild(done);
  updateSelectionUI();
}

function exportCSV() {
  if (!devices.length) return;
  const headers = ['DisplayName','DeviceId','OS','Version','JoinType','LastSignIn','LastSignInDate','Registered','AccountEnabled'];
  const rows = devices.map(d => [
    d.displayName, d.deviceId, d.operatingSystem, d.operatingSystemVersion,
    d.trustType, d.lastSignIn||'', (parseDate(d.lastSignIn) ? parseDate(d.lastSignIn).toLocaleDateString() : ''), d.registered||'', d.accountEnabled
  ].map(v => `"${String(v||'').replace(/"/g,'""')}"`).join(','));
  const csv  = [headers.join(','), ...rows].join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `StaleDevices_${new Date().toISOString().slice(0,10)}.csv`;
  a.click(); URL.revokeObjectURL(url);
}
</script>
</body>
</html>
'@

# ── Connect to Graph before starting the listener ─────────────────────────────
# Connect-MgGraph opens an interactive browser auth flow which blocks the thread.
# It must complete before the HttpListener loop starts, otherwise the listener
# cannot accept requests while waiting for the auth to finish.

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "A browser window will open for authentication." -ForegroundColor Gray

$ConnectedTenantId = $null
$ConnectedDomain   = $null
$ReadOnly          = $true
try {
    $ExistingCtx = Get-MgContext
    if ($ExistingCtx -and ($ExistingCtx.Scopes -contains "Device.ReadWrite.All")) {
        Write-Host "Reusing existing Graph session for tenant $($ExistingCtx.TenantId)." -ForegroundColor Green
        $ConnectedTenantId = $ExistingCtx.TenantId
    }
    else {
        Connect-MgGraph -Scopes "Device.ReadWrite.All" -NoWelcome -ErrorAction Stop
        $ConnectedTenantId = (Get-MgContext).TenantId
        Write-Host "Connected to tenant $ConnectedTenantId." -ForegroundColor Green
    }
    # Determine write permission by checking the signed-in user's transitive directory
    # role assignments rather than the OAuth scope. Device.ReadWrite.All is a delegated
    # scope granted to the app - it does not reflect the user's Entra role. A Global
    # Reader will be granted the scope but cannot write; the role check is authoritative.
    #
    # Roles that include device write permissions (displayName -> roleDefinitionId):
    #   Cloud Device Administrator  : 7698a772-787b-4ac8-901f-60d6b08affd2
    #   Intune Administrator        : 3a2c62db-5318-420d-8d74-23affee5d9d5
    #   Windows 365 Administrator   : 11451d60-acb2-45eb-a7d6-43d0f0125c13
    #   Global Administrator        : 62e90394-69f5-4237-9190-012177145e10
    #   Privileged Role Administrator: e8611ab8-c189-46e8-94e1-60213ab1f814
    $DeviceWriteRoleIds = @(
        "7698a772-787b-4ac8-901f-60d6b08affd2",  # Cloud Device Administrator
        "3a2c62db-5318-420d-8d74-23affee5d9d5",  # Intune Administrator
        "11451d60-acb2-45eb-a7d6-43d0f0125c13",  # Windows 365 Administrator
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814"   # Privileged Role Administrator
    )
    $Me = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/me?`$select=id,displayName,userPrincipalName" -ErrorAction Stop
    $ConnectedUserName = $Me.displayName
    $ConnectedUPN      = $Me.userPrincipalName
    $RoleResponse = Invoke-MgGraphRequest -Method Get `
        -Uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?`$select=displayName,roleTemplateId" `
        -ErrorAction Stop
    $AssignedRoles           = $RoleResponse.value
    $AssignedRoleTemplateIds = $AssignedRoles | ForEach-Object { $_.roleTemplateId }
    $AssignedRoleNames       = $AssignedRoles | ForEach-Object { $_.displayName } | Sort-Object
    $ReadOnly = -not ($AssignedRoleTemplateIds | Where-Object { $DeviceWriteRoleIds -contains $_ })
    $PermissionLabel = if ($ReadOnly) { "Read-only" } else { "Read/Write" }
    Write-Host "Signed in as: $ConnectedUserName ($ConnectedUPN)" -ForegroundColor Green
    Write-Host "Roles: $($AssignedRoleNames -join ', ')" -ForegroundColor Green
    Write-Host "Permission level: $PermissionLabel" -ForegroundColor $(if ($ReadOnly) { "Yellow" } else { "Green" })
    # Resolve primary domain from the organization object
    $OrgResponse = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/organization?`$select=verifiedDomains" -ErrorAction Stop
    $ConnectedDomain = ($OrgResponse.value[0].verifiedDomains | Where-Object { $_.isDefault -eq $true }).name
    if (-not $ConnectedDomain) { $ConnectedDomain = $ConnectedTenantId }
    Write-Host "Primary domain: $ConnectedDomain" -ForegroundColor Green
}
catch {
    Write-Error "Graph connection failed: $($_.Exception.Message)"
    exit 1
}

# ── HTTP listener ─────────────────────────────────────────────────────────────
# GetContext() blocks the thread permanently, so Ctrl+C can never land.
# BeginGetContext() + WaitOne(500) polls every 500 ms, keeping the thread
# responsive to interrupts while still processing every incoming request.

function Invoke-RequestHandler {
    param($ctx)
    $req  = $ctx.Request
    $path = $req.Url.AbsolutePath

    if ($path -eq "/" -or $path -eq "/index.html") {
        Write-HtmlResponse -Context $ctx -Html $Html
        return
    }

    $Body = $null
    if ($req.HasEntityBody) {
        $Reader = [System.IO.StreamReader]::new($req.InputStream, $req.ContentEncoding)
        $Body   = $Reader.ReadToEnd() | ConvertFrom-Json
        $Reader.Close()
    }

    switch ($path) {

        "/status" {
            Write-JsonResponse -Context $ctx -Body @{ ok = $true; tenant = $ConnectedDomain; readOnly = $ReadOnly; userName = $ConnectedUserName; upn = $ConnectedUPN; roles = $AssignedRoleNames }
        }

        "/query" {
            try {
                $JoinType = $JoinTypeMap[$Body.joinType]
                if (-not $JoinType) { throw "Unknown join type: $($Body.joinType)" }
                $Params = @{ JoinType = $JoinType; OS = $Body.os }
                if ($Body.scope -eq "disabled") { $Params.DisabledDevices = $true }
                else { $Params.Age = [int]$Body.age }
                $Result = Get-StaleDevices @Params
                Write-JsonResponse -Context $ctx -Body @{ ok = $true; devices = @($Result) }
            }
            catch {
                Write-JsonResponse -Context $ctx -Body @{ ok = $false; error = $_.Exception.Message }
            }
        }

        "/action" {
            try {
                $ObjectId = $Body.objectId
                $Action   = $Body.action
                if ($Action -eq "disable") {
                    Invoke-MgGraphRequestWithRetry -Method Patch `
                        -Uri "https://graph.microsoft.com/v1.0/devices/$ObjectId" `
                        -Body @{ accountEnabled = $false }
                }
                elseif ($Action -eq "remove") {
                    Invoke-MgGraphRequestWithRetry -Method Delete `
                        -Uri "https://graph.microsoft.com/v1.0/devices/$ObjectId"
                }
                else { throw "Unknown action: $Action" }
                Write-JsonResponse -Context $ctx -Body @{ ok = $true }
            }
            catch {
                Write-JsonResponse -Context $ctx -Body @{ ok = $false; error = $_.Exception.Message }
            }
        }

        default {
            $ctx.Response.StatusCode = 404
            $ctx.Response.Close()
        }
    }
}

$BaseUrl = "http://localhost:$Port/"
$Listener = [System.Net.HttpListener]::new()
$Listener.Prefixes.Add($BaseUrl)
$Listener.Start()

Write-Host "UI running at $BaseUrl" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop." -ForegroundColor Gray
Start-Process $BaseUrl

try {
    while ($Listener.IsListening) {
        $Async = $Listener.BeginGetContext($null, $null)
        # Poll every 500 ms so Ctrl+C is never blocked longer than half a second
        while (-not $Async.AsyncWaitHandle.WaitOne(500)) {
            if (-not $Listener.IsListening) { break }
        }
        if (-not $Listener.IsListening) { break }
        $ctx = $Listener.EndGetContext($Async)
        Invoke-RequestHandler -ctx $ctx
    }
}
finally {
    $Listener.Stop()
    Write-Host "Listener stopped." -ForegroundColor Gray
}
# Entra group
$clientID = "0f6b3cb3-7281-4cc2-ac59-34ce8d201402"
$clientsecret = "Oai8Q~T3IBzYI5a~BlZvKqnpuehTraQcqBD1Mbq1"
$tenantID = "046a9d17-ff40-425e-8f79-e4c6cd689c83"
$resource = "https://graph.microsoft.com/"

$TokenEndpoint = "https://login.microsoft.com/$tenantId/oauth2/v2.0/token"

$body = @{
    client_id = $clientID
    client_secret = $clientsecret
    scope = "$resource/.default"
    grant_type = "client_credentials"
}

$tokenResponse = Invoke-RestMethod -Uri $TokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"

$AccessToken = $tokenResponse.access_token

$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json" 
}

$Body = @{
    description = "Test Group"
    displayName = "Test Group"
    groupTypes = @("Unified")
    mailEnabled = "false"
    mailNickname = "nickName"
    securityEnabled = "true"
} | ConvertTo-Json -Depth 99 -Compress

Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/groups" -Headers $Headers -Body $Body
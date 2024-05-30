# Populate with the App Registration details and Tenant ID
$appid = '58d9e836-34b7-4537-bd98-5ccd930dde2a'
$tenantid = 'virtualwarlock.net'
$secret = 'KVB8Q~ftIBu2t.hxybTfZ0YZpXwke3gmQp3HVcrQ'
 
$body =  @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $appid
    Client_Secret = $secret
}
 
$connection = Invoke-RestMethod `
    -Uri https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token `
    -Method POST `
    -Body $body
 
$token = $connection.access_token
$secureToken = ConvertTo-SecureString -String $token -AsPlainText -Force
 
Connect-MgGraph -AccessToken $secureToken -NoWelcome

$Group = "App-Install-Google-Chrome"
Get-MgGroup -Filter "DisplayName eq $Group"
$staledevices = gc C:\temp\Staledevices.txt
 
ForEach ($deviceid in $staledevices) {
$azureaddevice = Get-AzureAdDevice -All:$true | where {$_.DeviceID -eq "$deviceid"}
$displayname = $azureaddevice.displayname
#$azureaddevice = Get-AzureAdDevice -All:$true | where {$_.DeviceID -eq "$device"}
Write-host "Working on $deviceid...."
 
    If ($azureaddevice -ne $null)  {Write-host "Found AzureAdevice with displayname $displayname to be deleted :)"
    Remove-AzureADDevice -ObjectId $AzureADDevice.ObjectId -ErrorAction Stop -Verbose}
        else {Write-Host "No AzureAD Device found"}
}
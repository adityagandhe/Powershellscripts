Connect-SPOService -Url https://yavatmal3-admin.sharepoint.com/ -Credential(Get-Credential)

$Sites= Get-Content -Path "Z:\pnppowershell\Sites.txt"

foreach($site in $Sites)
{
if($site -ne $null)
{
Write-Host -ForegroundColor Yellow  "Adding SCA to the site"+$site
Set-SPOUser -Site $site -LoginName Aditya@yavatmal3.onmicrosoft.com  -IsSiteCollectionAdmin $true
}
}
Disconnect-SPOService
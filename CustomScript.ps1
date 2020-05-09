#Connect-SPOService  -Url https://yavatmal3-admin.sharepoint.com 
#Add-SPOSiteCollectionAppCatalog -Site https://yavatmal3.sharepoint.com/sites/ravitest

Connect-PnPOnline -Url https://yavatmal3.sharepoint.com/sites/ravitest
#Get-PnPApp -Identity d486bfae-1a3b-4e3a-8ee3-fdf26196771d -Scope Site | Install-PnPApp
Get-PnPApp
#Get-PnPCustomAction -Scope Site | Where-Object { $_.ClientSideComponentId -eq "004B6D5E-AEE8-499B-9FE8-06757CFD043B" } | Remove-PnPCustomAction

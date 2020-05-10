Connect-SPOService -Url https://yavatmal3-admin.sharepoint.com

Get-SPOSite | Export-csv -Path "Z:\pnppowershell\AllSites.csv" -NoTypeInformation -Append
Connect-SPOService -Url https://yavatmal3-admin.sharepoint.com

Get-SPOSite | Export-csv -Path "Z:\pnppowershell\AllSites1.csv" -NoTypeInformation -Append
Connect-SPOService -Url https://Yavatmal3-admin.sharepoint.com -Credential (Get-Credential)
Set-SPOSite https://yavatmal3.sharepoint.com/sites/RaviTest -LockState NoAccess
#Set-SPOTenant -NoAccessRedirectUrl 'https://yavatmal3.sharepoint.com/sites/modernteam'

Connect-SPOService -Url "https://yavatmal3-admin.sharepoint.com"
Get-SPOTenantCdnEnabled -CdnType Public
Get-SPOTenantCdnOrigins -CdnType Public
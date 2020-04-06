Connect-SPOService -Url "https://yavatmal3-admin.sharepoint.com"
Get-SPOTenant | Select PublicCdnEnabled
Set-SPOTenantCdnEnabled -CdnType Public -NoDefaultOrigins




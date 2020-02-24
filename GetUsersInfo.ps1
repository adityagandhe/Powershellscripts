<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    General notes
#>
$SourceConnection =Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/modernTeam"  -ReturnConnection
$TargetConnection =Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/ModernTeam/SubTeam" -ReturnConnection


#Site Collection
$collection = Get-PnPSite  -Connection $SourceConnection
Get-PnPProperty $collection -Property Id,Usage,Owner
$subwebs =Get-PnPSubWebs -Recurse -Includes SiteUsers -Connection $SourceConnection
$SourceSite = Get-PnPWeb -Connection $SourceConnection 
$TargetSite = Get-PnPWeb -Connection $TargetConnection
$SiteCollectionAdmins = Get-PnPSiteCollectionAdmin -Connection $SourceConnection
$SiteCollectionAdminsTarget = Get-PnPSiteCollectionAdmin -Connection $TargetConnection

$sourceweb =Get-PnPWeb -Connection $SourceConnection

$SiteCollectionUsers = Get-PnPUser -WithRightsAssigned
Write-Host -ForegroundColor Yellow  $SiteCollectionUsers.Count
foreach ($site in  $subwebs)
{

$SubsiteUsers = Get-PnPUser -WithRightsAssigned -Web $site
Write-Host $SubsiteUsers.Count "for" $site.Url 
}
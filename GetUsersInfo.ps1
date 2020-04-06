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
$SourceConnection =Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/ModernTeam"  -ReturnConnection
#$TargetConnection =Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/ModernTeam/SubTeam" -ReturnConnection


#Site Collection
#$collection = Get-PnPSite  -Connection $SourceConnection
#Get-PnPProperty $collection -Property Id,Usage,Owner
#$subwebs =Get-PnPSubWebs -Recurse -Includes SiteUsers 
#$SourceSite = Get-PnPWeb 
#$TargetSite = Get-PnPWeb -Connection $TargetConnection
#$SiteCollectionAdmins = Get-PnPSiteCollectionAdmin -Connection $SourceConnection
#$SiteCollectionAdminsTarget = Get-PnPSiteCollectionAdmin -Connection $TargetConnection

$sourceweb =Get-PnPWeb 

$SiteCollectionUsers = Get-PnPUser -WithRightsAssigned -web $sourceweb
Get-PnPUser |Where {$_.Email -ne ""} |Where {$_.PrincipalType -eq "User"}
foreach ($site in  $subwebs)
{
$site =Get-PnPWeb -Identity $site
$SubsiteUsers = Get-PnPUser -WithRightsAssigned -Web $site
$SubsiteUsers = Get-PnPUser  -Web $site
foreach ($SubsiteUser in  $SubsiteUsers)
{

Write-host $SubsiteUser.Email  in $site.Url

}
}
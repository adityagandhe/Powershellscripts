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
 Function ProcessAlerts($site)
 {
 
 #Write-Host -ForegroundColor Yellow "Site URL:"$site.Url
 $Alerts= Get-PnPAlert -Web $site
 if($Alerts.Count -gt 0)
 {
 
 foreach ($alert in $Alerts)
 {
 Get-PnPProperty -ClientObject $alert -Property List ,User
  Write-Host -ForegroundColor DarkMagenta $alert.Title
 Write-Host -ForegroundColor DarkMagenta $alert.List.Title
  Write-Host -ForegroundColor DarkMagenta $alert.User.LoginName
}
}
}
 Function ProcessLists($site)
 {
 
 Write-Host -ForegroundColor Yellow "Site URL:"$site.Url
 $lists= Get-PnPList -Web $site
 foreach ($list in $lists)
 {
 Write-Host $list.Title

}
}

#Site Collection
$collection = Get-PnPSite  -Connection $SourceConnection
$subsites= Get-PnPSubWebs -Recurse
#$sitecollectionusers=Get-PnPSiteCollectionAdmin
#$users =Get-PnPUser -WithRightsAssigned
Get-PnPProperty $collection -Property Id,Usage,Owner
$web = Get-PnPWeb 

  ProcessAlerts $web



Write-Host "Site level collection"
# ProcessLists -site $web


 foreach($site in $subsites)
 {



 #ProcessLists $site
 ProcessAlerts $site


 <#
 Write-Host "`n"
 Write-Host "verification"
 $lists= Get-PnPList -Web $site
 foreach ($list in $lists)
 {
 Write-Host -ForegroundColor Cyan $list.Title

 }
 
 #>
 }


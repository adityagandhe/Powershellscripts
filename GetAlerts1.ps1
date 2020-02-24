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
#$users =Get-PnPUser -Connection $SourceConnection
 Function ProcessAlerts($site)
 {

 function GetAlertForUser ($users)
 {
  foreach($user in $users)
 {
 #Write-Host "fetching for user"$user $site.url
 $Alerts= Get-PnPAlert -Web $site -User $user
 if($Alerts.Count -gt 0)
 {
 
 foreach ($alert in $Alerts)
 {
 Get-PnPProperty -ClientObject $alert -Property List ,User
 Write-Host -ForegroundColor Yellow $alert.Title $alert.List.Title $alert.User.LoginName $site.Url
}
 
}
}
}
 $users =Get-PnPUser -Web $site 
# $SiteCollectionUsers = Get-PnPSiteCollectionAdmin
GetAlertForUser $users
#GetAlertForUser $SiteCollectionUsers

}

#Site Collection

$subsites= Get-PnPSubWebs -Recurse
$web = Get-PnPWeb 

ProcessAlerts $web


 foreach($site in $subsites)
 {
 ProcessAlerts $site


 }


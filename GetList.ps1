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
 $users =Get-PnPUser -Web $site

  foreach($user in $users)
 {
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

$subsites= Get-PnPSubWebs -Recurse
$web = Get-PnPWeb 
#$users =Get-PnPUser -Web $web
$lists =Get-PnPList -Includes LastItemModifiedDate,LastItemUserModifiedDate | Where {$_.LastItemModifiedDate -gt '2020-03-01T18:05:32Z' }| Select Title,LastItemUserModifiedDate,LastItemModifiedDate
$iTEMS = Get-PnPListItem  | Where {$_.LastItemModifiedDate -gt '2020-03-01T18:05:32Z' }
ProcessAlerts $web


 foreach($site in $subsites)
 {
 ProcessAlerts $site


 }


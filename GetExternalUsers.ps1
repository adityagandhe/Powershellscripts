


#If the external users are add directly in the SP group then they would appear in output of the script even if they have not accessed thethe site yet
#if the external user is added in one of the  tenant level group like DL,Security group or O365 group then the user would be fetched only if he has ever accessed the site
#Script would give list of all the users who may have previously accesed the site but may not currently have the access

Function getUsers($site)
{
$sourceweb =Get-PnPWeb -Identity $site 
# Get-PnPProperty -ClientObject $sourceweb -Property SiteGroups
# $SubsiteUsers = Get-PnPUser  |Where {$_.Email -ne ""} |Where {$_.PrincipalType -eq "User"} |Where {$_.Email -notlike "*@yavatmal3.onmicrosoft.com"}
$SubsiteUsers = Get-PnPUser -WithRightsAssigned |Where {$_.Email -ne ""} |Where {$_.PrincipalType -eq "User"} |Where {$_.Email -notlike "*@yavatmal3.onmicrosoft.com"}


foreach ($SubsiteUser in  $SubsiteUsers)
{

Write-host $SubsiteUser.Title, $SubsiteUser.Email , $sourceweb.Url

}
}

$SourceConnection =Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/ModernTeam"  -ReturnConnection
$sourceweb =Get-PnPWeb 
getUsers $sourceweb


$SourceConnection =Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/ModernTeam"  -ReturnConnection
$sourceweb =Get-PnPWeb 
$SubsiteUsers = Get-PnPUser |Where {$_.Email -ne ""} |Where {$_.PrincipalType -eq "User"} |Where {$_.Email -notlike "*@yavatmal3.onmicrosoft.com"}
foreach ($SubsiteUser in  $SubsiteUsers)
{

Write-host $SubsiteUser.Title, $SubsiteUser.Email , $sourceweb.Url

}
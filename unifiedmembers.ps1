$SourceConnection =Connect-PnPOnline -url "https://yavatmal3-admin.sharepoint.com/" -Scope "Group.Read.All" -ReturnConnection
$groups =Get-PnPGroup -Connection $SourceConnection
$securityGroups =Get-pnpuser -WithRightsAssigned |Where{$_.PrincipalType -ne "User"}|Select *
foreach($group in $groups)
{
$members =Get-PnPGroupMembers -Identity $group.Title
Foreach($member in $members)
{
Write-host $member.Email

}

}
Write-host "Working"
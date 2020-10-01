Connect-PnPOnline -Url https://yavatmal3.sharepoint.com/sites/modernteam -Scopes "Group.Read.All","User.Read.All"

$O365Group = Get-PnPUnifiedGroup 

foreach($group in $O365Group)
{
$Owners =Get-PnPUnifiedGroupOwners -Identity $group.DisplayName

foreach($Owner in $Owners)
{
Write-host $Owner.DisplayName  $Owner.UserPrincipalName $group.DisplayName $group.SiteUrl "Owner"

}

$members =Get-PnPUnifiedGroupMembers -Identity $group.DisplayName

foreach($member in $members)
{
Write-host $member.DisplayName $member.UserPrincipalName  $group.DisplayName $group.SiteUrl "member"

}

}
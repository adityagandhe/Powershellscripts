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
$TargetConnection =Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/ModernTeam/testClassic" -ReturnConnection


#Site Collection
$collection = Get-PnPSite -Connection $SourceConnection
Get-PnPProperty $collection -Property Id,Usage,Owner
$SourceSite = Get-PnPWeb -Connection $SourceConnection 
$TargetSite = Get-PnPWeb -Connection $TargetConnection
$query = "<View Scope='RecursiveAll'><RowLimit>5000</RowLimit></View>"  

$list= Get-PnPList test676 -Connection $SourceConnection

$Items =Get-PnPListItem -List $list -Query $query -Connection $SourceConnection
$count=0
foreach($item in $Items)
{
#Write-host $item.Id
$count++

}
Write-host $count
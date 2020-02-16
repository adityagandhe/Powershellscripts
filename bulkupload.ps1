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
Connect-PnPOnline -Url "https://yavatmal3.sharepoint.com/sites/modernTeam"
for ( $i=6000; $i -lt 8000; $i++)
{
   Write-Host "Value of i is" $i

   Add-PnPListItem -List "test676" -Values @{"Title"=$i}

}

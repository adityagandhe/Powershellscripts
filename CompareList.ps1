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


$SourceConnection = Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/modernTeam"  -ReturnConnection
$TargetConnection = Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/ModernTeam/testClassic" -ReturnConnection

$SourceSite = Get-PnPWeb -Connection $SourceConnection
$TargetSite = Get-PnPWeb -Connection $TargetConnection



$SourceListCollection = Get-PnPList  -Connection $SourceConnection | Where { $_.Hidden -eq $false }
$TargetListCollection = Get-PnPList  -Connection $TargetConnection | Where { $_.Hidden -eq $false }

foreach ($sourceList in $SourceListCollection ) {
    $targetList = Get-PnPList -Identity $sourcelist.Title -Connection $TargetConnection
    Write-host -ForegroundColor Yellow "Comparing the list" $sourceList.Title

    if ($targetList -eq $null) {
        Write-host $sourcelist.Title "does not exisits on the target site"
    }
    if ($sourcelist.ItemCount -ne $targetList.ItemCount) {
        if ($targetList -ne $null) {
            Write-host $sourcelist.Title "Count Mismatch"
        }
    }
    else {
        $SourcelistFeilds = Get-PnPField -List $sourcelist.Title | Where { $_.Hidden -eq $false } | Where { $_.TypeDisplayName -ne "Computed" }

        $TargetlistFeilds = Get-PnPField -List $targetList.Title | Where { $_.Hidden -eq $false } | Where { $_.TypeDisplayName -ne "Computed" }
        if ($TargetlistFeilds -eq $null) {
            Write-host $sourcelist.Title "does not exisits on the target site"
        }

        else {
            $fieldstoCompare = @()
            $sourceListItem = @()
            $targetlistItem = @()
            foreach ($feild in $SourcelistFeilds) {
                if (($feild.TypeDisplayName -eq "Single line of text") -or ($feild.TypeDisplayName -eq "person or group")) {
                    $fieldstoCompare += $feild.Title
                }

            }
            $query = "<View Scope='RecursiveAll'><RowLimit>5000</RowLimit></View>"
            if ($sourcelist.ItemCount -GT 0) {
                $SourceItemCollection = Get-PnPListItem -List $sourcelist.Title -Query $query -Connection $SourceConnection
                foreach ($item in  $SourceItemCollection) {
                    $VALUE = $item.ID.ToString() + "," + $item["Author"].LookupValue.ToString() + "," + $item["Editor"].LookupValue.ToString()
                    foreach ($fieldvalue in $fieldstoCompare) {
                        $VALUE = $VALUE + "," + $item[$fieldvalue]
                    }

                    $VALUE = $VALUE
                    $props = @{'Key' = $VALUE }

                    $itemVALUE = New-Object -TypeName PSObject -Property $props
                    $sourceListItem += $itemVALUE

                }
            }
            if ($targetList.ItemCount -gt 0) {
                $TargetItemCollection = Get-PnPListItem -List $sourcelist.Title -Query $query  -Connection $TargetConnection

                foreach ($item in  $TargetItemCollection) {

                    $VALUE = $item.ID.ToString() + "," + $item["Author"].LookupValue.ToString() + "," + $item["Editor"].LookupValue.ToString()
                    foreach ($fieldvalue in $fieldstoCompare) {
                        $VALUE = $VALUE + "," + $item[$fieldvalue]
                    }

                    $VALUE = $VALUE
                    $props = @{'Key' = $VALUE }

                    $itemVALUE = New-Object -TypeName PSObject -Property $props

                    $targetlistItem += $itemVALUE

                }
            }


            Compare-Object $sourceListItem  $targetlistItem  -Property "Key" | Out-File "Z:\pnppowershell\Comparsionreport.csv"
        }

    }
}
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

#Read the Flag values

$isCreatedByRequied = "No"
$isModifiedByRequired = "No"
$isCreatedRequied = "No"
$isModifiedRequired = "No"
$isChoiceRequired = "No"
$isDateRequired = "No"
$isPersonRequired = "No"
$isLookupRequired = "Yes"
$isYesNoRequired = "No"
$isVersionRequired = "Yes"
$isCalculatedRequired = "Yes"

$SourceConnection = Connect-PnPOnline -url "https://yavatmal3.sharepoint.com/sites/modernTeam" -Credentials (Get-Credential)  -ReturnConnection
$TargetConnection = Connect-PnPOnline -url "https://yavatmal4.sharepoint.com/sites/modernTeam" -Credentials (Get-Credential)  -ReturnConnection

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


        }
        $query = "<View Scope='RecursiveAll'><RowLimit>5000</RowLimit></View>"
        if ($sourcelist.ItemCount -GT 0) {
            $SourceItemCollection = Get-PnPListItem -List $sourcelist.Title -Query $query -Connection $SourceConnection

            foreach ($item in  $SourceItemCollection) {
                $VALUE = $item.ID.ToString()


                if ($isCreatedByRequied -eq "Yes") {
                    $VALUE = $VALUE + "," + $item["Author"].LookupValue.ToString()
                }
                if ($isModifiedByRequired -eq "Yes") {
                    $VALUE = $VALUE + "," + $item["Editor"].LookupValue.ToString()
                }
                if ( $isCreatedRequied -eq "Yes") {
                    $VALUE = $VALUE + "," + $item["Created"].ToString()
                }

                if ($isModifiedRequired -eq "Yes") {
                    $VALUE = $VALUE + "," + $item["Modified"].ToString()
                }

                if ($isVersionRequired -eq "Yes") {

                    $VALUE = $VALUE + "," + $item["_UIVersionString"]

                }


                foreach ($fieldvalue in $SourcelistFeilds) {

                    if (($fieldvalue.TypeDisplayName -eq "Person or Group") -and ($isPersonRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title].LookupValue.ToString()
                        }
                    }
                    if ( ($fieldvalue.TypeDisplayName -eq "Lookup") -and ($isLookupRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title].LookupValue.ToString()
                        }
                    }
                    if (($fieldvalue.TypeDisplayName -eq "Choice") -and ($isChoiceRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title]
                        }
                    }
                    if (($fieldvalue.TypeDisplayName -eq "Date and Time") -and ($isDateRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            if (!(($fieldvalue.Title -eq "Modified" ) -or ($fieldvalue.Title -eq "Created"))) {
                                $VALUE = $VALUE + "," + $item[$fieldvalue.Title].ToString()
                            }
                        }
                    }
                    if ( ($fieldvalue.TypeDisplayName -eq "Calculated") -and ($isCalculatedRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title]
                        }
                    }

                    if ( ($fieldvalue.TypeDisplayName -eq "Yes/No") -and ($isYesNoRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title]
                        }
                    }
                }

                $VALUE = $VALUE
                $props = @{'Key' = $VALUE }

                $itemVALUE = New-Object -TypeName PSObject -Property $props
                $sourceListItem += $itemVALUE

            }
        }
        if ($targetList.ItemCount -gt 0) {
            $TargetItemCollection = Get-PnPListItem -List $sourcelist.Title -Query $query  -Connection $TargetConnection

            foreach ($item in   $TargetItemCollection) {
                $VALUE = $item.ID.ToString()

                if ($isCreatedByRequied -eq "Yes") {
                    $VALUE = $VALUE + "," + $item["Author"].LookupValue.ToString()
                }
                if ($isModifiedByRequired -eq "Yes") {
                    $VALUE = $VALUE + "," + $item["Editor"].LookupValue.ToString()
                }
                if ( $isCreatedRequied -eq "Yes") {
                    $VALUE = $VALUE + "," + $item["Created"].ToString()
                }

                if ($isModifiedRequired -eq "Yes") {
                    $VALUE = $VALUE + "," + $item["Modified"].ToString()
                }


                if ($isVersionRequired -eq "Yes") {

                    $VALUE = $VALUE + "," + $item["_UIVersionString"]

                }


                foreach ($fieldvalue in $SourcelistFeilds) {

                    if (($fieldvalue.TypeDisplayName -eq "Person or Group") -and ($isPersonRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title].LookupValue.ToString()
                        }
                    }
                    if ( ($fieldvalue.TypeDisplayName -eq "Lookup") -and ($isLookupRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title].LookupValue.ToString()
                        }
                    }
                    if (($fieldvalue.TypeDisplayName -eq "Choice") -and ($isChoiceRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title]
                        }
                    }
                    if (($fieldvalue.TypeDisplayName -eq "Date and Time") -and ($isDateRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            if (!(($fieldvalue.Title -eq "Modified" ) -or ($fieldvalue.Title -eq "Created"))) {
                                $VALUE = $VALUE + "," + $item[$fieldvalue.Title].ToString()
                            }
                        }
                    }
                    if ( ($fieldvalue.TypeDisplayName -eq "Calculated") -and ($isCalculatedRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title]
                        }
                    }
                    if ( ($fieldvalue.TypeDisplayName -eq "Yes/No") -and ($isYesNoRequired -eq "Yes")) {
                        if ($item[$fieldvalue.Title] -ne $null) {
                            $VALUE = $VALUE + "," + $item[$fieldvalue.Title]
                        }
                    }
                }

                $VALUE = $VALUE
                $props = @{'Key' = $VALUE }

                $itemVALUE = New-Object -TypeName PSObject -Property $props

                $targetlistItem += $itemVALUE

            }
        }


        Compare-Object $sourceListItem  $targetlistItem  -Property "Key" | Out-File "Z:\pnppowershell\Comparsionreport.csv" -Append
    }

}

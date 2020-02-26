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


Write-Host -ForegroundColor Yellow "Choose option 1 to compare Site and its childs sites,all the lists would be compared"

Write-Host -ForegroundColor Yellow "Choose option 2 to compare Site ,all the lists would be compared"

Write-Host -ForegroundColor Yellow "Choose option 3 to compare specific lists of the given Site"

$ScriptOption = Read-Host "Enter 1 /2/ 3 and make sure that the input file has the data in the required format"

#Read the Flag values



$isCreatedByRequied = "Yes"
$isModifiedByRequired = "Yes"
$isCreatedRequied = "No"
$isModifiedRequired = "No"
$isChoiceRequired = "Yes"
$isDateRequired = "Yes"
$isPersonRequired = "Yes"
$isLookupRequired = "Yes"
$isYesNoRequired = "Yes"
$isVersionRequired = "No"
$isCalculatedRequired = "Yes"

#Global Variables

$Option1WebUrl = $null
$Option2WebUrl = $null
$Option3WebUrl = $null
main
Function Main() {
    if ($ScriptOption -eq "1" -or $ScriptOption -eq "2" ) {
        $Option1WebUrl = Import-Csv "Z:\pnppowershell\Option1.csv"

        foreach ($site in $Option1WebUrl ) {
            $SourceSite = $site.Source
            $SourceSite = $SourceSite.Trim()
            $SourceSite = $SourceSite.TrimEnd('/')

            $TargetSite = $site.Target
            $TargetSite = $TargetSite.Trim()
            $TargetSite = $TargetSite.TrimEnd('/')

            CompareSites $SourceSite $TargetSite

        }

    }


    if ($ScriptOption -eq "3" ) {

    }


}


Function CompareSites($SourceSite, $TargetSite) {

    Function ProcessSite($Source, $Target) {
        $SourceListCollection = Get-PnPList -Web $Source | Where { $_.Hidden -eq $false }
        $TargetListCollection = Get-PnPList -Web $Target | Where { $_.Hidden -eq $false }

        foreach ($sourceList in $SourceListCollection ) {

            $targetList = Get-PnPList -Identity $sourcelist.Title -Connection $TargetConnection
            Write-host -ForegroundColor Yellow "Comparing the list" $sourceList.Title
            "Comparing the  list " + $sourceList.Title | Out-File -FilePath Z:\pnppowershell\ComparsionLog.csv -Append

            if ($targetList -eq $null) {
                Write-host $sourcelist.Title "does not exisits on the target site"
                $sourcelist.Title + "does not exisits on the target site" | Out-File -FilePath Z:\pnppowershell\ComparsionLog.csv -Append
            }
            if ($sourcelist.ItemCount -ne $targetList.ItemCount) {
                if ($targetList -ne $null) {
                    Write-host $sourcelist.Title "Count Mismatch"
                    Write-host $sourcelist.Title "Count Mismatch" | Out-File -FilePath Z:\pnppowershell\ComparsionLog.csv -Append

                }
            }
            else {
                $SourcelistFeilds = Get-PnPField -List $sourcelist.Title | Where { $_.Hidden -eq $false } | Where { $_.TypeDisplayName -ne "Computed" }

                $TargetlistFeilds = Get-PnPField -List $targetList.Title | Where { $_.Hidden -eq $false } | Where { $_.TypeDisplayName -ne "Computed" }
                if ($TargetlistFeilds -eq $null) {
                    Write-host $sourcelist.Title "does not exisits on the target site"
                    $sourcelist.Title + "does not exisits on the target site" | Out-File -FilePath Z:\pnppowershell\ComparsionLog.csv -Append

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
                        if ($ScriptOption -eq "1" ) {
                            $VALUE = "SiteName:" + $Source.Title + "," + "ListName:" + $sourcelist.Title + "," + "Id:" + $item.ID.ToString()

                        }
                        else {
                            $VALUE = "ListName:" + $sourcelist.Title + "," + "Id:" + $item.ID.ToString()
                        }
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

                        if ($ScriptOption -eq "1" ) {
                            $VALUE = "SiteName:" + $Target.Title + "," + "ListName:" + $targetList.Title + "," + "Id:" + $item.ID.ToString()
                        }
                        else {
                            $VALUE = "ListName:" + $targetList.Title + "," + "Id:" + $item.ID.ToString()
                        }
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


                Compare-Object $sourceListItem  $targetlistItem  -Property "Key" | Where-Object { $_.SideIndicator -eq '<=' } | Out-File -FilePath Z:\pnppowershell\Comparsionreport.csv -Append
            }

        }

    }


    $SourceConnection = Connect-PnPOnline -url $SourceSite   -ReturnConnection
    $TargetConnection = Connect-PnPOnline -url $TargetSite   -ReturnConnection

    $SourceSite = Get-PnPWeb -Connection $SourceConnection
    $TargetSite = Get-PnPWeb -Connection $TargetConnection

    "Comparing the Source Site" + $SourceSite.Url + "and the target site" + $TargetSite.Url | Out-File -FilePath Z:\pnppowershell\ComparsionLog.csv -Append

    ProcessSite $SourceSite $TargetSite

    if ($ScriptOption -eq "1") {
        $SourceWebs = Get-PnPSubWebs -Connection $SourceConnection
        $TagetWebs = Get-PnPSubWebs -Connection $TargetConnection

        $SubsiteCount = $SourceWebs.Count

        for ($i = 0 ; $i -lt $SubsiteCount ; $i++) {
            ProcessSite $SourceWebs[$i] $TargetSite[$i]
        }

    }


}
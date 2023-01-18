﻿
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host
Write-host -ForegroundColor Green "Script execution for finding particular is in progress...."
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss

$Sitepath = $filepath + "\GetInstanceofFolder.csv"
$LogFilePath = $filepath + "\GetInstanceofFolderLog" + $date + ".csv"
#$Credentials =$null
#$SiteURL = "https://yavatmal3.sharepoint.com/sites/ModernTeam"
#$ListName = "DocumentSetModern"
# $foldername="General"
# $unique='49fe5de1-8376-4a09-8f83-6bb5c28e8f97'
#Log Function
Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Update-HistoricalId ($SiteURL, $ListName) {
    Try {
        #Connect to PnP Online
        Connect-PnPOnline -Url $SiteURL -UseWebLogin
        GenerateLog("SUCCESS:Connected successfully for the site: " + $SiteURL)
        
        #Get All Folders recursively
        #$FoldersByGetFolder = Get-PnPFolderItem -FolderSiteRelativeUrl $ListName -ItemType Folder  -Recursive 
       # Write-Host -ForegroundColor Green $FoldersByGetFolder.Count
    $Folders=  Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object { $_.FileSystemObjectType -eq "Folder"}
        Write-host -ForegroundColor Yellow "Total Number of Items in the Folder in the list:" $ListName "of site:" $SiteURL "is"  $Folders.Count
        GenerateLog("Total Number of Items in the Folder in the list: " + $ListName + "of site: " + $SiteURL + "is " + $Folders.Count)
      
        for ($i = 0; $i -lt $Folders.Count ; $i++) {
            # $item = Get-PnPListItem -List $ListName -UniqueId $Folders[$i].UniqueId
            try {
                if( ($Folders[$i].FieldValues.FileLeafRef -eq "Test" -or $Folders[$i].FieldValues.FileLeafRef -eq "Test1")-and $Folders[$i].FieldValues.FileRef -like "*/unzip/*") {
                   Write-Host -ForegroundColor Yellow $Folders[$i].FieldValues.FileRef  $Folders[$i].Id
                    Write-Host -ForegroundColor Yellow "Updating historical id for the folder" $Folders[$i].Name
                    if ([string]::IsNullOrEmpty($item.FieldValues.HistoricalId) ) {
    
                    #    Set-PnPListItem -List $ListName -Identity $item.Id -Values @{"HistoricalId" = $($Folders[$i].Name) }
                     #   GenerateLog("SUCCESS: Updated the historical id folder : " + $Folders[$i].Name + "of Id:" + $item.Id )
         

                    }
                    else {
                        Write-Host -ForegroundColor Red "Folder"$Folders[$i].Name "with the Id:" $item.Id "already has the value for historical id:" $item.FieldValues.HistoricalId
                        GenerateLog("ERROR: Folder: " + $Folders[$i].Name + "with the Id: " + $item.Id + "already has the value for historical id: " + $item.FieldValues.HistoricalId)
                        
                    }

                }
            }
            catch {
                GenerateLog("ERROR: Error in updating the historical id for the folder:" + $Folders[$i].Name + "with exception : " + $_.exception.message)
            }
        }
    }
    catch {
        write-host "Error: $($_.Exception.Message)" -foregroundcolor Red
        GenerateLog("ERROR: Error in updating the historical id for the list: " + $ListName + "with exception : " + $_.exception.message)
    }
}


function Main() {
    try {
        $listCollections = Import-Csv $Sitepath
    }
    catch {
        GenerateLog ("ERROR: Make sure that Input File is added at the desired location");



    }
    $listCollections | ForEach-Object {
        $ListName = $_."List";
        $url = $_."SiteUrl";
        $SiteURL = $url.TrimEnd('/');
        $SiteURL = $url.Trim();
       
        GenerateLog ("Applying historical id on the list " + $ListName + "for the Site:" + $SiteURL)
        Update-HistoricalId $SiteURL $ListName;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for finding particular folder is in progress.. Completed...."

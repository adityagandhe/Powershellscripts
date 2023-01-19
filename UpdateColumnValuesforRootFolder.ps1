
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host

Write-host -ForegroundColor Green "Script execution for updating the Historical Id column value for the root level folders is in progress...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "started at" $now 
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$fileref="/sites/ModernTeam/DocumentSetModern/"
$Sitepath = $filepath + "\UpdateHistoricalId.csv"
$LogFilePath = $filepath + "\UpdateHistoricalIdLog" + $date + ".csv"

Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Update-HistoricalId ($SiteURL, $ListName) {
    Try {
        #Connect to PnP Online
        Connect-PnPOnline -Url $SiteURL -UseWebLogin
        GenerateLog("INFO:Script started at : " + $now)
        GenerateLog("SUCCESS:Connected successfully for the site: " + $SiteURL)
        #Get Id of Folder working
        #$item= Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object {$_.FieldValues.Title -eq $foldername}
    

        #Get All Folders from the document Library from root level considering that root level wont have more than 5000 failing for large
       # $Folders = Get-PnPFolderItem -FolderSiteRelativeUrl $ListName -ItemType Folder 
                $Folders = Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object { $_.FileSystemObjectType -eq "Folder"}
     
        
        for ($i = 0; $i -lt $Folders.Count ; $i++) {
         
         # $item = Get-PnPListItem -List $ListName -Query "<View><Query><Where><Eq><FieldRef Name='UniqueId'/><Value Type='Guid'>$($Folders[$i].UniqueId)</Value></Eq></Where></Query></View>"
          $childfolderpath =$fileref + $Folders[$i].FieldValues.FileLeafRef
          if(($Folders[$i].Fieldvalues.FileLeafRef -like "DRU*" -or $Folders[$i].Fieldvalues.FileLeafRef -like "DRI*" ) -and ($Folders[$i].Fieldvalues.FileRef -eq $childfolderpath))
          {
           
            try {
                if ($Folders[$i].Fieldvalues.FileLeafRef -ne "Forms" -or $Folders[$i].Fieldvalues.FileLeafRef -ne $null) {
                    
                    GenerateLog("INFO:Updating the historical id for the  folder : " + $Folders[$i].Fieldvalues.FileLeafRef + "with the path: " + $Folders[$i].Fieldvalues.FileRef)
                    Write-Host -ForegroundColor Yellow "Updating historical id for the folder" $Folders[$i].Fieldvalues.FileLeafRef
                    if ([string]::IsNullOrEmpty($Folders[$i].FieldValues.HistoricalId) ) {
    
                        Set-PnPListItem -List $ListName -Identity $Folders[$i].Fieldvalues.ID -Values @{"HistoricalId" = $($Folders[$i].Fieldvalues.FileLeafRef) }
                        GenerateLog("SUCCESS: Updated the historical id folder : " + $Folders[$i].Fieldvalues.FileLeafRef + "at path:" + $Folders[$i].Fieldvalues.FileRef )
         

                    }
                    else {
                        Write-Host -ForegroundColor Red "Folder"$Folders[$i].Name "with the path:" $Folders[$i].Fieldvalues.FileLeafRef "already has the value for historical id:" $Folders[$i].FieldValues.HistoricalId
                        GenerateLog("FAILURE: Folder: " + $Folders[$i].Name + "with the path: " + $Folders[$i].Fieldvalues.FileLeafRef + "already has the value for historical id: " + $Folders[$i].FieldValues.HistoricalId)
                        
                    }

                }
            }
            catch {
                GenerateLog("FAILURE: Error in updating the historical id for the folder:" + $Folders[$i].Name + "with exception : " + $_.exception.message)
            }
        }
        else
        {
        GenerateLog("FAILURE:Foldername is not DRU/DRI or is not a parent level folder for: " + $Folders[$i].Fieldvalues.FileLeafRef + "with the path: " + $Folders[$i].Fieldvalues.FileRef)
                    Write-Host -ForegroundColor Yellow "Foldername is not DRU or DRI for:" $Folders[$i].Fieldvalues.FileRef
        }
        }
    }
    catch {
        write-host "Error: $($_.Exception.Message)" -foregroundcolor Red
        GenerateLog("FAILURE: Error in updating the historical id for the list: " + $ListName + "with exception : " + $_.exception.message)
    }
}


function Main() {
    try {
        $listCollections = Import-Csv $Sitepath
    }
    catch {
        GenerateLog ("FAILURE: Make sure that Input File is added at the desired location");



    }
    $listCollections | ForEach-Object {
        $ListName = $_."List";
        $url = $_."SiteUrl";
        $SiteURL = $url.TrimEnd('/');
        $SiteURL = $url.Trim();
       
        GenerateLog ("INFO: Applying historical id on the list " + $ListName + "for the Site:" + $SiteURL)
        Update-HistoricalId $SiteURL $ListName;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for updating the Historical Id column value for the root level folders is Completed...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "STOPPED at" $now 
       GenerateLog("INFO:Script completed at : " + $now)
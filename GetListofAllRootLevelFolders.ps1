
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host

Write-host -ForegroundColor Green "Script execution for getting root level folders is in progress...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "started at" $now 
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$fileref="/sites/ModernTeam/DocumentSetModern/"
$Sitepath = $filepath + "\UpdateHistoricalId.csv"
$outputfile =$filepath + "\AllFolderNames.csv"
$LogFilePath = $filepath + "\GetRootLevelFoldersLog" + $date + ".csv"
$Countupdate =0;
  $folderNames = @();
Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Get-RootLevelFolders ($SiteURL, $ListName) {
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
     
        Write-Host -ForegroundColor Green "Total number of folders found in this library is " $Folders.Count
        for ($i = 0; $i -lt $Folders.Count ; $i++) {
         
         # $item = Get-PnPListItem -List $ListName -Query "<View><Query><Where><Eq><FieldRef Name='UniqueId'/><Value Type='Guid'>$($Folders[$i].UniqueId)</Value></Eq></Where></Query></View>"
          $childfolderpath =$fileref + $Folders[$i].FieldValues.FileLeafRef
          if(($Folders[$i].Fieldvalues.FileLeafRef -like "DRU*" -or $Folders[$i].Fieldvalues.FileLeafRef -like "DRI*" ) -and ($Folders[$i].Fieldvalues.FileRef -eq $childfolderpath) -and ([string]::IsNullOrEmpty($Folders[$i].FieldValues.HistoricalId)))
          {
           
            try {
                if ($Folders[$i].Fieldvalues.FileLeafRef -ne "Forms" -or $Folders[$i].Fieldvalues.FileLeafRef -ne $null) {
                    $Countupdate = $Countupdate + 1
                     $jsObject = New-Object System.Object
                     $jsObject | Add-Member -MemberType NoteProperty -Name "FolderName" -Value $Folders[$i].Fieldvalues.FileLeafRef
                    GenerateLog("INFO:Getting root level folders : " + $Folders[$i].Fieldvalues.FileLeafRef + "with the path: " + $Folders[$i].Fieldvalues.FileRef)
                    Write-Host -ForegroundColor Green "Getting root level folders" $Folders[$i].Fieldvalues.FileLeafRef
                   $folderNames += $jsObject

                }
            }
            catch {
                GenerateLog("FAILURE: Error in getting the root level folder:" + $Folders[$i].Fieldvalues.FileLeafRef + "with exception : " + $_.exception.message)
            }
          
        }
        else
        {
        GenerateLog("FAILURE:Foldername is not DRU/DRI OR is not a parent level folder for: " + $Folders[$i].Fieldvalues.FileLeafRef + "with the path: " + $Folders[$i].Fieldvalues.FileRef)
                    Write-Host -ForegroundColor Red "Foldername is not DRU/DRI OR is not a parent level folderfor:" $Folders[$i].Fieldvalues.FileRef
        }
        }
        if ( $folderNames -ne $null) {
                            $folderNames  | Export-Csv -Path $outputfile -NoTypeInformation -Append
                        }
  Write-Host -ForegroundColor Cyan "Total number of folders fetched is "  $Countupdate
GenerateLog("INFO:Total number of folders fetched are : " + $Countupdate)
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
       
        GenerateLog ("INFO: Getting root level folders on the list " + $ListName + "for the Site:" + $SiteURL)
        Get-RootLevelFolders $SiteURL $ListName;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for getting root level folders is Completed...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "STOPPED at" $now 
       GenerateLog("INFO:Script completed at : " + $now)

 
#Get the Folder from site relative URL
#Config Variables
Clear-Host
Write-host -ForegroundColor Green "Script execution for finding  instance of restricted  folder is in progress...."
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$restrictedFolder1="*DocumentSetModern1*"
$restrictedFolder2="*DocumentSetModern2*"
$unzipFoldername="*unzip*"
$Sitepath = $filepath + "\GetInstanceofFolder.csv"
$LogFilePath = $filepath + "\GetInstanceofFolderLog" + $date + ".csv"
#$Credentials =$null
$Countupdate =0;
$now =Get-Date
     Write-Host -ForegroundColor Yellow "started at" $now 
#Log Function
Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Find-RestrictedFolders ($SiteURL, $ListName) {
    Try {
        #Connect to PnP Online
        Connect-PnPOnline -Url $SiteURL -UseWebLogin
        GenerateLog("SUCCESS:Connected successfully for the site: " + $SiteURL)
        
        
        $Folders=  Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object { $_.FileSystemObjectType -eq "Folder"}
        Write-host -ForegroundColor Yellow "Total folders in the list is:" $Folders.Count
        GenerateLog("INFO:Total folders in the list is: " + $Folders.Count)
      
        for ($i = 0; $i -lt $Folders.Count ; $i++) {
        
            # $item = Get-PnPListItem -List $ListName -UniqueId $Folders[$i].UniqueId
            try {
                      #if the name of the folder is Test and path has unzip and Path is not within the restricted folders
               if( ($Folders[$i].FieldValues.FileLeafRef -eq "Test" -or $Folders[$i].FieldValues.FileLeafRef -eq "Test1")-and $Folders[$i].FieldValues.FileRef -like $unzipFoldername  -and ($Folders[$i].FieldValues.FileRef -notlike $restrictedFolder1 -or $Folders[$i].FieldValues.FileRef -notlike $restrictedFolder1 )) {
                #  if( ($Folders[$i].FieldValues.FileLeafRef -eq "Test" -or $Folders[$i].FieldValues.FileLeafRef -eq "Test1")-and $Folders[$i].FieldValues.FileRef -like $unzipFoldername){
                   $Countupdate = $Countupdate +1
                   Write-Host -ForegroundColor Green "Found the restricted folder" $Folders[$i].FieldValues.FileRef  
                   GenerateLog("SUCCESS:Found the restricted folder" + $Folders[$i].FieldValues.FileRef )
                   
                    

                }
            }
            catch {
                GenerateLog("FAILURE: Error in finding restricted  folder:" + $Folders[$i].FieldValues.FileRef + "with exception : " + $_.exception.message)
            }
        }
         Write-Host -ForegroundColor Cyan "Total number of restricted folders found is "  $Countupdate
GenerateLog("INFO:Total number of restricted folders found  is : " + $Countupdate)
    }
    catch {
        write-host "Error: $($_.Exception.Message)" -foregroundcolor Red
        GenerateLog("FAILURE: site level error with exception : " + $_.exception.message)
    }
}


function Main() {
    try {
        $listCollections = Import-Csv $Sitepath
         GenerateLog("INFO:Script started at : " + $now)
    }
    catch {
        GenerateLog ("FAILURE: Make sure that Input File is added at the desired location");



    }
    $listCollections | ForEach-Object {
        $ListName = $_."List";
        $url = $_."SiteUrl";
        $SiteURL = $url.TrimEnd('/');
        $SiteURL = $url.Trim();
       
        GenerateLog ("INFO:Finding restricted folders for the library:  " + $ListName + "for the Site:" + $SiteURL)
        Find-RestrictedFolders $SiteURL $ListName;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for finding restricted folder is  Completed...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "STOPPED at" $now 
       GenerateLog("INFO:Script completed at : " + $now)
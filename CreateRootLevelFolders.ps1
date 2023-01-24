
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host

Write-host -ForegroundColor Green "Script execution for Creating root level folders is in progress...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "started at" $now 
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$fileref="/sites/ModernTeam/DocumentSetModern/"
$Sitepath = $filepath + "\AllFolderNames.csv"
$ListName
$SiteURL
$LogFilePath = $filepath + "\CreateRootLevelFoldersLog" + $date + ".csv"
$Countupdate =0;
  
Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Create-RootLevelFolders ($SiteURL, $folderName) {
    Try {
        
         $folderpath = $ListName + "/" + $folderName;
        try{
        $folderloc = Get-PnPFolder -Url $folderpath -ErrorAction SilentlyContinue
        }
        catch
        {
        Write-host -ForegroundColor Red "No folder exists"
        }
         if ([string]::IsNullOrEmpty($folderloc.Name )) {
         $Countupdate =$Countupdate+1;
            Write-Host -ForegroundColor Green " List: " $ListName "does not have a folder :" $folderName
            GenerateLog("SUCCESS :list: " + $ListName + "does not have a folder : " + $folderName)
            try
            {
             Resolve-PnPFolder -SiteRelativePath $folderpath -ErrorAction Stop
             Write-host -ForegroundColor Green " Folder name " $folderName "of site:" $SiteURL "and list: "$ListName "is created"
                GenerateLog("SUCCESS:Folder name " + $folderName + "is created for the list: " + $ListName + "of site: " + $SiteURL)

            }
            catch
            {
             Write-host -ForegroundColor Red " Folder name " $folderName "of site:" $SiteURL "and list: "$ListName "is created"
                GenerateLog("FAILURE:Folder name " + $folderName + "is not created for the list: " + $ListName + "of site: " + $SiteURL)
            }
        }
     
    

    }
    catch {
        write-host "Error: $($_.Exception.Message)" -foregroundcolor Red
        GenerateLog("FAILURE: Error in creating the folder  for the folder: " + $folderName+ "with exception : " + $_.exception.message)
    }
}


function Main() {
    try {
        $FolderCollections = Import-Csv $Sitepath
        $Collections = Import-Csv $Sitepath
        $SiteURL = Read-Host "Enter the SharePoint site Url"
        $ListName = Read-Host "Enter the target list name"
        Connect-PnPOnline -Url $SiteURL -UseWebLogin
        GenerateLog("SUCCESS: Connected successfully for the site: " + $SiteURL)
    }
    catch {
        GenerateLog ("FAILURE: Make sure that Input File is added at the desired location");



    }
    $FolderCollections | ForEach-Object {
        $folderName=$_."FolderName";
       
        GenerateLog ("INFO: Creating root level folders on the list " + $folderName + "for the Site:" + $SiteURL)
        Create-RootLevelFolders $SiteURL $folderName;
    }


}


Main
  Write-Host -ForegroundColor Cyan "Total number of folders created are "  $Countupdate
GenerateLog("INFO:Total number of folders fetched are : " + $Countupdate)
Write-host -ForegroundColor Green "Script execution for Creating root level folders is Completed...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "STOPPED at" $now 
       GenerateLog("INFO:Script completed at : " + $now)
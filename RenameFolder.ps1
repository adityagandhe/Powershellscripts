
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host
Write-host -ForegroundColor Green "Script execution for updating the folder name  for the root level folders is in progress...."
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$listName = "DocumentSetModern"
$Sitepath = $filepath + "\UpdateFolderName.csv"
$LogFilePath = $filepath + "\UpdateFolderNameLog" + $date + ".csv"

Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Update-FolderName ($SiteURL, $OldFolderName , $NewFolderName) {
    Try {
        #Connect to PnP Online
        
        
        $folderpath = $listName + "/" + $OldFolderName;
        try{
        $folderloc = Get-PnPFolder -Url $folderpath -ErrorAction SilentlyContinue
        }
        catch
        {
        Write-host -ForegroundColor Red "No folder exists"
        }
        if ([string]::IsNullOrEmpty($folderloc.Name )) {
            Write-Host -ForegroundColor Red " List: " $ListName "does not have a folder :" $OldFolderName
            GenerateLog("ERROR :list: " + $ListName + "does not have a folder : " + $OldFolderName)
        }
        else {
      


            try {
              Rename-PnPFolder -Folder $folderpath -TargetFolderName $NewFolderName -ErrorAction Stop
               
                Write-host -ForegroundColor Green "old folder name " $OldFolderName "of site:" $SiteURL "and list: "$listName "is updated with :" $NewFolderName
                GenerateLog("SUCCESS: old folder name " + $OldFolderName + "is updated with new name : " + $NewFolderName + "for the list: " + $ListName + "of site: " + $SiteURL)
            }
            catch {
                Write-host -ForegroundColor Red "Unable to update old folder name " $OldFolderName "of site:" $SiteURL "and list: "$listName " with error" Error: $($_.Exception.Message)
                GenerateLog("ERROR: Unable to update " + $OldFolderName +  "for the list: " + $ListName  +"with error"+$($_.Exception.Message))
            }
        }
        
    }
    catch {
        write-host  "Error: $($_.Exception.Message)" -foregroundcolor Red
        GenerateLog("ERROR: Error in updating the foldername  for the list: " + $ListName + "with exception : " + $_.exception.message)
    }
}


function Main() {
    try {
        $Collections = Import-Csv $Sitepath
        $SiteURL = Read-Host "Enter the SharePoint site Url"
        Connect-PnPOnline -Url $SiteURL -UseWebLogin
        GenerateLog("SUCCESS: Connected successfully for the site: " + $SiteURL)
    }
    catch {
        GenerateLog ("ERROR: Make sure that Input File is added at the desired location");



    }
    $Collections | ForEach-Object {
        $OldName = $_."OldName";
        $NewName = $_."NewName";
        
       
        GenerateLog ("Updating the foldername on the list " + $ListName + "for the Site:" + $SiteURL)
        Update-FolderName $SiteURL $OldName $NewName;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for updating the folder name for the root level folders is Completed...."

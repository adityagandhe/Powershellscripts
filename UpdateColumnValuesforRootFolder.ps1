
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host
Write-host -ForegroundColor Green "Script execution for updating the Historical Id column value for the root level folders is in progress...."
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss

$Sitepath = $filepath + "\UpdateHistoricalId.csv"
$LogFilePath = $filepath + "\UpdateHistoricalIdLog" + $date + ".csv"
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
        #Get Id of Folder working
        #$item= Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object {$_.FieldValues.Title -eq $foldername}
    

        #Get All Folders from the document Library from root level considering that root level wont have more than 5000
        $Folders = Get-PnPFolderItem -FolderSiteRelativeUrl $ListName -ItemType Folder 
        Write-host -ForegroundColor Yellow "Total Number of Items in the Folder in the list:" $ListName "of site:" $SiteURL "is"  $Folders.Count
        GenerateLog("Total Number of Items in the Folder in the list: " + $ListName + "of site: " + $SiteURL + "is " + $Folders.Count)
        #Get Folder/Subfolder details
        #$Folders | Select Name, ItemCount, ServerRelativeUrl ,UniqueId
        #Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object { $_.FileSystemObjectType -eq "Folder"}
        #  $id =Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object {$_.FieldValues.Title -eq "large"}
        #Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object { $_.FileSystemObjectType -eq "Folder"}
        for ($i = 0; $i -lt $Folders.Count ; $i++) {
            # $item = Get-PnPListItem -List $ListName -UniqueId $Folders[$i].UniqueId
            try {
                if ($Folders[$i].Name -ne "Forms" -or $Folders[$i].Name -ne $null) {
                    $item = Get-PnPListItem -List $ListName -Query "<View><Query><Where><Eq><FieldRef Name='UniqueId'/><Value Type='Guid'>$($Folders[$i].UniqueId)</Value></Eq></Where></Query></View>"
                    GenerateLog("Updating the folder : " + $Folders[$i].Name + "with the Id: " + $item.Id)
                    Write-Host -ForegroundColor Yellow "Updating historical id for the folder" $Folders[$i].Name
                    if ([string]::IsNullOrEmpty($item.FieldValues.HistoricalId) ) {
    
                        Set-PnPListItem -List $ListName -Identity $item.Id -Values @{"HistoricalId" = $($Folders[$i].Name) }
                        GenerateLog("SUCCESS: Updated the historical id folder : " + $Folders[$i].Name + "of Id:" + $item.Id )
         

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

Write-host -ForegroundColor Green "Script execution for updating the Historical Id column value for the root level folders is Completed...."

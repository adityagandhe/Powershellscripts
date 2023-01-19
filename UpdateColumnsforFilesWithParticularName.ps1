
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host
Write-host -ForegroundColor Green "Script execution for updating the Server relative path is in progress...."
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$restrictedpath="sites/ModernTeam/CheckCaml/Restricted/"
$requiredvalue="Records_Template.txt"
$Sitepath = $filepath + "\UpdateServerrelativePath.csv"
$LogFilePath = $filepath + "\UpdateServerrelativePathLog" + $date + ".csv"

Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Update-ServerRelativePath ($SiteURL, $ListName) {
    Try {
        #Connect to PnP Online
        Connect-PnPOnline -Url $SiteURL -UseWebLogin
        GenerateLog("SUCCESS:Connected successfully for the site: " + $SiteURL)
        #Get Id of Folder working
        $now =Get-Date
        Write-Host -ForegroundColor Red "Started at" $now
      $item= Get-PnPListItem -List $ListName -PageSize 1000 |Where-Object {(($_.FieldValues.FileLeafRef -like "*Records_Template*") -or($_.FieldValues.FileLeafRef -like "*Records Template*")-or($_.FieldValues.FileLeafRef -contains "*RecordsTemplate*")-or($_.FieldValues.FileLeafRef -contains "*Records-Template*")) }
   $now =Get-Date
   # Write-Host -ForegroundColor Red "stoped  at" $now "with count" $item_where.Count
    #$item= Get-PnPListItem -List $ListName -PageSize 1000 
    #$now =Get-Date
    # Write-Host -ForegroundColor Yellow "Sstopped at" $now "with count" $item.Count
   #      $item_filter= Get-PnPListItem -List $ListName -PageSize 1000 -Query "<View><Query><Where><And><Contains><FieldRef Name='DocIcon' /><Value Type='Computed'>txt</Value></Contains><Or><Contains><FieldRef Name='FileLeafRef' /><Value Type='File'>Records Template</Value></Contains><Or><Contains><FieldRef Name='FileLeafRef' /><Value Type='File'>Records_Template</Value></Contains> <Contains><FieldRef Name='FileLeafRef' /><Value Type='File'>RecordsTemplate</Value> </Contains> </Or></Or></And></Where>
#</Query></View>"

  Write-Host -ForegroundColor Yellow "ItemCount" $item.Count
               
        for ($i = 0; $i -lt $item.Count ; $i++) {
           
            try {

            GenerateLog("Updating the item : "  + $item[$i].Id)
            
           if(($item[$i].FieldValues.FileRef -notlike "*/Restricted*" ) -and ($item[$i].FieldValues.FileRef -like "*.txt" ))
            
          #  if(($item[$i].FieldValues.FileRef -notlike "*/Restricted*" ) -and ($item[$i].FieldValues.FileRef -like "*.txt" ) -and (($item[$i].FieldValues.FileLeafRef -like "*Records_Template*") -or($item[$i].FieldValues.FileLeafRef -like "*Records-Template*") -or ($item[$i].FieldValues.FileLeafRef -like "*RecordsTemplate*") -or ($item[$i].FieldValues.FileLeafRef -like "*Records Template*") )      )
            {

            Write-Host -ForegroundColor Green "Required files are found id" $item[$i].FieldValues.ID
            
            
            }
           
         # write-host $path
                   # Write-Host -ForegroundColor Yellow "Updating  the item" $item[$i].Id
                   # Set-PnPListItem -List $ListName -Identity $item.Id -Values @{"HistoricalId" = $($Folders[$i].Name) }
                     #   GenerateLog("SUCCESS: Updated the historical id folder : " + $Folders[$i].Name + "of Id:" + $item.Id )
               
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
       
        GenerateLog ("Applying server relative path  on the list " + $ListName + "for the Site:" + $SiteURL)
        Update-ServerRelativePath $SiteURL $ListName;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for updating the server relative path is Completed...."

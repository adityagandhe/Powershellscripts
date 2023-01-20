
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host
Write-host -ForegroundColor Green "Script execution for adding unzipp folder in final reports folders is in progress...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "started at" $now 
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$ReportName = "Report1"
$ReportPath
$Serverpath="/sites/ModernTeam/"
$fileref="/sites/ModernTeam/DocumentSetModern/"
$UnzipName = "unzip"
$avoidfolder1 ="*Test*"

$avoidfolder3="*unzip*"
$UnzipPath
$Sitepath = $filepath + "\CreateFolderatrootlevel.csv"
$LogFilePath = $filepath + "\RestrucutreFolderLog" + $date + ".csv"
$Countupdate =0;
Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Restrucutre-FinalReports ($SiteURL, $ListName) {
    Try {
        #Connect to PnP Online
        Connect-PnPOnline -Url $SiteURL -UseWebLogin
        GenerateLog("SUCCESS:Connected successfully for the site: " + $SiteURL)
       
    

        #Get All Folders from the document Library from root level but this would fail for large folders
       # $Folders = Get-PnPFolderItem -FolderSiteRelativeUrl $ListName -ItemType Folder
        $Folders = Get-PnPListItem -List $ListName -PageSize 1000 | Where-Object { $_.FileSystemObjectType -eq "Folder"}
        Write-Host -ForegroundColor Cyan "Total folders in the list is: " $Folders.Count
        for ($i = 0; $i -lt $Folders.Count ; $i++) {
          
            try {
             $childfolderpath =$fileref + $Folders[$i].FieldValues.FileLeafRef
               if($Folders[$i].Fieldvalues.Processed -eq $null -and($Folders[$i].Fieldvalues.FileLeafRef -like "DRU*" -or $Folders[$i].Fieldvalues.FileLeafRef -like "DRI*" )-and ($Folders[$i].Fieldvalues.FileRef -eq $childfolderpath))
               {
           # Forms is the OOTB folder created inside a library
                if ($Folders[$i].Fieldvalues.FileLeafRef -eq "Forms" -or $Folders[$i].Fieldvalues.FileLeafRef -eq $null) {

                     Write-host -ForegroundColor Red "Ignoring blank folder or OOTB Forms folder or non parent level folders"
                    }
                    else
                    {
                    $Countupdate = $Countupdate +1
                     # Try to find if subfolder with name report os found
                    
                    $ReportPath_temp = $ListName + "/" + $Folders[$i].Fieldvalues.FileLeafRef + "/" + $ReportName;

                    try {
                        $ReportPath = Get-PnPFolder -Url $ReportPath_temp -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-host -ForegroundColor Red "No report folder exists for the root folder with path" $Folders[$i].Fieldvalues.FileRef
                    }
                    if ([string]::IsNullOrEmpty($ReportPath.Name )) {
                       # Write-Host -ForegroundColor Red " Folder: " $Folders[$i].Name "does not have a report folder :" 
                        Write-host -ForegroundColor Red "No report folder exists for the root folder with path" $Folders[$i].Fieldvalues.FileRef
                        GenerateLog("FAILURE: No report folder exists for the root folder with path : " + $Folders[$i].Fieldvalues.FileRef  )
                        Set-PnPListItem -List $ListName -Identity $Folders[$i].Fieldvalues.ID -Values @{"Processed" = "No Report Folder" }
                    }
                    # HAS THE REPORT FOLDER
                    else {
                               
                               #TRY IF UNZIP FOLDER IS PRESENT
                                Write-host -ForegroundColor Green "Report folder exists for "$Folders[$i].Fieldvalues.FileRef
                        $UnzipPath_temp = $ListName + "/" + $Folders[$i].Fieldvalues.FileLeafRef + "/" + $ReportName + "/" + $UnzipName;
                        $unzip_path_folder =$ListName + "/" + $Folders[$i].Fieldvalues.FileLeafRef + "/" + $ReportName
                        try {
                            $UnzipPath = Get-PnPFolder -Url $UnzipPath_temp  -ErrorAction SilentlyContinue 
                            if($UnzipPath -ne $null)
                            {
                            Write-host -ForegroundColor Red "unzip folder exists for "$Folders[$i].Fieldvalues.FileRef
                            GenerateLog("FAILURE: Unzip folder  exists for the root folder with path : " + $Folders[$i].Fieldvalues.FileRef  )
                            Set-PnPListItem -List $ListName -Identity $Folders[$i].Fieldvalues.ID -Values @{"Processed" = "Unzipped already exists" }
                            }
                        }
                        catch {
                            Write-host -ForegroundColor Green "No  unzip folder exists for "$Folders[$i].Fieldvalues.FileRef
                            GenerateLog("SUCCESS: No  unzip folder exists root folder with path : " + $Folders[$i].Fieldvalues.FileRef  )

                        }
                            if ([string]::IsNullOrEmpty($UnzipPath.Name )) {
                                Write-Host -ForegroundColor Green " Folder: " $Folders[$i].Fieldvalues.FileLeafRef  "does not have a unzip folder :" $reportfolderpath
                                #Resolve is failing for large list

                                #$reportfolder = Resolve-PnPFolder $UnzipPath_temp
                               $reportfolder= Add-PnPFolder -Name $UnzipName -Folder $unzip_path_folder
                                 $Serverpath_temp =$Serverpath +$ReportPath_temp
                                 $unzippath_copy=$Serverpath +$UnzipPath_temp
                                 #earlier working
                             # $items =Get-PnPListItem -List $ListName -FolderServerRelativeUrl $Serverpath_temp 
                             #GET PARENT LEVEL FOLDERS OF THE FINAL RESPONSE
                              $items =Get-PnPFolderItem -FolderSiteRelativeUrl $ReportPath_temp -ItemType All
                             write-host -ForegroundColor Yellow "Total number of items in the report folder with path" $ReportPath_temp "is" $items.count
                              GenerateLog("SUCCESS: Total number of items found for  : " + $Folders[$i].FieldValues.FileLeafRef +"is"+$items.count )
                             for($j =0;$j -lt $items.Count ;$j++)
                             {
                         
                           if($items[$j].GetType().Name -eq "Folder")
                           {
                           if($items[$j].Name -like $avoidfolder1 -or $items[$j].Name -like $avoidfolder3)
                           {
                           Write-Host -ForegroundColor Cyan "Restricted Folder Name: " $items[$j].Name "at location " $items[$j].ServerRelativeUrl

                          
                              }
                              else
                              {
                                $source =$ReportPath_temp +"/"+$items[$j].Name
                              Copy-PnPFile -SourceUrl $source -TargetUrl $unzippath_copy -Force
                              Write-Host -ForegroundColor Yellow "Copying folder from the source location: "$source " to: " $unzippath_copy
                              
                              GenerateLog("SUCCESS: Copying folder from the location  : " + $source +" to"+ $unzippath_copy )
                              }
                              }
                              else
                              {
                                 $source =$ReportPath_temp +"/"+$items[$j].Name
                              Copy-PnPFile -SourceUrl $source -TargetUrl $unzippath_copy -Force 
                               Write-Host -ForegroundColor Magenta "Copying file from the source location: "$source " to: " $unzippath_copy
                              
                              GenerateLog("SUCCESS: Copying file from the location  : " + $source +" to"+ $unzippath_copy )
                              }
                            # }
                            }
                            Set-PnPListItem -List $ListName -Identity $Folders[$i].FieldValues.ID -Values @{"Processed" = "Yes" }
                            }
                            else
                            {
                          #  write-host -ForegroundColor red "Unzip already exists for:" $items[$j].ServerRelativeUrl

                            }
                        }
                    }
                    }
                    else
                    {
                     Write-Host -ForegroundColor Red "Folder is already processed OR the name of the folder is not in a required format:" $Folders[$i].FieldValues.FileRef
                       GenerateLog("FAILURE: Folder is already processed OR the name of the folder is not in a required format : " + $Folders[$i].FieldValues.FileRef  )
                    }
                         
            }
            catch {
                GenerateLog("ERROR: Error in updating the historical id for the folder:" + $Folders[$i].FieldValues.FileRef + "with exception : " + $_.exception.message)
            }
        }
        Write-Host -ForegroundColor Cyan "Total number of folders processed is "  $Countupdate
GenerateLog("INFO:Total number of folders processed is : " + $Countupdate)
    }
    catch {
        write-host "Error: $($_.Exception.Message)" -foregroundcolor Red
        GenerateLog("ERROR: Error in updating the historical id for the list: " + $ListName + "with exception : " + $_.exception.message)
    }
}


function Main() {
    try {
     GenerateLog("INFO:Script started at : " + $now)
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
       
        GenerateLog ("INFO:Creating unzip folders in the list : " + $ListName + "for the Site:" + $SiteURL)
        Restrucutre-FinalReports $SiteURL $ListName;
    }


}


Main

Write-host -ForegroundColor Green " Script execution for adding unzipp folder in final reports folders root level folders is Completed...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "STOPPED at" $now 
       GenerateLog("INFO:Script completed at : " + $now)
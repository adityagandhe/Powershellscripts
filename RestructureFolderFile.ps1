
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host
Write-host -ForegroundColor Green "Script execution for creating folder at  the root level folders is in progress...."
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$ReportName = "Report1"
$ReportPath
$Serverpath="/sites/ModernTeam/"
$UnzipName = "unzip"
$avoidfolder1 ="*Test*"

$avoidfolder3="*unzip*"
$UnzipPath
$Sitepath = $filepath + "\CreateFolderatrootlevel.csv"
$LogFilePath = $filepath + "\CreateFolderatrootlevelLog" + $date + ".csv"

Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}


function Update-HistoricalId ($SiteURL, $ListName) {
    Try {
        #Connect to PnP Online
        Connect-PnPOnline -Url $SiteURL -UseWebLogin
        GenerateLog("SUCCESS:Connected successfully for the site: " + $SiteURL)
       
    

        #Get All Folders from the document Library from root level
        $Folders = Get-PnPFolderItem -FolderSiteRelativeUrl $ListName -ItemType Folder 
        Write-host -ForegroundColor Yellow "Total Number of Folders in the list:" $ListName "of site:" $SiteURL "is"  $Folders.Count
        GenerateLog("INFO:Total Number of Folders in the list: " + $ListName + "of site: " + $SiteURL + "is " + $Folders.Count)
        
        for ($i = 0; $i -lt $Folders.Count ; $i++) {
          
            try {
                 Write-Host "Execution in progress for the folder number: " $i "and total folders are :" $Folders.Count
                  # Forms is the OOTB folder created inside a library
                if ($Folders[$i].Name -eq "Forms" -or $Folders[$i].Name -eq $null) {

                     Write-host -ForegroundColor Red "Ignoring blank folder or OOTB Forms folder"
                    }
                    else
                    {
                     # Try to find if subfolder with name report os found

                    $ReportPath_temp = $ListName + "/" + $Folders[$i].Name + "/" + $ReportName;

                    try {
                        $ReportPath = Get-PnPFolder -Url $ReportPath_temp -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-host -ForegroundColor Red "No report folder exists for the root folder with path"+$Folders[$i].ServerRelativeUrl
                        GenerateLog("FAILURE: No report folder exists for the root folder with path : " + $Folders[$i].ServerRelativeUrl  )
                    }
                    if ([string]::IsNullOrEmpty($ReportPath.Name )) {
                       # Write-Host -ForegroundColor Red " Folder: " $Folders[$i].Name "does not have a report folder :" 
           
                    }
                    # HAS THE REPORT FOLDER
                    else {
                               
                               #TRY IF UNZIP FOLDER IS PRESENT
                                Write-host -ForegroundColor Green "Report folder exists for "$Folders[$i].ServerRelativeUrl
                        $UnzipPath_temp = $ListName + "/" + $Folders[$i].Name + "/" + $ReportName + "/" + $UnzipName;
                        try {
                            $UnzipPath = Get-PnPFolder -Url $UnzipPath_temp  -ErrorAction SilentlyContinue 
                            if($UnzipPath -ne $null)
                            {
                            Write-host -ForegroundColor Red "unzip folder exists for "$Folders[$i].ServerRelativeUrl
                            GenerateLog("FAILURE: Unzip folder  exists for the root folder with path : " + $Folders[$i].ServerRelativeUrl  )
                            }
                        }
                        catch {
                            Write-host -ForegroundColor Green "No  unzip folder exists for "$Folders[$i].ServerRelativeUrl
                            GenerateLog("SUCCESS: No  unzip folder exists root folder with path : " + $Folders[$i].ServerRelativeUrl  )

                        }
                            if ([string]::IsNullOrEmpty($UnzipPath.Name )) {
                                Write-Host -ForegroundColor Green " Folder: " $Folders[$i].Name "does not have a unzip folder :" $reportfolderpath
                                
                                $reportfolder = Resolve-PnPFolder $UnzipPath_temp
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
                            }
                            else
                            {
                          #  write-host -ForegroundColor red "Unzip already exists for:" $items[$j].ServerRelativeUrl

                            }
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
       
        GenerateLog ("INFO:Creating unzip folders in the list : " + $ListName + "for the Site:" + $SiteURL)
        Update-HistoricalId $SiteURL $ListName;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for creating folder at  the root level folders for the root level folders is Completed...."

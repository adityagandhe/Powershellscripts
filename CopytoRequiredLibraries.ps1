
 
#Get the Folder from site relative URL
#Config Variables
Clear-Host
Write-host -ForegroundColor Green "Script execution for adding the required subfolders folders is in progress...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "started at" $now 
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$ReportName = "Report1"
$ReportPath
$Serverpath="/sites/ModernTeam/"
$fileref="/sites/ModernTeam/DocumentSetModern/"
$fileref_target="/sites/ModernTeam/Final_report"
$UnzipName = "unzip"
$RequestComms ="Child1"

$UnzippedFolder="*unzip*"
$UnzipPath
$Sitepath = $filepath + "\CreateFolderatrootlevel.csv"
$LogFilePath = $filepath + "\FinalFolderCopyLog" + $date + ".csv"
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
         Start-Sleep -Seconds 10
        for ($i = 0; $i -lt $Folders.Count ; $i++) {
          
            try {
             $childfolderpath =$fileref + $Folders[$i].FieldValues.FileLeafRef
               if($Folders[$i].Fieldvalues.Processed -eq "Yes" -and($Folders[$i].Fieldvalues.FileLeafRef -like "DRU*" -or $Folders[$i].Fieldvalues.FileLeafRef -like "DRI*" )-and ($Folders[$i].Fieldvalues.FileRef -eq $childfolderpath))
               {
           # Forms is the OOTB folder created inside a library
                if ($Folders[$i].Fieldvalues.FileLeafRef -eq "Forms" -or $Folders[$i].Fieldvalues.FileLeafRef -eq $null) {

                     Write-host -ForegroundColor Red "Ignoring blank folder or OOTB Forms folder or non parent level folders"
                    }
                    else
                    {
                    $Countupdate = $Countupdate +1
                     # Try to find if subfolder with name report os found
                    
                    $ReportComms_temp = $ListName + "/" + $Folders[$i].Fieldvalues.FileLeafRef + "/" + $RequestComms;

                    try {
                        $ReportCommsPath = Get-PnPFolder -Url $ReportComms_temp -ErrorAction SilentlyContinue
                    }
                    catch {
                        Write-host -ForegroundColor Red "No report comms folder exists for the root folder with path" $Folders[$i].Fieldvalues.FileRef
                    }
                    if ([string]::IsNullOrEmpty($ReportCommsPath.Name )) {
                       # Write-Host -ForegroundColor Red " Folder: " $Folders[$i].Name "does not have a report folder :" 
                        Write-host -ForegroundColor Yellow "No report comms folder exists for the root folder with path" $Folders[$i].Fieldvalues.FileRef
                        GenerateLog("INFO: No report comms folder exists for the root folder with path : " + $Folders[$i].Fieldvalues.FileRef  )
                        Set-PnPListItem -List $ListName -Identity $Folders[$i].FieldValues.ID -Values @{"CopyError" = "No Report Folder in the processed" } 
                      #  Set-PnPListItem -List $ListName -Identity $Folders[$i].Fieldvalues.ID -Values @{"CopyError" = "No unzipped folder exists in processed" }
                    }
                    # HAS THE REPORT FOLDER
                    else
                    {
                              Write-host -ForegroundColor Green "Report comms folder exists for the root folder with path" $Folders[$i].Fieldvalues.FileRef
                        GenerateLog("SUCCESS: Report comms folder exists for the root folder with path : " + $Folders[$i].Fieldvalues.FileRef  )
                          $source =$ReportComms_temp

               
          
                         # $target =$fileref_target +"/"+$Folders[$i].Fieldvalues.FileLeafRef
                         $target ="990/"+$Folders[$i].Fieldvalues.FileLeafRef
                          try
                          { 
                         # Start-Sleep -Seconds 2
                            # $job= Copy-PnPFile -SourceUrl $source -TargetUrl $target  -Overwrite -Force  -NoWait
                            $job
                            do{
                             Start-Sleep -Seconds 2
                             $job= Copy-PnPFile -SourceUrl $source -TargetUrl $target  -Overwrite -Force  -NoWait
                             Write-Host -BackgroundColor Yellow "Applying a delay for comms"
                            }
                            while($job -eq $null)
                            

                            
                              $jobStatus = Receive-PnPCopyMoveJobStatus -Job $job -Wait
    if($jobStatus.JobState -eq 0)
    {
      Write-Host -ForegroundColor Green "comms Job finished at 0"
      GenerateLog("SUCCESS: Report comms folder successfully copied from the path : " + $Folders[$i].Fieldvalues.FileRef  )
                              Write-Host -ForegroundColor Green "SUCCESS: Report comms folder successfully copied from the path : "$Folders[$i].Fieldvalues.FileRef
    }
    else
    {
     Write-Host -ForegroundColor Cyan "comms Job finished at non 0"
    }

                              }
                              catch
                              {
                             Write-Host -ForegroundColor Red "Unable to cretae requuest comms with exception : " + $_.exception.message
                              GenerateLog("FAILURE: Unable to cretae requuest comms with exception from the path : " + $Folders[$i].Fieldvalues.FileRef + $_.exception.message  )
                              }
                              
                    }
                  
                               
                               #TRY IF UNZIP FOLDER IS PRESENT
                              
                        $UnzipPath_temp = $ListName + "/" + $Folders[$i].Fieldvalues.FileLeafRef + "/" + $ReportName + "/" + $UnzipName;
                        $unzip_path_folder =$ListName + "/" + $Folders[$i].Fieldvalues.FileLeafRef + "/" + $ReportName
                        try {
                            $UnzipPath = Get-PnPFolder -Url $UnzipPath_temp  -ErrorAction SilentlyContinue 
                            if($UnzipPath -ne $null)
                            {
                            Write-host -ForegroundColor Green "Unzip folder exists for "$Folders[$i].Fieldvalues.FileRef
                            GenerateLog("SUCCESS: Unzip folder  exists for the root folder with path : " + $Folders[$i].Fieldvalues.FileRef  )
                          #  Set-PnPListItem -List $ListName -Identity $Folders[$i].Fieldvalues.ID -Values @{"Processed" = "Unzipped already exists" }
                           $source =$UnzipPath_temp
                           # $target =$fileref_target +"/"+$Folders[$i].Fieldvalues.FileLeafRef 
                           $target ="990/"+$Folders[$i].Fieldvalues.FileLeafRef
                           try
                           {
                          1# Start-Sleep -Seconds 2
                          $zipjob
                          
                           do{
                             Start-Sleep -Seconds 2
                             $zipjob=  Copy-PnPFile -SourceUrl $source -TargetUrl $target -Overwrite -Force  -NoWait
                             Write-Host -BackgroundColor Yellow "Applying a delay for zip"
                            }
                            while($zipjob -eq $null)
                         # Start-Sleep -Seconds 2

                           $jobStatus = Receive-PnPCopyMoveJobStatus -Job $zipjob -Wait
    if($jobStatus.JobState -eq 0)
    {
      Write-Host -ForegroundColor Green "UnzipJob finished 0"
      Write-Host -ForegroundColor Green "SUCCESS: Unzip folder successfully copied from the path : "$Folders[$i].Fieldvalues.FileRef
                            GenerateLog("SUCCESS: Unzip folder successfully copied from the path : " + $Folders[$i].Fieldvalues.FileRef  )
    }
    else
    {
        Write-Host -ForegroundColor Red "UnzipJob finished nonzero"
      Write-Host -ForegroundColor Green "SUCCESS: Unzip folder successfully copied from the path : "$Folders[$i].Fieldvalues.FileRef
                            GenerateLog("SUCCESS: Unzip folder successfully copied from the path : " + $Folders[$i].Fieldvalues.FileRef  )
    }
                             
                   }
                   catch
                   {
                   Write-Host -ForegroundColor Red "Unable to cretae Unzipped with exception : " + $_.exception.message
                              GenerateLog("FAILURE: Unable to cretae Unzipped with exception from the path : " + $Folders[$i].Fieldvalues.FileRef + $_.exception.message  )
                   }         }
                            else
                            {
                                  Write-host -ForegroundColor Yellow "unzip folder do not exists for "$Folders[$i].Fieldvalues.FileRef
                            GenerateLog("INFO: Unzip folder do not  exists for the root folder with path : " + $Folders[$i].Fieldvalues.FileRef  )
                            Set-PnPListItem -List $ListName -Identity $Folders[$i].FieldValues.ID -Values @{"CopyError" = "No unzipped folder exists in processed" } 
                          
                            }
                        }
                        catch {
                            Write-host -ForegroundColor Green "No  unzip folder copied for "$Folders[$i].Fieldvalues.FileRef
                            GenerateLog("FAILURE: No  unzip folder copied root folder with path : " + $Folders[$i].Fieldvalues.FileRef + $_.exception.message )

                        }
                            
                   
                 
                 Set-PnPListItem -List $ListName -Identity $Folders[$i].FieldValues.ID -Values @{"Processed" = "Migrated" }    }
                  
                  
             #     Set-PnPListItem -List $ListName -Identity $Folders[$i].FieldValues.ID -Values @{"Processed" = "Migrated" } 
                   }

                    else
                    {
                 #    Write-Host -ForegroundColor Red "Folder is already processed OR the name of the folder is not in a required format:" $Folders[$i].FieldValues.FileRef
                  #     GenerateLog("FAILURE: Folder is already processed OR the name of the folder is not in a required format : " + $Folders[$i].FieldValues.FileRef  )
                    }

                         
            }
            catch {
                GenerateLog("ERROR: Error in copying the folder:" + $Folders[$i].FieldValues.FileRef + "with exception : " + $_.exception.message)
            }
        }
        Write-Host -ForegroundColor Cyan "Total number of folders processed is "  $Countupdate
GenerateLog("INFO:Total number of folders processed is : " + $Countupdate)
    }
    catch {
        write-host "Error: $($_.Exception.Message)" -foregroundcolor Red
        GenerateLog("ERROR: Error in copying the required folders in the list: " + $ListName + "with exception : " + $_.exception.message)
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

Write-host -ForegroundColor Green " Script execution for adding the required subfolders root level folders is Completed...."
$now =Get-Date
     Write-Host -ForegroundColor Yellow "STOPPED at" $now 
       GenerateLog("INFO:Script completed at : " + $now)
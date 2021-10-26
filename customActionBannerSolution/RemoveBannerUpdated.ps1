Add-Type -Path "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.dll"
Add-Type -Path "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.Runtime.dll"

Clear-Host
Write-host -ForegroundColor Green "Script execution for Removing banners is in progress...."
#Global Variables
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$SiteInfoInputPath=$null
$LogFilePath = $filepath + "\RemoveBannerLog" + $date + ".csv"
$Credentials =$null



#Log Function
Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}

$type = Read-Host "Enter 1 for SharePoint onpremises or 2 for SharePoint online"

$userId = Read-Host -Prompt "Enter LoginName"
$password = Read-Host -Prompt "Enter Password" -AsSecureString
if ($type = 2) {
    write-host -ForegroundColor Yellow "Executing the script for SharePoint Online"
 
  $Credentials =New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($userId, $password)
    #$Credentials = New-Object -TypeName System.Management.Automation.PSCredential -argumentlist  $userId, $password
    $SiteInfoInputPath = $filepath + "\0365BannerSites.csv"
}
else {
    write-host -ForegroundColor Yellow "Executing the script for SharePoint OnPrem"

    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -argumentlist  $userId, $password
    $SiteInfoInputPath = $filepath + "\SP2013BannerSites.csv"
}

function Remove-SPBanner($SiteUrl)
{
GenerateLog("Removing banner for the site:"+ $SiteUrl.url)
try
{
  $context = New-Object Microsoft.SharePoint.Client.ClientContext($SiteUrl)
  $context.Credentials = $Credentials
  $site = $context.Web
  $context.Load($site)
  $context.ExecuteQuery()
  $UserCustomActions = $site.UserCustomActions
  $context.Load($UserCustomActions)
  $context.ExecuteQuery()

   $UserCustomActions  | Select Title, Sequence
  if($UserCustomActions.Count -gt 0)
  {
    for ($i=0;$i -lt $UserCustomActions.Count;$i++)
    {
    if($UserCustomActions[$i].Title -eq "BannerSolutionCSS")
    {
    $CA =$UserCustomActions[$i]
    $CA.DeleteObject()
    $context.ExecuteQuery()
    Write-Host “Banner CSS has been Removed…” -ForegroundColor Green
    }
     if($UserCustomActions[$i].Title -eq "BannerScriptMigrationJS")
    {
    $CA =$UserCustomActions[$i]
    $CA.DeleteObject()
    $context.ExecuteQuery()
    Write-Host “Banner JS has been Removed…” -ForegroundColor Green
    }
  }
}

}
catch
{

}

}



function Main() {
    try {
        $siteCollections = Import-Csv $SiteInfoInputPath
    }
    catch {
        GenerateLog ("Make sure that Input File is added at the desired location");



    }
    $siteCollections | ForEach-Object {
        $url = $_."URL";
        $sitecollections = $url.TrimEnd('/');
        $sitecollections = $url.Trim();
       
        GenerateLog ("Applying banner for the Site:" + $sitecollections)
        Remove-SPBanner $sitecollections;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for applying banner is Completed...."

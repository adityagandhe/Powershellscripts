Add-Type -Path "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.dll"
Add-Type -Path "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.Runtime.dll"

Clear-Host
Write-host -ForegroundColor Green "Script execution for Adding banners is in progress...."
#Global Variables
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$SiteInfoInputPath=$null
$LogFilePath = $filepath + "\BannerLog" + $date + ".csv"
$Credentials =$null

$ScriptUrl="https://yavatmal3.sharepoint.com/sites/RND/SiteAssets/JS/BannerScript.js"
$CSSStylesheet="https://yavatmal3.sharepoint.com/sites/RND/SiteAssets/CSS/BannerScript.css"

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

function Add-SPBanner($SiteUrl)
{
GenerateLog("Applying banner for the site:"+ $site.url)
try{
  $context = New-Object Microsoft.SharePoint.Client.ClientContext($SiteUrl)
  $context.Credentials = $Credentials
  $site = $context.Web
  $context.Load($site)
  $context.ExecuteQuery()
  $UserCustomActions = $site.UserCustomActions
  $context.Load($UserCustomActions)
  $context.ExecuteQuery()

   #add custom js injection action
   $CSSURL=$CSSStylesheet;
  $customJSAction = $UserCustomActions.Add()
  $customJSAction.Location = “ScriptLink”
 
 #Add new code

 $customJSAction.ScriptBlock ="var head = document.querySelector('head');
                        var styleTag = document.createElement('style'); 
                        var linkTag = document.createElement('link');
                        linkTag.rel = 'stylesheet'; 
                        linkTag.href = '$($CSSURL)'; 
                        linkTag.type = 'text/css'; 
                        head.appendChild(styleTag);
                        head.appendChild(linkTag);"


  #load it last
  $customJSAction.Title= “BannerSolutionCSS"
  $customJSAction.Sequence = 1000
  #make the changes
  $customJSAction.Update()
  $context.ExecuteQuery()


  #add custom js injection action
  $customJSAction = $UserCustomActions.Add()
  $customJSAction.Location = “ScriptLink”
  #reference to JS file
  $customJSAction.ScriptSrc = $ScriptUrl
  #load it last
  $customJSAction.Title= “BannerScriptMigrationJS"
  $customJSAction.Sequence = 1001
  #make the changes
  $customJSAction.Update()
  $context.ExecuteQuery()


  

  Write-Host “Banner has been Added…” -ForegroundColor Green
  }
  catch
  {
  GenerateLog("Error in applying banner for the Site:" + $site.url + "with exception : " + $_.exception.message)
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
        Add-SPBanner $sitecollections;
    }


}


Main

Write-host -ForegroundColor Green "Script execution for applying banner is Completed...."
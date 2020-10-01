Add-Type -Path "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.dll"
Add-Type -Path "C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.Runtime.dll"
function Add-SPBanner($SiteUrl, $Credentials) 
{ 
  $context = New-Object Microsoft.SharePoint.Client.ClientContext($SiteUrl) 
  $context.Credentials = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($Credentials.UserName,$Credentials.Password) 
  $site = $context.Web 
  $context.Load($site) 
  $context.ExecuteQuery() 
  $UserCustomActions = $site.UserCustomActions 
  $context.Load($UserCustomActions) 
  $context.ExecuteQuery() 
  
  #add custom js injection action 
  $customJSAction = $UserCustomActions.Add() 
  $customJSAction.Location = “ScriptLink” 
  #reference to JS file 
  $customJSAction.ScriptSrc = “https://yavatmal3.sharepoint.com/sites/team/SiteAssets/alert.js” 
  #load it last 
  $customJSAction.Title= “alert" 
  $customJSAction.Sequence = 1000
  #make the changes 
  $customJSAction.Update() 
  $context.ExecuteQuery() 


   #add custom js injection action 
   $CSSURL="https://yavatmal3.sharepoint.com/sites/team/SiteAssets/Divcss.css";
  $customJSAction = $UserCustomActions.Add() 
  $customJSAction.Location = “ScriptLink” 
  #reference to JS file 
  $customJSAction.ScriptBlock = "document.write('<link rel=""stylesheet"" After=""Corev15.css"" href=""$($CSSURL)"" type=""text/css""/>')"
  #load it last 
  $customJSAction.Title= “css for Banner" 
  $customJSAction.Sequence = 1000
  #make the changes 
  $customJSAction.Update() 
  $context.ExecuteQuery()
   
  Write-Host “Banner has been Added…” -ForegroundColor Green 
} 
function Remove-SPBanner($SiteUrl, $Credentials) 
{   
  $context = New-Object Microsoft.SharePoint.Client.ClientContext($SiteUrl) 
  $context.Credentials = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($Credentials.UserName,$Credentials.Password) 
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
    $CA =$UserCustomActions[$i]
    $CA.DeleteObject() 
    $context.ExecuteQuery() 
    Write-Host “Banner has been Removed…” -ForegroundColor Green 
  }   
} 
}
$Creds = Get-Credential 
$SiteUrl = “https://yavatmal3.sharepoint.com/sites/CustomAction” 
Add-SPBanner -SiteUrl $SiteUrl -Credentials $Creds 
#Remove-SPBanner -SiteUrl $SiteUrl -Credentials $Creds
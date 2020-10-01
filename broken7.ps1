
 
#Connect to SharePoint Online site
Connect-PnPOnline -Url "https://yavatmal5.sharepoint.com/sites/TestModern" -UseWebLogin
#$Page =  Get-PnPClientSidePage -Identity "SPFXdEPLOYMENTtEST.aspx"
 $AllPages = Get-PnPListItem -List 'SitePages'
 foreach ($Page in $AllPages) {
 $PageRelativeURL = $Page["FileRef"]
 $ClientContext = Get-PnPContext
$CurrentPage = Get-PnPFile -Url $PageRelativeURL -AsListItem
$PageFile = $CurrentPage.File
$ClientContext.Load($PageFile)
$ClientContext.ExecuteQuery()
$Webpart =Get-PnPClientSideComponent -Page "SPFXdEPLOYMENTtEST.aspx"
}
#Get webparts from modern page
$WebParts = $Page.Controls
ForEach($Webpart in $Webparts)
{ Get-PnPProperty -Property 
    Write-Host "WebPart Id:" $webpart.InstanceId 
    Write-Host "Title:" $webpart.Title
    Write-Host $webpart.WebPartData.Length
    Write-Host $webpart.JsonWebPartData
}


#Read more: https://www.sharepointdiary.com/2019/08/sharepoint-online-web-part-usage-report-using-powershell.html#ixzz6YazBc1tV
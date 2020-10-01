

# Here we can pass multiple string values which need to replace



#region [ Site Credentials ]
# ————————- #

$UserName = Read-Host -Prompt “Please enter user Email”
$PassWord = Read-Host -Prompt “Please enter user PassWord”

$Pwd = ConvertTo-SecureString $PassWord -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential($UserName,$Pwd)

#————————— #

#endregion

#region [ Configuration Values ]

#————————— #

$SiteURL= Read-Host -Prompt “Please enter site ( newly created site collection ) URL:”

$BroeknlinksReplacePageLogPath = Read-Host -Prompt “Please enter broken links web part page to store logs EX: C:\log.txt”
$OldValue ='https://www.google.com'

#$ConteneEditorType= ‘<TypeName>Microsoft.SharePoint.WebPartPages.ContentEditorWebPart</TypeName>’
#$SummaryLinksType = ‘name=”Microsoft.SharePoint.Publishing.WebControls.SummaryLinkWebPart’
#$ScriptEditorType='<type name=”Microsoft.SharePoint.WebPartPages.ScriptEditorWebPart’

#————————— #

#endregion

Write-Host “——— Started broken links replacement process ———- ” -ForegroundColor Green
Function ReplaceBrokenLinks($SubSiteURL) {

Connect-PnPOnline -Url $SubSiteURL -Credentials $Creds

Write-Host “Started replacing broken links on the site ” $SubSiteURL -ForegroundColor Magenta

$AllPages = Get-PnPListItem -List 'SitePages'#Need to change the list name if we want get items from differen list

$TotalPages = 0

foreach ($Page in $AllPages) {

$TotalPages++

# if($Page[“FileLeafRef”] -eq ‘default.aspx’){

Write-Host “Processing page no:” $TotalPages ” — Out of total pages” $AllPages.Count ” — Page title:” $Page[“FileLeafRef”] -ForegroundColor Cyan

Write-Host “================================================================” -ForegroundColor Cyan

# Write-Host “Started replacing broken links on the Page :” $Page[“FileLeafRef”] -ForegroundColor Green

$PageRelativeURL = $Page[“FileRef”]

#region [ Check page checkout status ]

$ClientContext = Get-PnPContext
$CurrentPage = Get-PnPFile -Url $PageRelativeURL -AsListItem
$PageFile = $CurrentPage.File
$ClientContext.Load($PageFile)
$ClientContext.ExecuteQuery()



#endregion
$AllWebParts = Get-PnPClientSidePage -Identity "SPFXdEPLOYMENTtEST.aspx"
#$AllWebParts = Get-PnPWebPart 
foreach ( $control in $AllWebParts.Controls) {

$GetWebpartsCount = 0

$WebPartTitle = $control.Title
#[int]$ZoneIndex = $WebPart.WebPart.ZoneIndex
#$ZoneID = $WebPart.ZoneId

$WebpartXML = Get-PnPWebPartXml -ServerRelativePageUrl "/sites/TestModern/SitePages/SPFXdEPLOYMENTtEST.aspx" -Identity $WebPartTitle

if($WebpartXML.IndexOf($OldUrlValue) -gt -1) {

$GetWebpartsCount++

# Write-Host “Old URL value existed on the web part” $WebPartTitle -ForegroundColor Green

}


#region [ Exporting the broken links fixed pages info to text file ]

if( $GetWebpartsCount -gt 0) {

‘Old URL existed on the page : ‘ + $PageRelativeURL + ” on web part ” + $WebPartTitle | Out-File $BroeknlinksReplacePageLogPath -Append

} else {

# ‘Broken links web parts not updated on the page : ‘ + $PageRelativeURL | Out-File $BroeknlinksReplacePageLogPath -Append
}

#endregion

}

# }

}
}

ReplaceBrokenLinks $SiteURL

Write-Host “——— Completed the broken links replacement process ———–” -ForegroundColor Green
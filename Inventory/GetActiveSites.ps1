<#
.SYNOPSIS
   SITE INFORMATION
.DESCRIPTION
  Script reads the input based on the selection of the option for Omprem or Online and then generate the SSRS information for all the sites
.EXAMPLE

.INPUTS
    0365Sites.csv OR ONPremSites.csv
.OUTPUTS
    In Log Folder
    In Report Folder
.NOTES
    General notes
#>
Clear-Host
Write-host -ForegroundColor Green "Script execution for fetching Last Item Modified date of list item is in progress...."
#Global Variables
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss

$LogFilePath = $filepath + "\Logs\ListItemModifiedDate" + $date + ".csv"
$ReportPath = $filepath + "\Report\ListItemModifiedDate" + $date + ".csv"
$SiteInfoInputPath = $null;
$Credentials = $null;
$Site = $null;
$BatchSize = 1
#Log Function
Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}

#Property Load Function
Function Invoke-LoadMethod() {
    param(
        [Microsoft.SharePoint.Client.ClientObject]$Object = $(throw "Please provide a Client Object"),
        [string]$PropertyName
    )
    $ctx = $Object.Context
    $load = [Microsoft.SharePoint.Client.ClientContext].GetMethod("Load")
    $type = $Object.GetType()
    $clientLoad = $load.MakeGenericMethod($type)


    $Parameter = [System.Linq.Expressions.Expression]::Parameter(($type), $type.Name)
    $Expression = [System.Linq.Expressions.Expression]::Lambda(
        [System.Linq.Expressions.Expression]::Convert(
            [System.Linq.Expressions.Expression]::PropertyOrField($Parameter, $PropertyName),
            [System.Object]
        ),
        $($Parameter)
    )
    $ExpressionArray = [System.Array]::CreateInstance($Expression.GetType(), 1)
    $ExpressionArray.SetValue($Expression, 0)
    $clientLoad.Invoke($ctx, @($Object, $ExpressionArray))
}
$type = Read-Host "Enter 1 for SharePoint onpremises or 2 for SharePoint online"
$userId = Read-Host -Prompt "Enter LoginName"
$password = Read-Host -Prompt "Enter Password" -AsSecureString
if ($type = 2) {
    write-host -ForegroundColor Yellow "Executing the script for SharePoint Online"
   Add-Type -Path ($filepath + "\Binaries\Online\Microsoft.SharePoint.Client.dll")
    Add-Type -Path ($filepath + "\Binaries\Online\Microsoft.SharePoint.Client.Runtime.dll")
    $Credentials = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($userId, $password)
    $SiteInfoInputPath = $filepath + "\0365Sites.csv"
}
else {
    write-host -ForegroundColor Yellow "Executing the script for SharePoint OnPrem"
      Add-Type -Path ($filepath + "\Binaries\Onprem\Microsoft.SharePoint.Client.dll")
    Add-Type -Path ($filepath + "\Binaries\Onprem\Microsoft.SharePoint.Client.Runtime.dll")
    $Credentials = New-Object System.Net.NetworkCredential($userId, $password)
    $SiteInfoInputPath = $filepath + "\SP2013.csv"
}
function GetSiteDetails ($web, $ctx) {
    try {
        Write-Host -ForegroundColor Yellow ("Starting Item modified report for:" + $web.url)
        $Webs = $web.Webs;
        $ctx.Load($Webs);

        $ctx.Load($ctx.Site);
        $lists = $web.lists
        $ctx.load($lists)
        $ctx.ExecuteQuery();
        #Define Query to get List Items in batch
        $Query = New-Object Microsoft.SharePoint.Client.CamlQuery
        $Query.ViewXml = @"
<View Scope='RecursiveAll'>
   <Query>
   <OrderBy>
      <FieldRef Name='Modified' Ascending='False' />
   </OrderBy>
</Query>
    <RowLimit Paged="TRUE">1</RowLimit>
</View>
"@
        $JSData = @();



        foreach ($list in $lists) {
            if ($list.Hidden -eq $false ) {
                GenerateLog("Starting generation List item modified for the site:" + $web.url + "with the list:" + $list.Title)
                
                    $ListItems = $list.GetItems($Query)
                    $Ctx.Load($ListItems)
                    $Ctx.ExecuteQuery()

                    if ($listItems.Count -gt 0) {
                         $JSData = @();
                        foreach ($listItem in $listItems) {
                            Write-Host -ForegroundColor Cyan "Processing for the list:"+ $list.Title
                            $jsObject = New-Object System.Object
                            $jsObject | Add-Member -MemberType NoteProperty -Name "Site Id" -Value $Site.Id
                            $jsObject | Add-Member -MemberType NoteProperty -Name "Site Url" -Value $Site.Url
                            $jsObject | Add-Member -MemberType NoteProperty -Name "Web Title" -Value $web.Title
                            $jsObject | Add-Member -MemberType NoteProperty -Name "Web Id" -Value $web.Id
                            $jsObject | Add-Member -MemberType NoteProperty -Name "Web Url" -Value $web.Url
                            $jsObject | Add-Member -MemberType NoteProperty -Name "ListTitle" -Value $list.Title
                             $jsObject | Add-Member -MemberType NoteProperty -Name "ListItemCount" -Value $list.ItemCount
                            $jsObject | Add-Member -MemberType NoteProperty -Name "LastItemModified" -Value $listItem["Modified"]

                            $JSData += $jsObject

                        }
                        if ( $JSData -ne $null) {
                            $JSData  | Export-Csv -Path $ReportPath -NoTypeInformation -Append
                        }
                    }

                
              

            }
        }

        Foreach ($sWebs in $Webs) {
            GetSiteDetails $sWebs $ctx
            $ctx.Dispose()

        }
    }

    catch {
        GenerateLog("Error in generating the listItemModified for the Site:" + $web.url + "with exception : " + $_.exception.message)


    }






}


function GetMainWeb($SiteURL) {
    try {
        $Ctx = New-Object Microsoft.SharePoint.Client.ClientContext($SiteURL)
        $Ctx.Credentials = $Credentials
        #Get the web
        $Web = $Ctx.Web
        $Ctx.Load($Web)
        $site = $Ctx.Site
        $Ctx.Load($site)

        $Ctx.Load($Web.Webs)
        $Ctx.ExecuteQuery()


        GetSiteDetails $Web $Ctx
    }
    catch {

        GenerateLog("Error in fetching the information for Site:" + $SiteURL + "with exception :" + $_.exception.message)

    }
    finally {
        $Ctx.Dispose();

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
        GenerateLog ("Fetching the Sandbox for the Site:" + $sitecollections)
        GetMainWeb $sitecollections;
    }


}



Main

Write-host -ForegroundColor Green "Script execution for fetching Last Item Modified date of list item in Completed...."

Clear-Host
Write-host -ForegroundColor Green "Script execution for fetching owners is in progress...."
#Global Variables
$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss

$LogFilePath = $filepath + "\OwnersInfoLog" + $date + ".csv"
$ReportPath = $filepath + "\OwnersInfoReport" + $date + ".csv"
$SiteInfoInputPath = $null;
$Credentials = $null;
$Site = $null;
$currentSite =$null;
#Log Function
Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}

#Property Load Function

$type = Read-Host "Enter 1 for SharePoint onpremises or 2 for SharePoint online"

$userId = Read-Host -Prompt "Enter LoginName"
$password = Read-Host -Prompt "Enter Password" -AsSecureString
if ($type = 2) {
    write-host -ForegroundColor Yellow "Executing the script for SharePoint Online"
 

    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -argumentlist  $userId, $password
    $SiteInfoInputPath = $filepath + "\0365Sites.csv"
}
else {
    write-host -ForegroundColor Yellow "Executing the script for SharePoint OnPrem"

    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -argumentlist  $userId, $password
    $SiteInfoInputPath = $filepath + "\SP2013.csv"
}

function GetOwners ($site) {
    try {
        $Owners = @();
        Write-Host -ForegroundColor Yellow ("Starting owner generation report for:" + $site.url)
         GenerateLog ("Fetching the  owners for the Site:" + $site.url)
        $OwnerGroup= Get-PnPGroup -AssociatedOwnerGroup
        $OwnerGroupMembers = Get-PnPGroupMembers -Identity $OwnerGroup
        Write-Host -ForegroundColor DarkCyan "Count of Owners:"+ $OwnerGroupMembers.Count
        foreach ($user in $SCAUsers) {
            $userData = New-Object PSObject
       $userData | Add-Member -MemberType NoteProperty -Name "Site Url" -Value $currentSite
            $userData | Add-Member -MemberType NoteProperty -Name "Web Url" -Value $site.Url
            $userData | Add-Member -MemberType NoteProperty -Name "User Title" -Value $user.Title
            $userData | Add-Member -MemberType NoteProperty -Name "User Email" -Value $user.Email
            $userData | Add-Member -MemberType NoteProperty -Name "LoginName" -Value $user.LoginName
            $userData | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $OwnerGroup.Title
            $Owners += $userData
        }
        if ($Owners -ne $null) {

            $Owners  | Export-Csv -Path $ReportPath -NoTypeInformation -Append

        }
    }
    catch {
        GenerateLog("Error in generating the owners details for the Site:" + $site.url + "with exception : " + $_.exception.message)
    }
  
}


function GetSCAUsers ($site) {
    try {
        $UserCollection = @();
        Write-Host -ForegroundColor Yellow ("Starting owner generation report for:" + $site.url)
        GenerateLog ("Fetching the SCA owners for the Site:" + $site.url)
        $sourceweb = Get-PnPWeb -Identity $site
        $SCAUsers= Get-PnPSiteCollectionAdmin 
        Write-Host -ForegroundColor DarkCyan "Count of Owners:"+ $SCAUsers.Count
        foreach ($user in $SCAUsers) {
            $userData = New-Object PSObject
      
            $userData | Add-Member -MemberType NoteProperty -Name "Site Url" -Value $currentSite
            $userData | Add-Member -MemberType NoteProperty -Name "Web Url" -Value $site.Url
            $userData | Add-Member -MemberType NoteProperty -Name "User Title" -Value $user.Title
            $userData | Add-Member -MemberType NoteProperty -Name "User Email" -Value $user.Email
            $userData | Add-Member -MemberType NoteProperty -Name "LoginName" -Value $user.LoginName
            $userData | Add-Member -MemberType NoteProperty -Name "GroupName" -Value "SCA"
            $UserCollection += $userData
        }
        if ($UserCollection -ne $null) {

            $UserCollection  | Export-Csv -Path $ReportPath -NoTypeInformation -Append

        }
    }
    catch {
        GenerateLog("Error in generating the owner details for the Site:" + $site.url + "with exception : " + $_.exception.message)
    }
    GetOwners $sourceweb

    $AllWebs = Get-PnPSubWebs -Recurse

    foreach($subweb in $AllWebs)
    {
     GetOwners $subweb
    }
  
}


function GetMainWeb($SiteURL) {
    try {

        $SourceConnection = Connect-PnPOnline -url $SiteURL -Credentials $Credentials -ReturnConnection
        $sourceweb = Get-PnPWeb
        GetSCAUsers $sourceweb

        Disconnect-PnPOnline -Connection $SourceConnection
    }
    catch {

        GenerateLog("Error in fetching the information for Site:" + $SiteURL + "with exception :" + $_.exception.message)

    }
    finally {
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
        $currentSite=$sitecollections
        GenerateLog ("Fetching the owners for the Site:" + $sitecollections)
        GetMainWeb $sitecollections;
    }


}



Main

Write-host -ForegroundColor Green "Script execution for fetching owners is in Completed...."
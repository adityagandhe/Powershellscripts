#Install-Module -Name MicrosoftTeams -AllowClobber

<#
.SYNOPSIS
    Script for creating teams in bulk
.DESCRIPTION
    Script would create a new MS team based on the input file .
.EXAMPLE

.INPUTS
 teamsInput.csv
 
.OUTPUTS
  Log file would be generated
.NOTES
    Module related to MS teams is installed
    Install-Module -Name MicrosoftTeams -AllowClobber
#>

Write-host -ForegroundColor Green "Script execution for creating MS Teams is in progress...."
#Define the path

$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$LogFilePath = $filepath + "\MSTeamsBulkScriptLog" + $date + ".csv"

$teamsInputpath = $filepath + "\teamsInput.csv"

#Declare Function for Logging

Function GenerateLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $LogFilePath $text

}
#Connect to the MS teams and provide the credentials
try {
    Connect-MicrosoftTeams
    GenerateLog ("Connected to the MS Teams ")
}
catch {
    GenerateLog ("Error in  connection to the MS Teams ")
}
#$TeamDetails = Get-Content -Path "";
$teamsInput = Import-Csv $teamsInputpath
$teamsInput | ForEach-Object {
    $teamName = $_."Name";
    $displayName = $_."DispalyName";
    $visibility = $_."Visibility";


try {
    if ($teamName -ne $null -or $displayName -ne $null -or $visibility -ne $null )
    {
        $group = New-Team -MailNickname $teamName -displayname  $displayName -Visibility $visibility
        GenerateLog ("Creating the MS team with the title "+$teamName)
        GenerateLog ("Creating the MS team with the Id "+$group.GroupId)
        Write-Host -BackgroundColor Green "Created new MS team with the name:"$teamName;
        Write-host -BackgroundColor Green "GroupId for the newly created team is:"$group.GroupId
    }
    else {
        GenerateLog ("Please provide the required Information for team creation ")
    }
}

catch {
    GenerateLog ("Error in creating the MS team with the title ")
}
}



Write-host -ForegroundColor Green "Script execution for creating MS Teams is completed...."
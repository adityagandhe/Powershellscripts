#Install-Module -Name MicrosoftTeams -AllowClobber

<#
.SYNOPSIS
    Script for creating Team, adding channels and adding members
.DESCRIPTION
    Script would create a new MS team based on the input file .Once the team is created, Owners and Members would be added based on the input file related to MS Team permission.There would be a third input file which would have list of all the channels
.EXAMPLE

.INPUTS
 TeamDescription.csv
 TeamUsers.csv
 TeamChannels.csv
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
$LogFilePath = $filepath + "\MSTeamsScriptLog" + $date + ".csv"

$teamsInputpath = $filepath + "\teamsInput.csv"
$userInputpath = $filepath + "\userInput.csv"
$channelInputpath = $filepath + "\channelInput.csv"
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
        Write-Host -BackgroundColor Green "Created new MS team with the name:"$teamName;
    }
    else {
        GenerateLog ("Please provide the required Information for team creation ")
    }
}

catch {
    GenerateLog ("Error in creating the MS team with the title ")
}
}
try {
    $userInput = Import-Csv $userInputpath
    $userInput | ForEach-Object {
        $userEmail = $_."Email";
        $role = $_."Role";
        if ($userEmail -ne $null -or $role -ne $null  )
        {
            Add-TeamUser -GroupId $group.GroupId -User $userEmail -Role $role


            GenerateLog ("Adding member:" + $userEmail + "with the role:" + $role + " to the MS team with the title" + $teamName)
        }else { GenerateLog ("Please provide the required Information for team's user addition ") }
    }
}
catch {
    GenerateLog ("Error in adding member:" + $userEmail + "with the role:" + $role + " to the MS team with the title" + $teamName)
}

try {
    $channelInput = Import-Csv $channelInputpath
    $channelInput | ForEach-Object {

        $channelName = $_."ChannelName";
        if ($channelName -ne $null   )
        {
            New-TeamChannel -GroupId $group.GroupId -DisplayName $channelName
            GenerateLog ("Adding channel:" + $channelName + "to the MS team with the title:" + $teamName)
        }
        else {
            GenerateLog ("Please provide the required Information for team's channel creation ")
        }
    }
}
catch {
    GenerateLog ("Error in  channel:" + $channelName + "to the MS team with the title:" + $teamName)
}


Write-host -ForegroundColor Green "Script execution for creating MS Teams is completed...."
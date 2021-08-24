#Install-Module -Name MicrosoftTeams -AllowClobber

<#
.SYNOPSIS
    Script for adding channels in bulk
.DESCRIPTION
  Input file which would have list of all the channels along with the Team id would be used for creating the Channels in bulk.
.EXAMPLE

.INPUTS

 TeamChannels.csv
.OUTPUTS
  Log file would be generated
.NOTES
    Module related to MS teams is installed
    Install-Module -Name MicrosoftTeams -AllowClobber
#>

Write-host -ForegroundColor Green "Script execution for creating  channels in Teams is in progress...."
#Define the path

$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$LogFilePath = $filepath + "\MSTeamsChannelScriptLog" + $date + ".csv"

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


try {
    $channelInput = Import-Csv $channelInputpath
    $channelInput | ForEach-Object {

        $channelName = $_."ChannelName";
        $teamId=$_."TeamId";
        if ($channelName -ne $null -or $teamId -ne $null )
        {
            New-TeamChannel -GroupId $teamId -DisplayName $channelName
            GenerateLog ("Added channel:" + $channelName + "to the MS team with the Id:" + $teamId)
        }
        else {
            GenerateLog ("Please provide the required Information for team's channel creation ")
        }
    }
}
catch {
    GenerateLog ("Error in  channel:" + $channelName + "to the MS team with the Id:" + $teamId)
}


Write-host -ForegroundColor Green "Script execution for creating Channels in Teams is completed...."
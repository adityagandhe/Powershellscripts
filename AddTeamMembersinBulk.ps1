#Install-Module -Name MicrosoftTeams -AllowClobber

<#
.SYNOPSIS
    Script for adding members and Owners
.DESCRIPTION
    Script would add Owners and Members would be added based on the input file related to MS Team permission.
.EXAMPLE

.INPUTS
 
 TeamUsers.csv
 
.OUTPUTS
  Log file would be generated
.NOTES
    Module related to MS teams is installed
    Install-Module -Name MicrosoftTeams -AllowClobber
#>

Write-host -ForegroundColor Green "Script execution for adding Members/Owners MS Teams is in progress...."
#Define the path

$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$LogFilePath = $filepath + "\MSTeamsUsersScriptLog" + $date + ".csv"


$userInputpath = $filepath + "\userInput.csv"

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
    $userInput = Import-Csv $userInputpath
    $userInput | ForEach-Object {
        $userEmail = $_."Email";
        $role = $_."Role";
        $teamId=$_."TeamId";
        if ($userEmail -ne $null -or $role -ne $null -or $teamId -ne $null )
        {
            Add-TeamUser -GroupId $teamId -User $userEmail -Role $role


            GenerateLog ("Added member:" + $userEmail + "with the role:" + $role + " to the MS team with the Id" + $teamId)
        }else { GenerateLog ("Please provide the required Information for team's user addition ") }
    }
}
catch {
    GenerateLog ("Error in adding member:" + $userEmail + "with the role:" + $role + " to the MS team with the title" + $teamName)
}




Write-host -ForegroundColor Green "Script execution for adding Members/Owners in MS Teams is completed...."
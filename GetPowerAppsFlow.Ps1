<#
.SYNOPSIS
    Script for getting the details of PowerApps and Flows use in the Tenant
.DESCRIPTION
    Script is used to generate the report related to the Flow and PowerApps
    In case the Login user is Admin for a particular environment then only the flows anf PowerApps for that particular envrionment would be fetched
    In case the user is Global Admin for all the Environments then all the PowerApps and Flows from all the Environments would be fetched
.EXAMPLE
    Execute the script in PowerShell ISE
.INPUTS
    Make sure that updated dlls are used
    Only the user login would be required
.OUTPUTS
    Output files would be generated at the script location.Following are the files:
    GetFlowReport<Date>.csv
    GetFlowLog<Date>.csv
    GetPowerAppsReport<Date>.csv
    GetPowerAppsLog<Date>.csv
.NOTES
    The script is tested only on the dev environment,Verify and review the script before running on prod environment
    Currently the PowerShell support for the PowerApps and Flow is in Preview mode
    All the commands and dlls are reffered from https://docs.microsoft.com/en-us/power-platform/admin/powerapps-powershell
#>
Write-host -ForegroundColor Green "Script execution for the PowerApps is in progress...."
#Define the path

$filepath = Split-Path $MyInvocation.MyCommand.Path
$date = Get-Date -Format yyyyMMddHHmmss
$PowerAppsLogFilePath = $filepath + "\GetPowerAppsLog" + $date + ".csv"
$PowerAppsReportPath = $filepath + "\GetPowerAppsReport" + $date + ".csv"

$FlowLogFilePath = $filepath + "\GetFlowLog" + $date + ".csv"
$FlowReportPath = $filepath + "\GetFlowReport" + $date + ".csv"
#Load Modules

Import-Module  ($filepath + "\Microsoft.PowerApps.Administration.PowerShell") -Force
Import-Module ($filepath + "\Microsoft.PowerApps.PowerShell") -Force

#Declare Function for Logging

Function GeneratePowerAppsLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $PowerAppsLogFilePath $text

}

Function GenerateFlowLog($msg) {

    $text = "{0,-30} {1}" -f $date, $msg
    Add-Content $FlowLogFilePath $text

}

#variables
$PowerApps = @()
$FlowsInfo = @()
#Add-PowerAppsAccount
try {
    $Apps = Get-AdminPowerApp
    GeneratePowerAppsLog ("Connected to the PowerApps AdminCenter")
}
catch {
    GeneratePowerAppsLog ("ERROR:Connection to the PowerApps AdminCenter" + $_.exception.message)
}
foreach ($app in $apps) {
    try {
        GeneratePowerAppsLog (" fetching the PowerAppsData for" + $app.Internal.properties.displayName)
        $AppInfo = New-Object System.Object

        $connectionList = ""
        $OnPremConnection = ""
        foreach ($conRef in $app.Internal.properties.connectionReferences) {
            foreach ($connection in $conRef) {
                foreach ($connId in ($connection | Get-Member -MemberType NoteProperty).Name) {
                    $connDetails = $($connection.$connId)

                    $connDisplayName = $connDetails.displayName -replace '[,]'
                    $isOnPremiseConnection = $connDetails.isOnPremiseConnection
                    $connId = $connDetails.id

                    $OnPremiseConnection = $isOnPremiseConnection
                    $connectionList += $connDisplayName + "; "
                }
            }
        }
        $AppInfo | Add-Member -MemberType NoteProperty -Name "DisplayName"  -value $app.Internal.properties.displayName
        $AppInfo | Add-Member -MemberType NoteProperty -Name "CreatedBy"  -value $app.Internal.properties.createdBy.displayName
        $AppInfo | Add-Member -MemberType NoteProperty -Name "Created"  -value $app.Internal.properties.createdTime
        $AppInfo | Add-Member -MemberType NoteProperty -Name "Modified By" -value $app.Internal.properties.lastModifiedBy.displayName
        $AppInfo | Add-Member -MemberType NoteProperty -Name "Modified" -value $app.Internal.properties.lastModifiedTime
        $AppInfo | Add-Member -MemberType NoteProperty -Name "OwnerName" -value $app.Internal.properties.owner.displayName
        $AppInfo | Add-Member -MemberType NoteProperty -Name "UsesPremiumAPI" -value $app.Internal.properties.usesPremiumApi
        $AppInfo | Add-Member -MemberType NoteProperty -Name  "UsesCustomApi"-value $app.Internal.properties.usesCustomApi
        $AppInfo | Add-Member -MemberType NoteProperty -Name  "ConnectionsUsed"-value $connectionList
        $AppInfo | Add-Member -MemberType NoteProperty -Name  "OnPremConnectionsUsed"-value $OnPremiseConnection
        $PowerApps += $AppInfo
    }
    catch {
        GeneratePowerAppsLog ("ERROR:for fetching the PowerAppsData for" + $app.Internal.properties.displayName + $_.exception.message)
    }

}
$PowerApps | Export-Csv $PowerAppsReportPath -NoTypeInformation -Append
Write-host -ForegroundColor Green "Script execution for the PowerApps is completed...."
Write-host -ForegroundColor Green "Script execution for the Flows is in progress...."

try {
    $flows = Get-AdminFlow
    GenerateFlowLog ("Connected to the PowerApps AdminCenter")
}
catch {
    GenerateFlowLog ("ERROR:Connection  to the Flow AdminCenter" + $_.exception.message)
}
foreach ($flow in $flows) {

    try {
        $flowInfo = New-Object System.Object
        GenerateFlowLog ("Fetching information for " + $flow.DisplayName)

        $OwnerObjectId = $flow.createdBy.objectid


        $CreatedTime = $flow.CreatedTime
        $LastModifiedTime = $flow.LastModifiedTime

        $userOrGroupObject = Get-UsersOrGroupsFromGraph -ObjectId $OwnerObjectId
        $OwnerUserPrincipalName = $userOrGroupObject.Mail

        $flowInfo | Add-Member -MemberType NoteProperty -Name "DisplayName"   -Value $flow.DisplayName
        $flowInfo | Add-Member -MemberType NoteProperty -Name "Enabled?"   -Value $flow.Enabled

        $flowInfo | Add-Member -MemberType NoteProperty -Name "Created"  -Value $flow.CreatedTime
        $flowInfo | Add-Member -MemberType NoteProperty -Name "CreatedBy"  -Value $OwnerUserPrincipalName
        $flowInfo | Add-Member -MemberType NoteProperty -Name "LastModifiedTime"-Value $flow.LastModifiedTime
        $connectionList = ""
        $flowDetails = $flow | Get-AdminFlow

        $connectionList = ""

        foreach ($conRef in $flowDetails.Internal.properties.connectionReferences) {
            foreach ($connection in $conRef) {
                foreach ($connId in ($connection | Get-Member -MemberType NoteProperty).Name) {
                    $connDetails = $($connection.$connId)

                    $connDisplayName = $connDetails.displayName -replace '[,]'


                    $connectionList += $connDisplayName + "; "
                }
            }
        }

        $flowInfo | Add-Member -MemberType NoteProperty -Name "Connections"  -Value $connectionList


        $FlowsInfo += $flowInfo
    }
    catch {
        GenerateFlowLog ("ERROR:for fetching the flow for" + $flow.DisplayName + $_.exception.message)
    }
}
$FlowsInfo | Export-Csv $FlowReportPath -NoTypeInformation -Append
Write-host -ForegroundColor Green "Script excetion for the  Flow is completed"
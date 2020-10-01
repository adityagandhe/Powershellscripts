
Write-host -ForegroundColor Green "Script execution for the PowerApps is in progress...."
#Define the path

$filepath =Split-Path $MyInvocation.MyCommand.Path
$date =Get-Date -Format yyyyMMddHHmmss
$PowerAppsLogFilePath=$filepath +"\GetPowerAppsLog"+$date+".csv"
$PowerAppsReportPath =$filepath +"\GetPowerAppsReport"+$date+".csv"

$FlowLogFilePath=$filepath +"\GetFlowLog"+$date+".csv"
$FlowReportPath =$filepath +"\GetFlowReport"+$date+".csv"
#Load Modules

Import-Module  ($filepath +"\Microsoft.PowerApps.Administration.PowerShell") -Force
Import-Module ($filepath + "\Microsoft.PowerApps.PowerShell") -Force

#Declare Function for Logging

Function GeneratePowerAppsLog($msg)
{

$text="{0,-30} {1}" -f $date,$msg
Add-Content $PowerAppsLogFilePath $text

}

Function GenerateFlowLog($msg)
{

$text="{0,-30} {1}" -f $date,$msg
Add-Content $FlowLogFilePath $text

}

#variables
$PowerApps =@()
$Flows =@()
#Add-PowerAppsAccount
try
{
    $Apps =Get-AdminPowerApp
    GeneratePowerAppsLog ("Connected to the PowerApps AdminCenter")
}
catch{
    GeneratePowerAppsLog ("ERROR:Connection to the PowerApps AdminCenter" + $_.exception.message)
}
foreach ($app in $apps)
{
    try {
        GeneratePowerAppsLog (" fetching the PowerAppsData for"+$app.Internal.properties.displayName)
        $AppInfo= New-Object System.Object

$connectionList = ""
    foreach($conRef in $app.Internal.properties.connectionReferences)
    {
        foreach($connection in $conRef)
        {
            foreach ($connId in ($connection | Get-Member -MemberType NoteProperty).Name)
            {
                $connDetails = $($connection.$connId)

                $connDisplayName = $connDetails.displayName -replace '[,]'
                $connIconUri = $connDetails.iconUri
                $isOnPremiseConnection = $connDetails.isOnPremiseConnection
                $connId = $connDetails.id


                $connectionList += $connDisplayName + "; "
            }
        }
    }
    $AppInfo |Add-Member -MemberType NoteProperty -Name "DisplayName"  -value $app.Internal.properties.displayName
    $AppInfo |Add-Member -MemberType NoteProperty -Name "CreatedBy"  -value $app.Internal.properties.createdBy.displayName
    $AppInfo |Add-Member -MemberType NoteProperty -Name "Created"  -value $app.Internal.properties.createdTime
    $AppInfo |Add-Member -MemberType NoteProperty -Name "Modified By" -value $app.Internal.properties.lastModifiedBy.displayName
    $AppInfo |Add-Member -MemberType NoteProperty -Name "Modified" -value $app.Internal.properties.lastModifiedTime
    $AppInfo |Add-Member -MemberType NoteProperty -Name "OwnerName" -value $app.Internal.properties.owner.displayName
    $AppInfo |Add-Member -MemberType NoteProperty -Name "UsesPremiumAPI" -value $app.Internal.properties.usesPremiumApi
    $AppInfo |Add-Member -MemberType NoteProperty -Name  "UsesCustomApi"-value $app.Internal.properties.usesCustomApi
    $AppInfo |Add-Member -MemberType NoteProperty -Name  "ConnectionsUsed"-value $connectionList
    $PowerApps +=$AppInfo
    }
    catch {
        GeneratePowerAppsLog ("ERROR:for fetching the PowerAppsData for"+$app.Internal.properties.displayName +  $_.exception.message)
    }

}
$PowerApps | Export-Csv $PowerAppsReportPath -NoTypeInformation -Append
Write-host -ForegroundColor Green "Script execution for the PowerApps is completed...."
Write-host -ForegroundColor Green "Script execution for the Flows is in progress...."

try
{
$flows = Get-AdminFlow
    GenerateFlowLog ("Connected to the PowerApps AdminCenter")
}
catch
{
 GenerateFlowLog ("ERROR:Connection  to the Flow AdminCenter"+ $_.exception.message)
}
foreach($flow in $flows)
{

try
{
 $flowInfo= New-Object System.Object
  GenerateFlowLog ("Fetching information for "+$flow.DisplayName)

$connectionList = ""
      $flowDetails =   $flow | Get-AdminFlow

    $connectionList = ""
    foreach($conRef in $flowDetails.Internal.properties.connectionReferences)
    {
        foreach($connection in $conRef)
        {
            foreach ($connId in ($connection | Get-Member -MemberType NoteProperty).Name)
            {
                $connDetails = $($connection.$connId)

                $connDisplayName = $connDetails.displayName -replace '[,]'
                $connIconUri = $connDetails.iconUri
                $isOnPremiseConnection = $connDetails.isOnPremiseConnection
                $connId = $connDetails.id

                $connectionList += $connDisplayName + "; "
            }
        }
    }
 

    $flowInfo | Add-Member -MemberType NoteProperty -Name "DisplayName"   -Value $flow.DisplayName
    $flowInfo | Add-Member -MemberType NoteProperty -Name "Enabled?"   -Value $flow.Enabled
    $flowInfo | Add-Member -MemberType NoteProperty -Name "CreatedBy"  -Value $flow.CreatedBy.userId
    $flowInfo | Add-Member -MemberType NoteProperty -Name "Created"  -Value $flow.CreatedTime
    $flowInfo | Add-Member -MemberType NoteProperty -Name "ModifiedBy"-Value $flow.ModifiedBy.userId
    $flowInfo | Add-Member -MemberType NoteProperty -Name "Modified"-Value $flow.LastModifiedTime
    $flowInfo | Add-Member -MemberType NoteProperty -Name "Connections"  -Value $connectionList
$Flows+=$flowInfo
}
catch
{
GenerateFlowLog ("ERROR:for fetching the flow for"+$flow.DisplayName +  $_.exception.message)
}
}
$Flows | Export-Csv $FlowReportPath -NoTypeInformation -Append
Write-host -ForegroundColor Green "Script excetion for the  Flow is completed"
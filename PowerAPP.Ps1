Import-Module  "Z:\pnppowershell\Microsoft.PowerApps.Administration.PowerShell" -Force
Import-Module  "Z:\pnppowershell\Microsoft.PowerApps.PowerShell" -Force

$PowerApps =@()
$Flows =@()
Add-PowerAppsAccount
$Apps =Get-AdminPowerApp
foreach ($app in $apps)
{

Write-Host $app.Internal.properties.displayName
Write-Host $app.Internal.properties.createdBy.displayName
Write-Host $app.Internal.properties.createdTime
Write-Host $app.Internal.properties.lastModifiedBy.displayName
Write-Host $app.Internal.properties.lastModifiedTime
Write-Host $app.Internal.properties.owner.displayName
Write-Host $app.Internal.properties.usesPremiumApi
Write-Host $app.Internal.properties.usesCustomApi

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
    Write-host -ForegroundColor Yellow $connectionList
}
$flows = Get-AdminFlow

foreach($flow in $flows)
{
Write-Host $flow.DisplayName
Write-Host $flow.Enabled
Write-Host $flow.CreatedTime
Write-Host $flow.LastModifiedTime
Write-Host $flow.CreatedBy.userId


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
    Write-host -ForegroundColor Yellow $connectionList


}
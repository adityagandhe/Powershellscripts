Import-Module (Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) "Microsoft.PowerApps.RestClientModule.psm1") -NoClobber #-Force
Import-Module (Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) "Microsoft.PowerApps.AuthModule.psm1") -NoClobber #-Force



function Add-ConnectorToBusinessDataGroup
{
    <#
    .SYNOPSIS
    Sets connector to the business data group of data loss policy.
    .DESCRIPTION
    The Add-ConnectorToBusinessDataGroup set connector to the business data group of DLP depending on parameters. 
    Use Get-Help Add-ConnectorToBusinessDataGroup -Examples for more detail.
    .PARAMETER PolicyName
    The PolicyName's identifier.
    .PARAMETER ConnectorName
    The Connector's identifier.
    .PARAMETER EnvironmentName
    The Environment's identifier.
    .PARAMETER ApiVersion
    The api version to call with. Default 2018-01-01.
    .EXAMPLE
    Add-ConnectorToBusinessDataGroup -PolicyName e25a94b2-3111-468e-9125-3d3db3938f13 -ConnectorName shared_office365users
    Sets the connector to BusinessData group of policyname e25a94b2-3111-468e-9125-3d3db3938f13.
    .EXAMPLE
    Add-ConnectorToBusinessDataGroup -EnvironmentName Default-02c201b0-db76-4a6a-b3e1-a69202b479e6 -PolicyName e25a94b2-3111-468e-9125-3d3db3938f13 -ConnectorName shared_office365users
    Sets the connector to BusinessData group of policyname e25a94b2-3111-468e-9125-3d3db3938f13 in environment Default-02c201b0-db76-4a6a-b3e1-a69202b479e6.
    #> 
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$PolicyName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2018-01-01"
    )
    process 
    {
        if([string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies/{policyName}?api-version={apiVersion}"
        }
        else
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/apiPolicies/{policyName}?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName
        }

        $route = $route | ReplaceMacro -Macro "{policyName}" -Value $PolicyName;

        $policy = InvokeApi -Method Get -Route $route -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        $existingConnector = $policy.properties.definition.apiGroups.hbi.apis | where { ($_.id -split "/apis/")[1] -eq $ConnectorName }
        if($existingConnector -ne $null)
        {
            Write-Error "Connector already exists in business data group"
            return $null
        }
		$environments = Get-AdminPowerAppEnvironment
        $connector = $environments[0] | Get-PowerAppConnector -ConnectorName $ConnectorName `
            | %{ New-Object -TypeName PSObject -Property @{ id = $_.connectorId; name = $_.internal.properties.displayName; type = $_.internal.type } }

        if($connector -eq $null)
        {
            Write-Error "No connector with specified name found"
            return $null
        }

        #Add it to the hbi object of policy
        $policy.properties.definition.apiGroups.hbi.apis += $connector

        #remove from lbi object of policy
        $lbiWithoutProvidedConnector = $policy.properties.definition.apiGroups.lbi.apis | Where-Object { $_.id -ne $connector.id }
		
		if ($lbiWithoutProvidedConnector -eq $null)
		{
			$lbiWithoutProvidedConnector =  @()
		}
		
		$policy.properties.definition.apiGroups.lbi.apis = [Array]$lbiWithoutProvidedConnector

        #API Call
        $setConnectorResult = InvokeApiNoParseContent -Method PUT -Body $policy -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        CreateHttpResponse($setConnectorResult)
    }
}

function Remove-ConnectorFromBusinessDataGroup
{
     <#
    .SYNOPSIS
    Removes connector to the business data group of data loss policy.
    .DESCRIPTION
    The Remove-ConnectorFromBusinessDataGroup removes connector from the business data group of DLP depending on parameters. 
    Use Get-Help Remove-ConnectorFromBusinessDataGroup -Examples for more detail.
    .PARAMETER PolicyName
    The PolicyName's identifier.
    .PARAMETER ConnectorName
    The Connector's identifier.
    .PARAMETER EnvironmentName
    The Environment's identifier.
    .PARAMETER ApiVersion
    The api version to call with. Default 2018-01-01.
    .EXAMPLE
    Remove-ConnectorFromBusinessDataGroup -PolicyName e25a94b2-3111-468e-9125-3d3db3938f13 -ConnectorName shared_office365users
    Removes the connector from BusinessData group of policyname e25a94b2-3111-468e-9125-3d3db3938f13.
    .EXAMPLE
    Remove-ConnectorFromBusinessDataGroup -EnvironmentName Default-02c201b0-db76-4a6a-b3e1-a69202b479e6 -PolicyName e25a94b2-3111-468e-9125-3d3db3938f13 -ConnectorName shared_office365users
    Removes the connector from BusinessData group of policyname e25a94b2-3111-468e-9125-3d3db3938f13 in environment Default-02c201b0-db76-4a6a-b3e1-a69202b479e6.
    #> 
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$PolicyName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2018-01-01"
    )
    process 
    {
        if([string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies/{policyName}?api-version={apiVersion}"
        }
        else
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/apiPolicies/{policyName}?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName
        }

        $route = $route | ReplaceMacro -Macro "{policyName}" -Value $PolicyName;

        $policy = InvokeApi -Route $route -Method Get -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        $existingConnector = $policy.properties.definition.apiGroups.lbi.apis | where { ($_.id -split "/apis/")[1] -eq $ConnectorName }
        if($existingConnector -ne $null)
        {
            Write-Error "Connector already exists in non-business data group"
            return $null
        }
        $environments = Get-AdminPowerAppEnvironment
        $connector = $environments[0] | Get-PowerAppConnector -ConnectorName $ConnectorName `
            | %{ New-Object -TypeName PSObject -Property @{ id = $_.connectorId; name = $_.internal.properties.displayName; type = $_.internal.type } }

        if($connector -eq $null)
        {
            Write-Error "No connector with specified name found"
            return $null
        }

        #Add it to the lbi object of policy
        $policy.properties.definition.apiGroups.lbi.apis += $connector
        #remove from hbi object of policy
        $hbiWithoutProvidedConnector = $policy.properties.definition.apiGroups.hbi.apis | Where-Object { $_.id -ne $connector.id }
		
		if ($hbiWithoutProvidedConnector -eq $null)
		{
			$hbiWithoutProvidedConnector = @()
		}
		
		$policy.properties.definition.apiGroups.hbi.apis = [Array]$hbiWithoutProvidedConnector

        #API Call
        $setConnectorResult = InvokeApiNoParseContent -Method PUT -Body $policy -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        CreateHttpResponse($setConnectorResult)
    }
}

function Get-TenantSettings
{
 <#
 .SYNOPSIS
 Get tenant settings
 .DESCRIPTION
 The Get-TenantSettings cmdlet to get tenant settings.
 Use Get-Help Get-TenantSettings -Examples for more detail.
 .PARAMETER ApiVersion
 The api version to call with. Default 2016-11-01
 .EXAMPLE
 Get-TenantSettings
Return:
    @{walkMeOptOut=False}
 #>
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )
    process
    {
        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version={apiVersion}"

        return InvokeApi -Method POST -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    }
}

function Set-TenantSettings
{
 <#
 .SYNOPSIS
 Set tenant settings
 .DESCRIPTION
 The Set-TenantSettings cmdlet to update tenant settings.
 Use Get-Help Set-TenantSettings -Examples for more detail.
 .PARAMETER RequestBody
 Tenant settings to be updated
 .PARAMETER ApiVersion
 The api version to call with. Default 2016-11-01
 .EXAMPLE
	$requestBody = @{
		WalkMeOptOut = $true
	}

	Set-TenantSettings -RequestBody $requestBody

Return:
    @{walkMeOptOut=True}
 #>
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$RequestBody,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )
    process
    {
        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/updateTenantSettings?api-version={apiVersion}"

        return InvokeApi -Method POST -Route $route -Body $RequestBody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    }
}

function Remove-AllowedConsentPlans
{
 <#
 .SYNOPSIS
 Removes all consent plans of the specified types from the tenant and blocks consent plans of those type from being created within the tenant.
 .DESCRIPTION
 The Remove-AllowedConsentPlans cmdlet to remove consent plans of the specified types from the tenant and block consent plans of those
 type from being created within the tenant. Note that this will only impact the types specified, all others will be unaffected. 
 Use Get-Help Remove-AllowedConsentPlans -Examples for more detail.

 .PARAMETER Types
 The types of consent plans that should be removed. Valid options are Internal, Viral.
 .PARAMETER Prompt
 Prompt remove consent plans confirmation
 .PARAMETER ApiVersion
 The api version to call with. Default 2016-11-01
 .EXAMPLE
    Remove-AllowedConsentPlans -Types @("Internal", "Viral")
 #>
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Internal", "Viral", IgnoreCase = $true)]
        [string[]] $Types,

        [Parameter(Mandatory = $false)]
        [bool]$Prompt = $true,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2019-05-01"
    )
    process
    {
        if ($Prompt)
        {
            $question = Read-Host "Are you sure you want to proceed? This command will remove all consent plans of the specified type(s) from all users within your tenant. Enter 'y' to proceed."

            if ($question -ne 'y')
            {
                return
            }
        }

        foreach ($type in $Types)
        {
            Write-Host "Removing all consent plans of type $type."
    
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/allowedConsentPlans/" + $type + "?api-version={apiVersion}"

            InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        }
    }
}

function Add-AllowedConsentPlans
{
 <#
 .SYNOPSIS
 Allows consent plans of the specified types to be created within the tenant.
 .DESCRIPTION
 The Add-AllowedConsentPlans cmdlet to allow creation of consent plans of the specified types within the tenant.
 Note that this will only impact the types specified, all others will be unaffected. 
 Use Get-Help Add-AllowedConsentPlans -Examples for more detail.

  .PARAMETER Types
 The types of consent plans that should become allowed. Valid options are Internal, Viral.
 .PARAMETER ApiVersion
 The api version to call with. Default 2016-11-01
 .EXAMPLE
    Add-AllowedConsentPlans -Types @("Internal", "Viral")
 #>
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Internal", "Viral", IgnoreCase = $true)]
        [string[]] $Types,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2019-05-01"
    )
    process
    {
        $requestBody = @{
            "types" = $Types
        }

        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/allowedConsentPlans?api-version={apiVersion}"

        return InvokeApi -Method POST -Route $route -Body $requestBody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    }
}

function Get-AllowedConsentPlans
{
 <#
 .SYNOPSIS
 Gets the types of consent plans that are allowed within the tenant.
 .DESCRIPTION
 The Get-AllowedConsentPlans cmdlet to get all of the types of consent plans that are allowed within the tenant.
 Use Get-Help Get-AllowedConsentPlans -Examples for more detail.

 .PARAMETER ApiVersion
 The api version to call with. Default 2016-11-01
 .EXAMPLE
	Get-AllowedConsentPlans
 #>
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2019-05-01"
    )
    process
    {
        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/allowedConsentPlans?api-version={apiVersion}"

        return InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    }
}

function Add-CustomConnectorToPolicy
{
    <#
    .SYNOPSIS
    Adds a custom connector to the given group.
    .DESCRIPTION
    The Add-CustomConnectorToGroup adds a custom connector to a specific group of a DLP policy depending on parameters.
    Use Get-Help Add-CustomConnectorToGroup -Examples for more detail.
    .PARAMETER PolicyName
    The PolicyName's identifier.
    .PARAMETER GroupName
    The name of the group to add the connector to, lbi or hbi.
    .PARAMETER ConnectorName
    The Custom Connector's name.
    .PARAMETER ConnectorId
    The Custom Connector's ID.
    .PARAMETER ConnectorType
    The Custom Connector's type.
    .PARAMETER EnvironmentName
    The Environment's identifier.
    .PARAMETER ApiVersion
    The api version to call with. Default 2018-01-01.
    .EXAMPLE
    Add-CustomConnectorToGroup -PolicyName 7b914a18-ad8b-4f15-8da5-3155c77aa70a -ConnectorName BloopBlop -ConnectorId /providers/Microsoft.PowerApps/apis/BloopBlop -ConnectorType Microsoft.PowerApps/apis -GroupName hbi
    Adds the custom connector 'BloopBlop' to BusinessData group of policy name 7b914a18-ad8b-4f15-8da5-3155c77aa70a.
    .EXAMPLE
    Add-CustomConnectorToGroup -EnvironmentName Default-02c201b0-db76-4a6a-b3e1-a69202b479e6 -PolicyName 7b914a18-ad8b-4f15-8da5-3155c77aa70a -ConnectorName BloopBlop -ConnectorId /providers/Microsoft.PowerApps/apis/BloopBlop -ConnectorType Microsoft.PowerApps/apis -GroupName hbi
    Adds the custom connector 'BloopBlop' to BusinessData group of policy name 7b914a18-ad8b-4f15-8da5-3155c77aa70a in environment Default-02c201b0-db76-4a6a-b3e1-a69202b479e6.
    #>
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$PolicyName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string][ValidateSet("lbi", "hbi")]$GroupName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorType,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2018-01-01"
    )
    process
    {
        if([string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies/{policyName}?api-version={apiVersion}"
        }
        else
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/apiPolicies/{policyName}?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName
        }

        $route = $route | ReplaceMacro -Macro "{policyName}" -Value $PolicyName;

        $policy = InvokeApi -Method Get -Route $route -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        $connectorJsonLbi = $policy.properties.definition.apiGroups.lbi.apis | where { $_.id -eq $ConnectorId }
        $connectorJsonHbi = $policy.properties.definition.apiGroups.hbi.apis | where { $_.id -eq $ConnectorId }


        if($connectorJsonLbi -eq $null -and $connectorJsonHbi -eq $null)
        {
            $customConnectorJson = @{
                id = $ConnectorId
                name = $ConnectorName
                type = $ConnectorType
            }

            if ($GroupName -eq "hbi")
            {
                #Add it to the hbi object of policy
                $policy.properties.definition.apiGroups.hbi.apis += $customConnectorJson
            }
            else
            {
                #Add it to the lbi object of policy
                $policy.properties.definition.apiGroups.lbi.apis += $customConnectorJson
            }

            #APi Call
            $setConnectorResult = InvokeApiNoParseContent -Method PUT -Body $policy -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            CreateHttpResponse($setConnectorResult)
        }
        else
        {
            if($connectorJsonLbi -eq $null)
            {
                Write-Error "The given connector is already present in the hbi group."
            }
            else
            {
                Write-Error "The given connector is already present in the lbi group."
            }
            return $null
        }
    }
}

function Remove-CustomConnectorFromPolicy
{
    <#
    .SYNOPSIS
    Deletes a custom connector from the given DLP policy.
    .DESCRIPTION
    The Delete-CustomConnectorFromPolicy deletes a custom connector from the specific DLP policy. 
    Use Get-Help Delete-CustomConnectorFromPolicy -Examples for more detail.
    .PARAMETER PolicyName
    The PolicyName's identifier.
    .PARAMETER ConnectorName
    The Custom Connector's name.
    .PARAMETER EnvironmentName
    The Environment's identifier.
    .PARAMETER ApiVersion
    The api version to call with. Default 2018-01-01.
    .EXAMPLE
    Delete-CustomConnectorFromPolicy -PolicyName 7b914a18-ad8b-4f15-8da5-3155c77aa70a -ConnectorName BloopBlop
    Deletes the custom connector 'BloopBlop' from the DLP policy of policy name 7b914a18-ad8b-4f15-8da5-3155c77aa70a.
    .EXAMPLE
    Delete-CustomConnectorFromPolicy -EnvironmentName Default-02c201b0-db76-4a6a-b3e1-a69202b479e6 -PolicyName 7b914a18-ad8b-4f15-8da5-3155c77aa70a -ConnectorName BloopBlop
    Deletes the custom connector 'BloopBlop' from the DLP policy of policy name 7b914a18-ad8b-4f15-8da5-3155c77aa70a in environment Default-02c201b0-db76-4a6a-b3e1-a69202b479e6.
    #>
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$PolicyName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2018-01-01"
    )
    process
    {
        if([string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies/{policyName}?api-version={apiVersion}"
        }
        else
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/apiPolicies/{policyName}?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName
        }

        $route = $route | ReplaceMacro -Macro "{policyName}" -Value $PolicyName;

        $policy = InvokeApi -Method Get -Route $route -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        $connectorJsonLbi = $policy.properties.definition.apiGroups.lbi.apis | where { ($_.id -split "/apis/")[1] -eq $ConnectorName }
        $connectorJsonHbi = $policy.properties.definition.apiGroups.hbi.apis | where { ($_.id -split "/apis/")[1] -eq $ConnectorName }

        if($connectorJsonLbi -eq $null -and $connectorJsonHbi -eq $null)
        {
            Write-Error "The given connector is not in the policy."
            return $null
        }
        else
        {
            if($connectorJsonLbi -eq $null)
            {
                #remove from hbi object of policy
                $hbiWithoutProvidedConnector = $policy.properties.definition.apiGroups.hbi.apis -ne $connectorJsonHbi
                $policy.properties.definition.apiGroups.hbi.apis =  $hbiWithoutProvidedConnector

                #APi Call
                $removeConnectorResult = InvokeApiNoParseContent -Method PUT -Body $policy -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                CreateHttpResponse($removeConnectorResult)
            }
            else
            {
                #remove from lbi object of policy
                $lbiWithoutProvidedConnector = $policy.properties.definition.apiGroups.lbi.apis -ne $connectorJsonLbi
                $policy.properties.definition.apiGroups.lbi.apis =  $lbiWithoutProvidedConnector

                #APi Call
                $removeConnectorResult = InvokeApiNoParseContent -Method PUT -Body $policy -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                CreateHttpResponse($removeConnectorResult)
            }
        }
    }
}

function Get-AdminPowerAppConnectionReferences
{
 <#
 .SYNOPSIS
 Returns app connection references.
 .DESCRIPTION
 The Get-AdminPowerAppConnectionList information about all connections referenced in an input PowerApp. 
 Use Get-Help Get-AdminPowerAppConnectionList -Examples for more detail.
 .PARAMETER AppName
 PowerApp to list connectors for.
 .PARAMETER EnvironmentName
 Environment where the input PowerApp is located.
 .EXAMPLE
 Get-AdminPowerAppConnectionList -EnvironmentName 643268a6-c680-446f-b8bc-a3ebbf98895f -AppName fc947231-728a-4a74-a654-64b0f22a0d71
 Returns all connections referenced in the PowerApp fc947231-728a-4a74-a654-64b0f22a0d71.
 #>
    [CmdletBinding(DefaultParameterSetName="Connector")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Connector", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,
        [Parameter(Mandatory = $true, ParameterSetName = "Connector", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName
    )
    process
    {
        $app = Get-AdminPowerApp -EnvironmentName $EnvironmentName -AppName $AppName

        foreach($conRef in $app.Internal.properties.connectionReferences)
        {
            foreach($connection in $conRef)
            {
                foreach ($connId in ($connection | Get-Member -MemberType NoteProperty).Name)
                {
                    Get-PowerAppConnector -EnvironmentName $EnvironmentName -ConnectorName ($($connection.$connId).id -split '/apis/')[1]
                }
            }
        }
    }
}

function Get-AdminPowerAppConnector
{
 <#
 .SYNOPSIS
 Returns information about one or more custom connectors.
 .DESCRIPTION
 The Get-AdminConnector looks up information about one or more custom connectors depending on parameters. 
 Use Get-Help Get-AdminConnector -Examples for more detail.
 .PARAMETER Filter
 Finds custom connector matching the specified filter (wildcards supported).
 .PARAMETER ConnectorName
 Limit custom connectors returned to those of a specified connector.
 .PARAMETER EnvironmentName
 Limit custom connectors returned to those in a specified environment.
 .PARAMETER CreatedBy
 Limit custom connectors returned to those created by the specified user (email or AAD Principal object id)
 .PARAMETER ApiVersion
 The api version to call with. Default 2017-05-01
 .EXAMPLE
 Get-AdminConnector
 Returns all custom connector from all environments where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
 .EXAMPLE
 Get-AdminConnector *customapi*
 Returns all custom connectors with the text "customapi" in the name/display name from all environments where the calling user is an Environment Admin  For Global admins, this will search across all environments in the tenant.
  .EXAMPLE
 Get-AdminConnector -CreatedBy foo@bar.onmicrosoft.com
 Returns all apps created by the user with an email of "foo@bar.onmicrosoft.com" from all environment where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
  .EXAMPLE
 Get-AdminConnector -EnvironmentName 0fc02431-15fb-4563-a5ab-8211beb2a86f
 Finds custom connectors within the 0fc02431-15fb-4563-a5ab-8211beb2a86f environment
  .EXAMPLE
 Get-AdminConnector -ConnectorName shared_customapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698
 Finds all custom connectosr created with name/id shared_customapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698 from all environments where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
  .EXAMPLE
 Get-AdminConnector -ConnectorName shared_customapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698 -EnvironmentName 0fc02431-15fb-4563-a5ab-8211beb2a86f
 Finds connections within the 0fc02431-15fb-4563-a5ab-8211beb2a86f environment that are created against the shared_customapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698.
 .EXAMPLE
 Get-AdminConnector *customapi* -EnvironmentName 0fc02431-15fb-4563-a5ab-8211beb2a86f
 Finds all connections in environment 0fc02431-15fb-4563-a5ab-8211beb2a86f that contain the string "customapi" in their display name.
 #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "User")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = "Connector", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Connector", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$CreatedBy,

        [Parameter(Mandatory = $false, ParameterSetName = "Connector")]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2017-05-01"
    )

    process 
    {
        # If the connector name is specified, only return connections for that connector
        if (-not [string]::IsNullOrWhiteSpace($ConnectorName))
        {
            $environments = @();
 
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $environments += @{
                    EnvironmentName = $EnvironmentName
                }
            }
            else 
            {
                $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false
            }

            foreach($environment in $environments)
            {

                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environmentName}/apis?api-version={apiVersion}" `
                | ReplaceMacro -Macro "{environmentName}" -Value $environment.EnvironmentName;

                $connectionResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                # There is no api endpoint with connector name to get the details for specified connector, so assigning filter to connectorname to just return the specified connector details
                Get-FilteredCustomConnectors -Filter $ConnectorName -CreatedBy $CreatedBy -ConnectorResult $connectionResult
            }
        }
        else
        {
            # If the caller passed in an environment scope, filter the query to only that environment 
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environmentName}/apis?api-version={apiVersion}" `
                | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;    

                $connectionResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion

                Get-FilteredCustomConnectors -Filter $Filter -CreatedBy $CreatedBy -ConnectorResult $connectionResult
            }
            # otherwise search for the apps acroos all environments for this calling user
            else 
            {
                $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false

                foreach($environment in $environments)
                {
                    $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environmentName}/apis?api-version={apiVersion}" `
                    | ReplaceMacro -Macro "{environmentName}" -Value $environment.EnvironmentName;    
    
                    $connectionResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    
                    Get-FilteredCustomConnectors -Filter $Filter -CreatedBy $CreatedBy -ConnectorResult $connectionResult
                }
            }
        }
    }
}

function Get-AdminPowerAppConnectorRoleAssignment
{
 <#
 .SYNOPSIS
 Returns the connection role assignments for a user or a custom connection. Owner role assignments cannot be deleted without deleting the connection resource.
 .DESCRIPTION
 The Get-AdminConnectorRoleAssignment functions returns all roles assignments for an custom connector or all custom connectors roles assignments for a user (across all of their connections).  A connection's role assignments determine which users have access to the connection for using or building apps and flows and with which permission level (CanUse, CanUseAndShare) . 
 Use Get-Help Get-AdminPowerAppConnectorRoleAssignment -Examples for more detail.
 .PARAMETER EnvironmentName
 The connector's environment. 
 .PARAMETER ConnectorName
 The connector's identifier.
 .PARAMETER PrincipalObjectId
 The objectId of a user or group, if specified, this function will only return role assignments for that user or group.
 .EXAMPLE
 Get-AdminPowerAppConnectorRoleAssignment
 Returns all role assignments for all custom connectors in all environments
 .EXAMPLE
 Get-AdminPowerAppConnectorRoleAssignment -ConnectorName shared_customapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698
 Returns all role assignments for the connector with name shared_customapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698 in all environments
 .EXAMPLE
 Get-AdminPowerAppConnectorRoleAssignment -ConnectorName shared_customapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698 -EnvironmentName 0fc02431-15fb-4563-a5ab-8211beb2a86f -PrincipalObjectId a1caec2d-8b48-40cc-8eb8-5cf95b445b46
 Returns all role assignments for the user, or group with an principal object id of a1caec2d-8b48-40cc-8eb8-5cf95b445b46 for the custom connector with name shared_customapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698 in environment with name 0fc02431-15fb-4563-a5ab-8211beb2a86f
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $selectedObjectId = $null

        if (-not [string]::IsNullOrWhiteSpace($ConnectorName))
        {
            if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
            {
                $selectedObjectId = $PrincipalObjectId;
            }
        }

        $pattern = BuildFilterPattern -Filter $selectedObjectId

        #If Both EnvironmentName and ConnectorName is Provided, Get the details of provided connector in provided Environment
        if (-not [string]::IsNullOrWhiteSpace($ConnectorName) -and -not [string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connector}/permissions?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $connectorRoleResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            foreach ($connectorRole in $connectorRoleResult.Value)
            {
                if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
                {
                    if ($pattern.IsMatch($connectorRole.properties.principal.id ) -or
                        $pattern.IsMatch($connectorRole.properties.principal.email) -or 
                        $pattern.IsMatch($connectorRole.properties.principal.tenantId))
                    {
                        CreateCustomConnectorRoleAssignmentObject -ConnectorRoleAssignmentObj $connectorRole -EnvironmentName $EnvironmentName
                    }
                }
                else 
                { 
                    CreateCustomConnectorRoleAssignmentObject -ConnectorRoleAssignmentObj $connectorRole -EnvironmentName $EnvironmentName
                }
            }
        }
        else 
        {
            # only if EnvironmentName is provided, get the details of specified environment
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $connectorsList = Get-AdminPowerAppConnector -EnvironmentName $EnvironmentName -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            }
            #only if ConnectorName is provided, get the details of specified ConnectorName in all environments
            elseif(-not [string]::IsNullOrWhiteSpace($ConnectorName))
            {
                $connectorsList = Get-AdminPowerAppConnector -ConnectorName $ConnectorName -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            }
            else
            {
                $connectorsList = Get-AdminPowerAppConnector -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            }

            foreach($connector in $connectorsList)
            {
                Get-AdminPowerAppConnectorRoleAssignment `
                    -ConnectorName $connector.ConnectorName `
                    -EnvironmentName $connector.EnvironmentName `
                    -PrincipalObjectId $selectedObjectId `
                    -ApiVersion $ApiVersion `
					 -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            }
        }
    }
}

function Set-AdminPowerAppConnectorRoleAssignment
{
    <#
    .SYNOPSIS
    Sets permissions to the custom connectors.
    .DESCRIPTION
    The Set-AdminPowerAppConnectorRoleAssignment set up permission to custom connectors depending on parameters. 
    Use Get-Help Set-AdminPowerAppConnectorRoleAssignment -Examples for more detail.
    .PARAMETER ConnectorName
    The custom connector's identifier.
    .PARAMETER EnvironmentName
    The connectors's environment. 
    .PARAMETER RoleName
    Specifies the permission level given to the connector: CanView, CanViewWithShare, CanEdit. Sharing with the entire tenant is only supported for CanView.
    .PARAMETER PrincipalType
    Specifies the type of principal this connector is being shared with; a user, a security group, the entire tenant.
    .PARAMETER PrincipalObjectId
    If this connector is being shared with a user or security group principal, this field specified the ObjectId for that principal. You can use the Get-UsersOrGroupsFromGraph API to look-up the ObjectId for a user or group in Azure Active Directory.
    .EXAMPLE
   Set-AdminPowerAppConnectorRoleAssignment -ConnectorName shared_testapi.5f0629412a7d1fe83e.5f6f049093c9b7a698 -EnvironmentName 0fc02431-15fb-4563-a5ab-8211beb2a86f -RoleName CanView -PrincipalType User -PrincipalObjectId a9f34b89-b7f2-48ef-a3ca-1c435bc655a0
    Give the specified user CanView permissions to the connector with name shared_testapi.5f0629412a7d1fe83e.5f6f049093c9b7a698
    #> 
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("CanView", "CanViewWithShare", "CanEdit")]
        [string]$RoleName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("User", "Group", "Tenant")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $TenantId = $Global:currentSession.tenantId

        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connector}/modifyPermissions?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null

        If ($PrincipalType -eq "Tenant")
        {
            $requestbody = @{ 
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            principal = @{
                                id = $TenantId
                                tenantId = $TenantId
                            }          
                        }
                    }
                )
            }
        }
        else
        {
            $requestbody = @{ 
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            principal = @{
                                id = $PrincipalObjectId
                            }               
                        }
                    }
                )
            }
        }
        
        $setConnectorRoleResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($setConnectorRoleResult)
    }
}

function Remove-AdminPowerAppConnectorRoleAssignment
{
 <#
 .SYNOPSIS
 Deletes a connector role assignment record.
 .DESCRIPTION
 The Remove-AdminPowerAppConnectorRoleAssignment deletes the specific connector role assignment
 Use Get-Help Remove-AdminPowerAppConnectorRoleAssignment -Examples for more detail.
 .PARAMETER RoleId
 The id of the role assignment to be deleted.
 .PARAMETER ConnectorName
 The connector name
 .PARAMETER EnvironmentName
 The connector's environment. 
 .EXAMPLE
 Remove-AdminPowerAppConnectorRoleAssignment -EnvironmentName 0fc02431-15fb-4563-a5ab-8211beb2a86f -ConnectorName shared_testapi.5f0629412a7d1fe83e.5f6f049093c9b7a698 -RoleId /providers/Microsoft.PowerApps/scopes/admin/environments/0fc02431-15fb-4563-a5ab-8211beb2a86f/apis/shared_testapi.5f0629412a7d1fe83e.5f6f049093c9b7a698/permissions/a9f34b89-b7f2-48ef-a3ca-1c435bc655a0
 Deletes the role assignment with an id of /providers/Microsoft.PowerApps/scopes/admin/environments/0fc02431-15fb-4563-a5ab-8211beb2a86f/apis/shared_testapi.5f0629412a7d1fe83e.5f6f049093c9b7a698/permissions/a9f34b89-b7f2-48ef-a3ca-1c435bc655a0
 #>
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connector}/modifyPermissions`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName `
        | ReplaceMacro -Macro "{apiVersion}"  -Value $ApiVersion;

        #Construct the body 
        $requestbody = $null
        
        $requestbody = @{ 
            delete = @(
                @{ 
                    id = $RoleId
                }
            )
        }
    
        $removeResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}

function Remove-AdminPowerAppConnector
{
 <#
 .SYNOPSIS
 Deletes the custom connector.
 .DESCRIPTION
 The Remove-AdminPowerAppConnector permanently deletes the custom connector. 
 Use Get-Help Remove-AdminPowerAppConnector -Examples for more detail.
 .PARAMETER ConnectorName
 The connector's connector name.
 .PARAMETER EnvironmentName
 The connector's environment.
 .EXAMPLE
 Remove-AdminPowerAppConnector -EnvironmentName 0fc02431-15fb-4563-a5ab-8211beb2a86f -ConnectorName shared_testapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698
 Deletes the custom connector with name shared_testapi2.5f0629412a7d1fe83e.5f6f049093c9b7a698
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connector}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        $removeResult = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}

function Get-AdminPowerAppsUserDetails
{
 <#
 .SYNOPSIS
 Downloads the user details into specified filepath
 .DESCRIPTION
 The Get-AdminPowerAppsUserDetails downloads the powerApps user details into the specified path file
 Use Get-Help Get-AdminPowerAppsUserDetails -Examples for more detail.
 .PARAMETER UserPrincipalName
 The user principal name
 .PARAMETER OutputFilePath
 The Output FilePath 
 .EXAMPLE
 Get-AdminPowerAppsUserDetails -OutputFilePath C:\Users\testuser\userdetails.json
 Donloads the details of calling user into specified path file C:\Users\testuser\userdetails.json
 .EXAMPLE
 Get-AdminPowerAppsUserDetails -UserPrincipalName foo@bar.com -OutputFilePath C:\Users\testuser\userdetails.json
 downloads the details of user with principal name foo@bar.com into specified file path C:\Users\testuser\userdetails.json
 #>
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName = $null,

        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath = $null,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )
    process
    {
        #Construct the body 
        $requestbody = $null

        if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName))
        {
            $requestbody = @{
                userPrincipalName = $UserPrincipalName
            }
        }
        #first post call would just return the status 'ACCEPTED' and Location in Headers
        #keep calling Get Location Uri until the job gets finished and once the job gets finished it returns http 'OK' and SAS uri otherwise 'ACCEPTED'
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/exportHiddenUserData?api-version={apiVersion}";

        #Kick-off the job
        $getUserDataJobKickOffResponse = InvokeApiNoParseContent -Route $route -Method POST -Body $requestbody -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        $statusUrl = $getUserDataJobKickOffResponse.Headers['Location']

        #Wait until job is completed
        if (-not [string]::IsNullOrWhiteSpace($statusUrl))
        {
            while($getJobCompletedResponse.StatusCode -ne 200) 
            {
                Start-Sleep -s 3
                $getJobCompletedResponse = InvokeApiNoParseContent -Route $statusUrl -Method GET -ThrowOnFailure
            }

            CreateHttpResponse($getJobCompletedResponse)

            $responseBody = ConvertFrom-Json $getJobCompletedResponse.Content

            try {
                $downloadCsvResponse = Invoke-WebRequest -Uri $responseBody -OutFile $OutputFilePath
                Write-Host "Downloaded to specified file"
            } catch {
                Write-Host "Error while downloading"
                $response = $_.Exception.Response
                if ($_.ErrorDetails)
                {
                    $errorResponse = ConvertFrom-Json $_.ErrorDetails;
                    $code = $response.StatusCode
                    $message = $errorResponse.error.message
                    Write-Verbose "Status Code: '$code'. Message: '$message'" 
                }
            }
        }
    }
}

#internal, helper function
function Get-FilteredCustomConnectors
{
     param
    (
        [Parameter(Mandatory = $false)]
        [object]$Filter,

        [Parameter(Mandatory = $false)]
        [object]$CreatedBy,

        [Parameter(Mandatory = $false)]
        [object]$ConnectorResult
    )

    $patternCreatedBy = BuildFilterPattern -Filter $CreatedBy
    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($connector in $ConnectorResult.Value)
    {
        if ($patternCreatedBy.IsMatch($connector.properties.createdBy.displayName) -or
            $patternCreatedBy.IsMatch($connector.properties.createdBy.email) -or 
            $patternCreatedBy.IsMatch($connector.properties.createdBy.id) -or 
            $patternCreatedBy.IsMatch($connector.properties.createdBy.userPrincipalName))
        {
            if ($patternFilter.IsMatch($connector.name) -or
                $patternFilter.IsMatch($connector.properties.displayName))
            {
                CreateCustomConnectorObject -CustomConnectorObj $connector
            }
        }
    }
}

#internal, helper function
function CreateCustomConnectorObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$CustomConnectorObj
    )
    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value $CustomConnectorObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorId -Value $CustomConnectorObj.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name ApiDefinitions -Value $CustomConnectorObj.properties.apiDefinitions `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $CustomConnectorObj.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $CustomConnectorObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedBy -Value $CustomConnectorObj.properties.createdBy `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $CustomConnectorObj.properties.changedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $CustomConnectorObj.properties.environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $CustomConnectorObj.properties;
}

#internal, helper function
function CreateCustomConnectorRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ConnectorRoleAssignmentObj,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName
    )

    If($ConnectorRoleAssignmentObj.properties.principal.type -eq "Tenant")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectorRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectorRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectorRoleAssignmentObj.properties.principal.tenantId `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectorRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectorRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectorRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectorRoleAssignmentObj;
    }
    elseif($ConnectorRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectorRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectorRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $ConnectorRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $ConnectorRoleAssignmentObj.properties.principal.email `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectorRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectorRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectorRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectorRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectorRoleAssignmentObj;
    }
    elseif($ConnectorRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectorRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectorRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $ConnectorRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectorRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectorRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectorRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectorRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectorRoleAssignmentObj;
    }
    else {
        return $null
    }
}

function New-AdminPowerAppEnvironment
{
<#
 .SYNOPSIS
 Creates an Environment.
 .DESCRIPTION
 The New-AdminPowerAppEnvironment cmdlet creates a new Environment by the logged in user.
 Api version 2019-05-01 adds the capability to create an environment with a database. The new commandline argument 'ProvisionDatabase'
 acts as switch to indicate we need to create an environment with the database. If the switch is set, LanguageName and CurrencyName arguments
 are mandatory to pass while Templates,SecurityGroupId and DomainName are optional.
 Use Get-Help New-AdminPowerAppEnvironment -Examples for more detail.
 .PARAMETER DisplayName
 The display name of the new Environment.
 .PARAMETER LocationName
 The location of the new Environment. Use Get-AdminPowerAppEnvironmentLocations to see the valid locations.
 .PARAMETER EnvironmentSku
 The Environment type (Trial, Sandbox, or Production).
 .PARAMETER ProvisionDatabase
 The switch to provision Cds database along with creating the environment. If set, LanguageName and CurrencyName are mandatory to pass as arguments.
 .PARAMETER CurrencyName
 The default currency for the database, use Get-AdminPowerAppCdsDatabaseCurrencies to get the supported values
 .PARAMETER LanguageName
 The default languages for the database, use Get-AdminPowerAppCdsDatabaseLanguages to get the support values
 .PARAMETER Templates
 The list of templates used for provisioning. If it is null, an empty Common Data Service database will be created
 .PARAMETER SecurityGroupId
 The Azure Active Directory security group object identifier to restrict database membership.
 .PARAMETER DomainName
 The domain name.
 .PARAMETER WaitUntilFinished
 If set to true, the function will not return until provisioning the database is complete (as either a success or failure)
 .EXAMPLE
 New-AdminPowerAppEnvironment -DisplayName 'HQ Apps' -Location unitedstates -EnvironmentSku Trial
 Creates a new Trial Environment in the United States with the display name 'HQ Apps'
 .EXAMPLE
 New-AdminPowerAppEnvironment -DisplayName 'Asia Dev' -Location asia -EnvironmentSku Production
 Creates a new Production Environment in Asia with the display name 'Asia Dev'
 #>
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$DisplayName,

        [Parameter(Mandatory = $true, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$LocationName,

        [ValidateSet("Trial", "Sandbox", "Production")]
        [Parameter(Mandatory = $true, ParameterSetName = "Name")]
        [string]$EnvironmentSku,

        [Parameter(Mandatory = $false)]
        [Switch]$ProvisionDatabase,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$CurrencyName,
    
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$LanguageName,

        [Parameter(Mandatory = $false)]
        [string[]]$Templates,

        [Parameter(Mandatory = $false)]
        [string]$SecurityGroupId = $null,

        [Parameter(Mandatory = $false)]
        [string]$DomainName = $null,

        [Parameter(Mandatory = $false)]
        [bool]$WaitUntilFinished = $true,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2019-05-01"
    )
    process
    {
        $postEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/environments`?api-version={apiVersion}&id=/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments";

        $environment = @{
            location = $LocationName
            properties = @{
                displayName = $DisplayName
                environmentSku = $EnvironmentSku
            }
        }

        if ($ProvisionDatabase)
        {
            if ($CurrencyName -ne $null -and
                $LanguageName -ne $null)
            {
                $environment.properties["linkedEnvironmentMetadata"] = @{
                    baseLanguage = $LanguageName
                    currency = @{
                        code = $CurrencyName
                    }
                    templates = $Templates
                }

                if (-not [string]::IsNullOrEmpty($SecurityGroupId))
                {
				    $environment.properties["linkedEnvironmentMetadata"] += @{
                       securityGroupId = $SecurityGroupId
                    }
                }

                if (-not [string]::IsNullOrEmpty($DomainName))
                {
                    $environment.properties["linkedEnvironmentMetadata"] += @{
                        domainName = $DomainName
                    }
                }

                $environment.properties["databaseType"] = "CommonDataService"
            }
            else
            {
                Write-Error "CurrencyName and Language must be passed as arguments."
                throw
            }

            # By default we poll until the CDS database is finished provisioning
            If($WaitUntilFinished)
            {
                $response = InvokeApiNoParseContent -Method POST -Route $postEnvironmentUri -Body $environment -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
                $statusUrl = $response.Headers['Location']

                if ($response.StatusCode -eq 400)
                {
                    #Write-Error "An error occured."
                }
                else
                {
                    $currentTime = Get-Date -format HH:mm:ss
                    $nextTime = Get-Date -format HH:mm:ss
                    $TimeDiff = New-TimeSpan $currentTime $nextTime
                    $timeoutInSeconds = 600
        
                    #Wait until the environment has been deleted, there is an error, or we hit a timeout
                    while((-not [string]::IsNullOrEmpty($statusUrl)) -and ($response.StatusCode -eq 202) -and ($TimeDiff.TotalSeconds -lt $timeoutInSeconds))
                    {
                        Start-Sleep -s 5
                        $response = InvokeApiNoParseContent -Route $statusUrl -Method GET -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
                        $nextTime = Get-Date -format HH:mm:ss
                        $TimeDiff = New-TimeSpan $currentTime $nextTime
                    }
                }

                CreateHttpResponse($response)
            }
            # optionally the caller can choose to NOT wait until provisioning is complete and get the provisioning status by polling on Get-AdminPowerAppEnvironment and looking at the provisioning status field
            else
            {
                $response = InvokeApi -Method POST -Route $route -Body $environment -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                if ($response.StatusCode -eq 400)
                {
                    #Write-Error "An error occured."
                    CreateHttpResponse($response)
                }

                CreateHttpResponse($response)
            }
        }
        else
        {
            $response = InvokeApi -Method POST -Route $postEnvironmentUri -ApiVersion $ApiVersion -Body $environment  -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            if ($response.StatusCode -eq 400)
            {
                #Write-Error "An error occured."
                CreateHttpResponse($response)
            }
            else
            {
                CreateEnvironmentObject -EnvObject $response -ReturnCdsDatabaseType $false
            }
        }
    }
}

function Set-AdminPowerAppEnvironmentDisplayName
{
<#
 .SYNOPSIS
 Updates the Environment display name.
 .DESCRIPTION
 The Set-EnvironmentDisplayName cmdlet updates the display name field of the specified Environment. 
 Use Get-Help Set-EnvironmentDisplayName -Examples for more detail.
 .PARAMETER EnvironmentName
 Updates a specific environment.
 .PARAMETER NewDisplayName
 The new display name of the Environment.
 .EXAMPLE
 Set-EnvironmentDisplayName -EnvironmentName 8d996ece-8558-4c4e-b459-a51b3beafdb4 -NewDisplayName Applications
 Updates the display name of Environment '8d996ece-8558-4c4e-b459-a51b3beafdb4' to be called 'Applications'.
 .EXAMPLE
 Set-EnvironmentDisplayName -EnvironmentName 8d996ece-8558-4c4e-b459-a51b3beafdb4 -NewDisplayName 'Main Organization Apps'
 Updates the display name to be 'Main Organization Apps'
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Name")]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Name")]
        [string]$NewDisplayName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2016-11-01"
    )
    process
    {
        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;
    
        $requestBody = @{
            properties = @{
                displayName = $NewDisplayName
            }
        }

        $response = InvokeApi -Method PATCH -Route $route -Body $requestBody -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($response)
    }
}

function Get-AdminPowerAppEnvironmentLocations
{
    <#
    .SYNOPSIS
    Returns all supported environment locations.
    .DESCRIPTION
    The Get-AdminPowerAppEnvironmentLocations cmdlet returns all supported locations to create an environment in PowerApps.
    Use Get-Help Get-AdminPowerAppEnvironmentLocations -Examples for more detail.
    .PARAMETER Filter
    Finds locations matching the specified filter (wildcards supported).
    .EXAMPLE
    Get-AdminPowerAppEnvironmentLocations
    Returns all locations.
    .EXAMPLE
    Get-AdminPowerAppEnvironmentLocations *unitedstates*
    Returns the US location
    #>
    param
    (
        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]$Filter,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    $getLocationsUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/locations?api-version={apiVersion}"
    
    $locationsResult = InvokeApi -Method GET -Route $getLocationsUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($location in $locationsResult.Value)
    {
        if ($patternFilter.IsMatch($location.name) -or
            $patternFilter.IsMatch($location.properties.displayName))
        {
            CreateEnvironmentLocationObject -EnvironmentLocationObject $location
        }
    }
}


function Get-AdminPowerAppCdsDatabaseCurrencies
{
    <#
    .SYNOPSIS
    Returns all supported CDS database currencies.
    .DESCRIPTION
    The Get-AdminPowerAppCdsDatabaseCurrencies cmdlet returns all supported database currencies, which is required to provision a new instance.
    Use Get-Help Get-AdminPowerAppCdsDatabaseCurrencies -Examples for more detail.
    .PARAMETER Filter
    Finds currencies matching the specified filter (wildcards supported).
    .PARAMETER LocationName
    The location of the current environment. Use Get-AdminPowerAppEnvironmentLocations to see the valid locations.
    .EXAMPLE
    Get-AdminPowerAppCdsDatabaseCurrencies
    Returns all currencies.
    .EXAMPLE
    Get-AdminPowerAppCdsDatabaseCurrencies *USD*
    Returns the US dollar currency
    #>
    param
    (
        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]$Filter,

        [Parameter(Mandatory = $true, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$LocationName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    $getCurrenciesUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/locations/{location}/environmentCurrencies?api-version={apiVersion}" `
    | ReplaceMacro -Macro "{location}" -Value $LocationName;
    
    $currenciesResult = InvokeApi -Method GET -Route $getCurrenciesUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($currency in $currenciesResult.Value)
    {
        if ($patternFilter.IsMatch($currency.name) -or
            $patternFilter.IsMatch($currency.properties.code))
        {
            CreateCurrencyObject -CurrencyObject $currency
        }
    }
}

function Get-AdminPowerAppCdsDatabaseLanguages
{
    <#
    .SYNOPSIS
    Returns all supported CDS database languages.
    .DESCRIPTION
    The Get-AdminPowerAppCdsDatabaseLanguages cmdlet returns all supported database languages, which is required to provision a new instance.
    Use Get-Help Get-AdminPowerAppCdsDatabaseLanguages -Examples for more detail.
    .PARAMETER Filter
    Finds langauges matching the specified filter (wildcards supported).
    .PARAMETER LocationName
    The location of the current environment. Use Get-AdminPowerAppEnvironmentLocations to see the valid locations.
    .EXAMPLE
    Get-AdminPowerAppCdsDatabaseLanguages
    Returns all languages.
    .EXAMPLE
    Get-AdminPowerAppCdsDatabaseLanguages *English*
    Returns all English language options
    #>
    param
    (
        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]$Filter,

        [Parameter(Mandatory = $true, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$LocationName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    $getLanguagesUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/locations/{location}/environmentLanguages?api-version={apiVersion}" `
    | ReplaceMacro -Macro "{location}" -Value $LocationName;
    
    $languagesResult = InvokeApi -Method GET -Route $getLanguagesUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($languages in $languagesResult.Value)
    {
        if ($patternFilter.IsMatch($languages.name) -or
            $patternFilter.IsMatch($languages.properties.displayName) -or
            $patternFilter.IsMatch($languages.properties.localizedName))
        {
            CreateLanguageObject -LanguageObject $languages
        }
    }
}

function Get-AdminPowerAppCdsDatabaseTemplates
{
    <#
    .SYNOPSIS
    Returns all supported CDS database templates.
    .DESCRIPTION
    The Get-AdminPowerAppCdsDatabaseTemplates cmdlet returns all supported database templates, which is required to provision a new instance.
    Use Get-Help Get-AdminPowerAppCdsDatabaseTemplates -Examples for more detail.
    .PARAMETER Filter
    Finds templates matching the specified filter (wildcards supported).
    .PARAMETER LocationName
    The location of the current environment. Use Get-AdminPowerAppEnvironmentLocations to see the valid locations.
    .EXAMPLE
    Get-AdminPowerAppCdsDatabaseTemplates -LocationName unitedstates
    Returns all templates for United States.
    .EXAMPLE
    Get-AdminPowerAppCdsDatabaseTemplates *CDS*
    Returns the CDS template
    #>
    param
    (
        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]$Filter,

        [Parameter(Mandatory = $true, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$LocationName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2019-05-01"
    )

    $getTemplatesUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/locations/{location}/templates?api-version={apiVersion}" `
    | ReplaceMacro -Macro "{location}" -Value $LocationName;
    
    $templatesResult = InvokeApi -Method GET -Route $getTemplatesUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($template in $templatesResult.Value)
    {
        if ($patternFilter.IsMatch($template.name) -or
            $patternFilter.IsMatch($template.properties.code))
        {
            CreateTemplateObject -TemplateObject $template
        }
    }
}

function New-AdminPowerAppCdsDatabase
{
    <#
    .SYNOPSIS
    Creates a Common Data Service For Apps database for the specified environment.
    .DESCRIPTION
    The New-AdminPowerAppCdsDatabase cmdlet creates a Common Data Service For Apps database for the specified environment with teh specified default language and currency.
    Use Get-Help New-AdminPowerAppCdsDatabase -Examples for more detail.
    .PARAMETER EnvironmentName
    The environment name
    .PARAMETER CurrencyName
    The default currency for the database, use Get-AdminPowerAppCdsDatabaseCurrencies to get the supported values
    .PARAMETER LanguageName
    The default languages for the database, use Get-AdminPowerAppCdsDatabaseLanguages to get the support values
    .PARAMETER WaitUntilFinished
    Default is true.  If set to true, then the function will not return a value until provisioning the database is complete (as either a success or failure)
    .PARAMETER Templates
    The list of templates that used for provisision. If not provided then an empty Common Data Service database will be created.
    .PARAMETER SecurityGroupId
    The Azure Active Directory security group object identifier to which to restrict database membership.
    .PARAMETER DomainName
    The domain name
    .EXAMPLE
    New-AdminPowerAppCdsDatabase -EnvironmentName 8d996ece-8558-4c4e-b459-a51b3beafdb4 -CurrencyName USD -LanguageName 1033
    Creates a database with the US dollar currency and Environment (US) language
    #>
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$CurrencyName,
    
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$LanguageName,

        [Parameter(Mandatory = $false)]
        [bool]$WaitUntilFinished = $true,

        [Parameter(Mandatory = $false)]
        [string[]]$Templates,

        [Parameter(Mandatory = $false)]
        [string]$SecurityGroupId = $null,

        [Parameter(Mandatory = $false)]
        [string]$DomainName = $null,
		
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$ApiVersion = "2018-01-01"
    )
    process
    {
        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/environments/{environmentName}/provisionInstance`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;
        
        $requestBody = @{
            baseLanguage = $LanguageName
            currency = @{
                code = $CurrencyName
            }
            templates = $Templates
        }

        if (-not [string]::IsNullOrEmpty($SecurityGroupId))
        {
		    $requestBody += @{
                securityGroupId = $SecurityGroupId
            }
        }
        if (-not [string]::IsNullOrEmpty($DomainName))
        {
		    $requestBody += @{
                domainName = $DomainName
            }
        }

        # By default we poll until the CDS database is finished provisioning
        If($WaitUntilFinished)
        {
            $response = InvokeApiNoParseContent -Method POST -Route $route -Body $requestBody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            $statusUrl = $response.Headers['Location']

            if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 202)
            {
                #Write-Error "An error occured."
                CreateHttpResponse($response)
            }
            else
            {
                $currentTime = Get-Date -format HH:mm:ss
                $nextTime = Get-Date -format HH:mm:ss
                $TimeDiff = New-TimeSpan $currentTime $nextTime
                $timeoutInSeconds = 300
        
                #Wait until CDS provision is completed, or we hit a timeout
                while(($response.StatusCode -eq 202) -and ($TimeDiff.TotalSeconds -lt $timeoutInSeconds))
                {
                    Start-Sleep -s 5
                    $response = InvokeApiNoParseContent -Route $statusUrl -Method GET -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
                    $nextTime = Get-Date -format HH:mm:ss
                    $TimeDiff = New-TimeSpan $currentTime $nextTime
                }
    
                $parsedResponse = ConvertFrom-Json $response.Content
                CreateEnvironmentObject -EnvObject $parsedResponse
            }
        }
        # optionally the caller can choose to NOT wait until provisioning is complete and get the provisioning status by polling on Get-AdminPowerAppEnvironment and looking at the provisioning status field
        else
        {
            $response = InvokeApi -Method POST -Route $route -Body $requestBody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 202)
            {
                #Write-Error "An error occured."
                CreateHttpResponse($response)
            }
            else
            {
                CreateEnvironmentObject -EnvObject $response
            }
        }
    }
}


function Remove-LegacyCDSDatabase
{
    <#
    .SYNOPSIS
    This command is used for removing legacy (version 1.0) CDS database.
    .DESCRIPTION
    To make sure the database exist, the command tries to get the database first. Then delete the database and verify the database is deleted.
    .PARAMETER EnvironmentName
    This is the environment name (Guid) which has CDS 1.0 database to be removed.
    .PARAMETER DatabaseId
    This is the database id for the CDS 1.0 database to be removed.
    .EXAMPLE
    Remove-LegacyCDSDatabase -EnvironmentName '0e075c48-a792-4705-8f99-82eec3b1cd8e' -DatabaseId '80c75532-5cf7-4d27-b5ef-6ab9f9024ab6'
    #>
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory=$true)]
        [string]$DatabaseId
    )
    process
    {
        $deleteDatabaseUrl = "https://api.cds.microsoft.com/providers/Microsoft.CommonDataModel/namespaces/$DatabaseId`?api-version=2016-11-01&`$filter=environment eq '$EnvironmentName'"

        # Check if the database exist
        $getDatabaseRequest = Invoke-Request -Uri $deleteDatabaseUrl -Method "GET" -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        if ($getDatabaseRequest.StatusCode -eq 200)
        {
            $deleteDatabaseRequest = Invoke-Request -Uri $deleteDatabaseUrl -Method Delete -ThrowOnFailure -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            $getDatabaseRequest = Invoke-Request -Uri $deleteDatabaseUrl -Method "GET" -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            while ($getDatabaseRequest.StatusCode -ne 404)
            {
                Start-Sleep -s 3
                Write-Verbose "Waiting for operation to complete..."

                $getDatabaseRequest = Invoke-Request -Uri $deleteDatabaseUrl -Method "GET" -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            }

            Write-Verbose "Successfully removed database $DatabaseId"
        }
        elseif ($getDatabaseRequest.StatusCode -eq 404)
        {
            $deleteDatabaseRequest = $getDatabaseRequest
            Write-Verbose "Database $DatabaseId does not exist"
        }
        else
        {
            $deleteDatabaseRequest = $getDatabaseRequest
            Write-Verbose "Get database $DatabaseId fails"	
        }

        return $deleteDatabaseRequest
    }
}

function Get-AdminPowerAppEnvironment
{
    <#
    .SYNOPSIS
    Returns information about one or more PowerApps environments where the calling uses is an Environment Admin. If the calling user is a tenant admin, all envionments within the tenant will be returned.
    .DESCRIPTION
    The Get-AdminPowerAppEnvironment cmdlet looks up information about =one or more environments depending on parameters. 
    Use Get-Help Get-AdminPowerAppEnvironment -Examples for more detail.
    .PARAMETER Filter
    Finds environments matching the specified filter (wildcards supported).
    .PARAMETER EnvironmentName
    Finds a specific environment.
    .PARAMETER Default
    Finds the default environment.
    .PARAMETER CreatedBy
    Limit environments returned to only those created by the specified user (you can specify a email address or object id)
    .EXAMPLE
    Get-AdminPowerAppEnvironment
    Finds all environments within the tenant where the user is an Environment Admin.
    .EXAMPLE
    Get-AdminPowerAppEnvironment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Finds environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    .EXAMPLE
    Get-AdminPowerAppEnvironment *Test*
    Finds all environments that contain the string "Test" in their display name where the user is an Environment Admin.
    .EXAMPLE
    Get-AdminPowerAppEnvironment -CreatedBy 7557f390-5f70-4c93-8bc4-8c2faabd2ca0
    Finds all environments that were created by the user with an object of 7557f390-5f70-4c93-8bc4-8c2faabd2ca0
    #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "User")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$EnvironmentName,
        
        [Parameter(Mandatory = $false, ParameterSetName = "Default")]
        [Switch]$Default,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$CreatedBy,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2016-11-01",

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [bool]$ReturnCdsDatabaseType = $true
    )
    process
    {
        if ($Default)
        {
            $getEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/~default?`$expand=permissions&api-version={apiVersion}"
        
            $environmentResult = InvokeApi -Method GET -Route $getEnvironmentUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        
            CreateEnvironmentObject -EnvObject $environmentResult -ReturnCdsDatabaseType $ReturnCdsDatabaseType
        }
        elseif (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $getEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}?`$expand=permissions&api-version={apiVersion}" `
                | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;
        
            $environmentResult = InvokeApi -Method GET -Route $getEnvironmentUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        
            CreateEnvironmentObject -EnvObject $environmentResult -ReturnCdsDatabaseType $ReturnCdsDatabaseType
        }
        else
        {
            $getAllEnvironmentsUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?`$expand=permissions&api-version={apiVersion}"
        
            $environmentsResult = InvokeApi -Method GET -Route $getAllEnvironmentsUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        
            Get-FilteredEnvironments -Filter $Filter -CreatedBy $CreatedBy -EnvironmentResult $environmentsResult -ReturnCdsDatabaseType $ReturnCdsDatabaseType
        }
    }
}

function Get-AdminPowerAppSoftDeletedEnvironment
{
    <#
    .SYNOPSIS
    Returns information about one or more PowerApps environments which is soft-deleted. If the calling user is a tenant admin, all soft-deleted environments within the tenant will be returned.
    .DESCRIPTION
    The Get-AdminPowerAppSoftDeletedEnvironment cmdlet looks up information about one or more soft-deleted environments depending on parameters. 
    Use Get-Help Get-AdminPowerAppSoftDeletedEnvironment -Examples for more detail.
    .PARAMETER Filter
    Finds soft-deleted environments matching the specified filter (wildcards supported).
    .PARAMETER EnvironmentName
    Finds a specific soft-deleted environment.
    .EXAMPLE
    Get-AdminPowerAppSoftDeletedEnvironment
    Finds all soft-deleted environments within the tenant where the user is an Tenant Admin.
    .EXAMPLE
    Get-AdminPowerAppSoftDeletedEnvironment *Test*
    Finds all soft-deleted environments that contain the string "Test" in their display name where the user is an Tenant Admin.
    #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2019-05-01"
    )
    process
    {
        $getAllEnvironmentsUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/deletedEnvironments?`$expand=permissions&api-version={apiVersion}"
        
        $environmentsResult = InvokeApi -Method GET -Route $getAllEnvironmentsUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        
        Get-FilteredEnvironments -Filter $Filter -EnvironmentResult $environmentsResult
    }
}

function Remove-AdminPowerAppEnvironment
{
    <#
    .SYNOPSIS
    Deletes the specific environment.  This operation can take some time depending on how many resources are stored in the environment. If the operation returns witha  404 NotFound, then the environment has been successfully deleted.
    .DESCRIPTION
    Remove-AdminPowerAppEnvironment cmdlet deletes an environment. 
    Use Get-Help Remove-AdminPowerAppEnvironment -Examples for more detail.
    .PARAMETER Filter
    Finds environments matching the specified filter (wildcards supported).
    .EXAMPLE
    Remove-AdminPowerAppEnvironment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Deletes environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 and all of the environment's resources
    #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$EnvironmentName,


        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2018-01-01"
    )

    process
    {    
        $validateEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/validateDelete`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;

        $validateResponse = InvokeApi -Method POST -Route $validateEnvironmentUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        if (-not $validateResponse.canInitiateDelete)
        {
            #Write-Host "Unable to delete this environment."
            CreateHttpResponse($validateResponse)
        }
        else {

            $deleteEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}`?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;

            $resources = $validateResponse.Content.resourcesToBeDeleted | Group type
            #Write-Host "Deleting..."
            foreach ($type in $resources)
            {
                #Write-Host $type.Name: $type.Count
            }

            #Kick-off delete
            $deleteEnvironmentResponse = InvokeApiNoParseContent -Route $deleteEnvironmentUri -Method DELETE -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            $deleteStatusUrl = $deleteEnvironmentResponse.Headers['Location']

            #If there is no status Url then the environment likely does not exist
            if(!$deleteStatusUrl)
            {
                CreateHttpResponse($deleteEnvironmentResponse)     
            }
            else 
            {
                # Don't poll on delete

                # $currentTime = Get-Date -format HH:mm:ss
                # $nextTime = Get-Date -format HH:mm:ss
                # $TimeDiff = New-TimeSpan $currentTime $nextTime
                # $timeoutInSeconds = 300
        
                # #Wait until the environment has been deleted, there is an error, or we hit a timeout
                # while($deleteEnvironmentResponse.StatusCode -ne 404 -and $deleteEnvironmentResponse.StatusCode -ne 500 -and ($TimeDiff.TotalSeconds -lt $timeoutInSeconds))
                # {
                #     Start-Sleep -s 5
                #     $deleteEnvironmentResponse = InvokeApiNoParseContent -Route $deleteStatusUrl -Method GET -ApiVersion $ApiVersion
                #     $nextTime = Get-Date -format HH:mm:ss
                #     $TimeDiff = New-TimeSpan $currentTime $nextTime
                # }
                
                CreateHttpResponse($deleteEnvironmentResponse)   
            }
        }
    }
}

function Recover-AdminPowerAppEnvironment
{
    <#
    .SYNOPSIS
    Recovers the specific environment. This operation can take some time depending on how many resources are stored in the environment.
    .DESCRIPTION
    Recover-AdminPowerAppEnvironment cmdlet recovers an environment. 
    Use Get-Help Recover-AdminPowerAppEnvironment -Examples for more detail.
    .PARAMETER Filter
    Finds environments matching the specified filter (wildcards supported).
    .EXAMPLE
    Recover-AdminPowerAppEnvironment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Recovers environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 and all of the environment's resources
    #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [bool]$WaitUntilFinished = $false,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2019-05-01"
    )

    process
    {    
        $recoverEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/deletedEnvironments/{environmentName}/recover`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;

        #call recover api
        $recoverEnvironmentResponse = InvokeApiNoParseContent -Route $recoverEnvironmentUri -Method POST -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        $recoverStatusUrl = $recoverEnvironmentResponse.Headers['Location']

        #If there is no status Url then the environment likely does not exist
        if($recoverEnvironmentResponse.StatusCode -eq 202 -and $recoverStatusUrl -and $WaitUntilFinished)
        {
            $currentTime = Get-Date -format HH:mm:ss
            $nextTime = Get-Date -format HH:mm:ss
            $TimeDiff = New-TimeSpan $currentTime $nextTime
            $timeoutInSeconds = 300
        
            # Get operation status sometimes return 404 at beginning.
            while(($recoverEnvironmentResponse.StatusCode -eq 202 -or $recoverEnvironmentResponse.StatusCode -eq 404) -and ($TimeDiff.TotalSeconds -lt $timeoutInSeconds))
            {
                Start-Sleep -s 5
                $recoverEnvironmentResponse = InvokeApiNoParseContent -Method GET -Route $recoverStatusUrl -ApiVersion "2018-01-01"
                $nextTime = Get-Date -format HH:mm:ss
                $TimeDiff = New-TimeSpan $currentTime $nextTime
            }
        }

        CreateHttpResponse($recoverEnvironmentResponse)   
    }
}

function Get-AdminPowerAppEnvironmentRoleAssignment
{
    <#
    .SYNOPSIS
    Returns the environment role assignments for environments without a Common Data Service For Apps database instance.
    .DESCRIPTION
    The Get-AdminPowerAppEnvironmentRoleAssignment returns environment role assignments for environments with a Common Data Service For Apps database instance.  This includes which users are assigned as an Environment Admin or Environment Maker in each environment.
    Use Get-Help Get-AdminPowerAppEnvironmentRoleAssignment -Examples for more detail.
    .PARAMETER EnvironmentName
    Limit roles returned to those in a specified environment.
    .PARAMETER UserId
    A objectId of the user you want to filter by.
    .EXAMPLE
    Get-AdminPowerAppEnvironmentRoleAssignment
    Returns all environment role assignments across all environments. where the calling users is an Environment Admin.
    .EXAMPLE
    Get-AdminPowerAppEnvironmentRoleAssignment -UserId 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    Returns all environment role assignments across all environments (where the calling users is an Environment Admin) for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    .EXAMPLE
    Get-AdminPowerAppEnvironmentRoleAssignment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -UserId 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    Returns all environment role assignments for the environment  3c2f7648-ad60-4871-91cb-b77d7ef3c239  for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    .EXAMPLE
    Get-AdminPowerAppEnvironmentRoleAssignment  -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Returns all environment role assignments for the environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    #>
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $false, ParameterSetName = "Environment", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ParameterSetName = "Environment")]
        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$UserId,

        [Parameter(Mandatory = $false, ParameterSetName = "Environment")]
        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2016-11-01"
    )
    process
    {    

        $environments = @();

        if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $environments += @{
                EnvironmentName = $EnvironmentName
            }
        }
        else {
            $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false
        }

        foreach($environment in $environments)
        {                 
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/roleAssignments?api-version={apiVersion}" `
                | ReplaceMacro -Macro "{environmentName}" -Value $environment.EnvironmentName;
            
            $envRoleAssignmentResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            #Write-Host $envRoleAssignmentResult.StatusCode #Returns 'Forbidden' for CDS 2.0 orgs

            $pattern = BuildFilterPattern -Filter $UserId

            foreach ($envRole in $envRoleAssignmentResult.Value)
            {
                if ($pattern.IsMatch($envRole.properties.principal.id ) -or
                    $pattern.IsMatch($envRole.properties.principal.email))
                {
                    CreateEnvRoleAssignmentObject -EnvRoleAssignmentObj $envRole -EnvObj $environment
                }
            }
        }
    }
}

function Set-AdminPowerAppEnvironmentRoleAssignment
{
<#
 .SYNOPSIS
 Sets permissions to an environment without a Common Data Service For Apps database instance. If you make this call to an environment with a Common Data Service for Apps database instance you will get a 403 Forbidden error.
 .DESCRIPTION
 The Set-AdminPowerAppEnvironmentRoleAssignment set up permission to environment depending on parameters. 
 Use Get-Help Set-AdminPowerAppEnvironmentRoleAssignment -Examples for more detail.
 .PARAMETER EnvironmentName
 The environmnet id.
 .PARAMETER RoleName
 Specifies the permission level given to the environment: Environment Admin or Environment Maker.
 .PARAMETER PrincipalType
 Specifies the type of principal this environment is being shared with; a user, a security group, the entire tenant.
 .PARAMETER PrincipalObjectId
 If this environment is being shared with a user or security group principal, this field specified the ObjectId for that principal. You can use the Get-UsersOrGroupsFromGraph API to look-up the ObjectId for a user or group in Azure Active Directory.
 .EXAMPLE
 Set-AdminPowerAppEnvironmentRoleAssignment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -RoleName EnvironmentAdmin -PrincipalType User -PrincipalObjectId 53c0a918-ce7c-401e-98f9-1c60b3a723b3
 Assigns the Environment Admin role privileges to the the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3 in the environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239  
 .EXAMPLE
 Set-AdminPowerAppEnvironmentRoleAssignment -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -RoleName EnvironmentMaker -PrincipalType Tenant
 Assigns everyone Environment Maker role privileges in the environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239  
 #>
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("EnvironmentAdmin", "EnvironmentMaker")]
        [string]$RoleName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("User", "Group", "Tenant")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [string]$ApiVersion = "2016-11-01"
    )
        
    process 
    {
        $TenantId = $Global:currentSession.tenantId

        if($PrincipalType -ne "Tenant") 
        {
            $userOrGroup = Get-UsersOrGroupsFromGraph -ObjectId $PrincipalObjectId
            $PrincipalEmail = $userOrGroup.Mail
        }

        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environment}/modifyRoleAssignments`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null

        If ($PrincipalType -eq "Tenant")
        {
            $requestbody = @{ 
                add = @(
                    @{ 
                        properties = @{
                            roleDefinition = @{
                                id = "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/$EnvironmentName/roleDefinitions/$RoleName"
                            }      
                            principal = @{
                                email = ""
                                id = $PrincipalObjectId
                                type = $PrincipalType
                                tenantId = $TenantId
                            }          
                        }
                    }
                )
            }
        }
        else
        {
            $requestbody = @{ 
                add = @(
                    @{ 
                        properties = @{
                            roleDefinition = @{
                                id = "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/$EnvironmentName/roleDefinitions/$RoleName"
                            }      
                            principal = @{
                                email = $PrincipalEmail
                                id = $PrincipalObjectId
                                type = $PrincipalType
                                tenantId = "null"
                            }          
                        }
                    }
                )
            }
        }

        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}

function Remove-AdminPowerAppEnvironmentRoleAssignment
{
<#
 .SYNOPSIS
 Deletes specific role assignment of an environment.
 .DESCRIPTION
 Deletes specific role assignment of an environment.
 Use Get-Help Remove-AdminPowerAppEnvironmentRoleAssignment -Examples for more detail.
 .PARAMETER EnvironmentName
 The environment id
 .PARAMETER RoleId
 Specifies the role assignment id.
 .EXAMPLE
 Remove-AdminPowerAppEnvironmentRoleAssignment -RoleId "4d1f7648-ad60-4871-91cb-b77d7ef3c239" -EnvironmentName "Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877"
 Deletes the role named 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in Environment Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
 #>
    [CmdletBinding(DefaultParameterSetName="App")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ParameterSetName = "App")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environment}/modifyRoleAssignments`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            #Construct the body 
        $requestbody = $null
        
        $requestbody = @{ 
            remove = @(
                @{ 
                    id = $RoleId
                }
            )
        }


        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}

function Get-AdminPowerAppConnection
{
 <#
 .SYNOPSIS
 Returns information about one or more connection.
 .DESCRIPTION
 The Get-AdminPowerAppConnection looks up information about one or more connections depending on parameters. 
 Use Get-Help Get-AdminPowerAppConnection -Examples for more detail.
 .PARAMETER Filter
 Finds connection matching the specified filter (wildcards supported).
 .PARAMETER ConnectorName
 Limit connections returned to those of a specified connector.
 .PARAMETER EnvironmentName
 Limit connections returned to those in a specified environment.
 .PARAMETER CreatedBy
 Limit connections returned to those created by by the specified user (email or AAD object id)
 .EXAMPLE
 Get-AdminPowerAppConnection
 Returns all connection from all environments where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
 .EXAMPLE
 Get-AdminPowerAppConnection *PowerApps*
 Returns all connection with the text "PowerApps" in the display namefrom all environments where the calling user is an Environment Admin  For Global admins, this will search across all environments in the tenant.
  .EXAMPLE
 Get-AdminPowerAppConnection -CreatedBy foo@bar.onmicrosoft.com
 Returns all apps created by the user with an email of "foo@bar.onmicrosoft.com" from all environment where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
  .EXAMPLE
 Get-AdminPowerAppConnection -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds connections within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment
  .EXAMPLE
 Get-AdminPowerAppConnection -ConnectorName shared_runtimeservice
 Finds all connections created against the shared_runtimeservice (CDS) connector from all environments where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
  .EXAMPLE
 Get-AdminPowerAppConnection -ConnectorName shared_runtimeservice -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds connections within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment that are created against the shared_runtimeservice (CDS) connector.
 .EXAMPLE
 Get-AdminPowerAppConnection *Foobar* -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 
 Finds all connections in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 that contain the string "Foobar" in their display name.
 #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "User")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = "Connector", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Connector", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$CreatedBy,

        [Parameter(Mandatory = $false, ParameterSetName = "Connector")]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        # If the connector name is specified, only return connections for that connector
        if (-not [string]::IsNullOrWhiteSpace($ConnectorName))
        {
            $environments = @();
 
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $environments += @{
                    EnvironmentName = $EnvironmentName
                }
            }
            else 
            {
                $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false
            }

            foreach($environment in $environments)
            {
                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connectorName}/connections?api-version={apiVersion}" `
                | ReplaceMacro -Macro "{connectorName}" -Value $ConnectorName `
                | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName;

                $connectionResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                Get-FilteredConnections -Filter $Filter -CreatedBy $CreatedBy -ConnectionResult $connectionResult
            }
        }
        else
        {
            # If the caller passed in an environment scope, filter the query to only that environment 
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/connections?api-version={apiVersion}" `
                | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;    

                $connectionResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                Get-FilteredConnections -Filter $Filter -CreatedBy $CreatedBy -ConnectionResult $connectionResult
            }
            # otherwise search for the apps acroos all environments for this calling user
            else 
            {
                $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false

                foreach($environment in $environments)
                {
                    $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/connections?api-version={apiVersion}" `
                    | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName;    
    
                    $connectionResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    
                    Get-FilteredConnections -Filter $Filter -CreatedBy $CreatedBy -ConnectionResult $connectionResult
                }
            }
        }
    }
}


function Remove-AdminPowerAppConnection
{
 <#
 .SYNOPSIS
 Deletes the connection.
 .DESCRIPTION
 The Remove-AdminPowerAppConnection permanently deletes the connection. 
 Use Get-Help Remove-AdminPowerAppConnection -Examples for more detail.
 .PARAMETER ConnectionName
 The connection identifier.
 .PARAMETER ConnectorName
 The connection's connector name.
 .PARAMETER EnvironmentName
 The connection's environment.
 .EXAMPLE
 Remove-AdminPowerAppConnection -ConnectionName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -ConnectorName shared_twitter -EnvironmentName Default-efecdc9a-c859-42fd-b215-dc9c314594dd
 Deletes the connection with name 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$ConnectionName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connector}/connections/{connection}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        $removeResult = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}

function Get-AdminPowerAppConnectionRoleAssignment
{
 <#
 .SYNOPSIS
 Returns the connection role assignments for a user or a connection. Owner role assignments cannot be deleted without deleting the connection resource.
 .DESCRIPTION
 The Get-AdminPowerAppConnectionRoleAssignment functions returns all roles assignments for an connection or all connection roles assignments for a user (across all of their connections).  A connection's role assignments determine which users have access to the connection for using or building apps and flows and with which permission level (CanUse, CanUseAndShare) . 
 Use Get-Help Get-AdminPowerAppConnectionRoleAssignment -Examples for more detail.
 .PARAMETER ConnectionName
 The connection identifier.
 .PARAMETER EnvironmentName
 The connections's environment. 
 .PARAMETER ConnectorName
 The connection's connector identifier.
 .PARAMETER PrincipalObjectId
 The objectId of a user or group, if specified, this function will only return role assignments for that user or group.
 .EXAMPLE
 Get-AdminPowerAppConnectionRoleAssignment
 Returns all connection role assignments for the calling user.
 .EXAMPLE
 Get-AdminPowerAppConnectionRoleAssignment -ConnectionName 3b4b9592607147258a4f2fb33517e97a -ConnectorName shared_sharepointonline -EnvironmentName ee1eef10-ba55-440b-a009-ce379f86e20c
 Returns all role assignments for the connection with name 3b4b9592607147258a4f2fb33517e97ain environment with name ee1eef10-ba55-440b-a009-ce379f86e20c for the connector named shared_sharepointonline
 .EXAMPLE
 Get-AdminPowerAppConnectionRoleAssignment -ConnectionName 3b4b9592607147258a4f2fb33517e97a -ConnectorName shared_sharepointonline -EnvironmentName ee1eef10-ba55-440b-a009-ce379f86e20c -PrincipalObjectId 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns all role assignments for the user, or group with an object of 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the connection with name 3b4b9592607147258a4f2fb33517e97ain environment with name ee1eef10-ba55-440b-a009-ce379f86e20c for the connector named shared_sharepointonline
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectionName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $selectedObjectId = $null

        if (-not [string]::IsNullOrWhiteSpace($ConnectionName))
        {
            if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
            {
                $selectedObjectId = $PrincipalObjectId;
            }
        }

        $pattern = BuildFilterPattern -Filter $selectedObjectId

        if (-not [string]::IsNullOrWhiteSpace($ConnectionName))
        {

            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connector}/connections/{connection}/permissions?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
            | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $connectionRoleResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            foreach ($connectionRole in $connectionRoleResult.Value)
            {
                if (-not [string]::IsNullOrWhiteSpace($PrincipalObjectId))
                {
                    if ($pattern.IsMatch($connectionRole.properties.principal.id ) -or
                        $pattern.IsMatch($connectionRole.properties.principal.email) -or 
                        $pattern.IsMatch($connectionRole.properties.principal.tenantId))
                    {
                        CreateConnectionRoleAssignmentObject -ConnectionRoleAssignmentObj $connectionRole -EnvironmentName $EnvironmentName
                    }
                }
                else 
                {    
                    CreateConnectionRoleAssignmentObject -ConnectionRoleAssignmentObj $connectionRole -EnvironmentName $EnvironmentName
                }
            }
        }
        else 
        {
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $connections = Get-AdminPowerAppConnection -EnvironmentName $EnvironmentName -ConnectorName $ConnectorName -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            }
            else 
            {
                $connections = Get-AdminPowerAppConnection -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            }

            foreach($connection in $connections)
            {
                Get-AdminPowerAppConnectionRoleAssignment `
                    -ConnectionName $connection.ConnectionName `
                    -ConnectorName $connection.ConnectorName `
                    -EnvironmentName $connection.EnvironmentName `
                    -PrincipalObjectId $selectedObjectId `
                    -ApiVersion $ApiVersion `
					-Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            }
        }
    }
}

function Set-AdminPowerAppConnectionRoleAssignment
{
    <#
    .SYNOPSIS
    Sets permissions to the connection.
    .DESCRIPTION
    The Set-AdminPowerAppConnectionRoleAssignment set up permission to connection depending on parameters. 
    Use Get-Help Set-AdminPowerAppConnectionRoleAssignment -Examples for more detail.
    .PARAMETER ConnectionName
    The connection identifier.
    .PARAMETER EnvironmentName
    The connections's environment. 
    .PARAMETER ConnectorName
    The connection's connector identifier.
    .PARAMETER RoleName
    Specifies the permission level given to the connection: CanView, CanViewWithShare, CanEdit. Sharing with the entire tenant is only supported for CanView.
    .PARAMETER PrincipalType
    Specifies the type of principal this connection is being shared with; a user, a security group, the entire tenant.
    .PARAMETER PrincipalObjectId
    If this connection is being shared with a user or security group principal, this field specified the ObjectId for that principal. You can use the Get-UsersOrGroupsFromGraph API to look-up the ObjectId for a user or group in Azure Active Directory.
    .EXAMPLE
    Set-AdminPowerAppConnectionRoleAssignment -PrincipalType Group -PrincipalObjectId b049bf12-d56d-4b50-8176-c6560cbd35aa -RoleName CanEdit -ConnectionName 3b4b9592607147258a4f2fb33517e97a -ConnectorName shared_vsts -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
    Give the specified security group CanEdit permissions to the connection with name 3b4b9592607147258a4f2fb33517e97a
    #> 
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectionName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("CanView", "CanViewWithShare", "CanEdit")]
        [string]$RoleName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("User", "Group", "Tenant")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $TenantId = $Global:currentSession.tenantId

        # if($PrincipalType -ne "Tenant") 
        # {
        #     $userOrGroup = Get-UsersOrGroupsFromGraph -ObjectId $PrincipalObjectId
        #     $PrincipalEmail = $userOrGroup.Mail
        # }

        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connector}/connections/{connection}/modifyPermissions?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null

        If ($PrincipalType -eq "Tenant")
        {
            $requestbody = @{ 
                delete = @()
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            principal = @{
                                id = $TenantId
                                tenantId = $TenantId
                            }          
                        }
                    }
                )
            }
        }
        else
        {
            $requestbody = @{ 
                delete = @()
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            principal = @{
                                id = $PrincipalObjectId
                            }               
                        }
                    }
                )
            }
        }
        
        $setConnectionRoleResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($setConnectionRoleResult)
    }
}

function Remove-AdminPowerAppConnectionRoleAssignment
{
 <#
 .SYNOPSIS
 Deletes a connection role assignment record.
 .DESCRIPTION
 The Remove-AdminPowerAppConnectionRoleAssignment deletes the specific connection role assignment
 Use Get-Help Remove-AdminPowerAppConnectionRoleAssignment -Examples for more detail.
 .PARAMETER RoleId
 The id of the role assignment to be deleted.
 .PARAMETER ConnectionName
 The app identifier.
 .PARAMETER ConnectorName
 The connection's associated connector name
 .PARAMETER EnvironmentName
 The connection's environment. 
 .EXAMPLE
 Remove-AdminPowerAppConnectionRoleAssignment -ConnectionName a2956cf95ba441119d16dc2ef0ca1ff9 -EnvironmentName 08b4e32a-4e0d-4a69-97da-e1640f0eb7b9 -ConnectorName shared_twitter -RoleId /providers/Microsoft.PowerApps/apis/shared_twitter/connections/a2956cf95ba441119d16dc2ef0ca1ff9/permissions/7557f390-5f70-4c93-8bc4-8c2faabd2ca0
 Deletes the app role assignment with an id of /providers/Microsoft.PowerApps/apps/f8d7a19d-f8f9-4e10-8e62-eb8c518a2eb4/permissions/tenant-efecdc9a-c859-42fd-b215-dc9c314594dd
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectionName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$ConnectorName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2017-06-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apis/{connector}/connections/{connection}/modifyPermissions`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{connector}" -Value $ConnectorName `
        | ReplaceMacro -Macro "{connection}" -Value $ConnectionName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null
        
        $requestbody = @{ 
            delete = @(
                @{ 
                    id = $RoleId
                }
            )
        }
    
        $removeResult = InvokeApi -Method POST -Body $requestbody -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        If($removeResult -eq $null)
        {
            return $null
        }
        
        CreateHttpResponse($removeResult)
    }
}


function Get-AdminPowerApp
{
 <#
 .SYNOPSIS
 Returns information about one or more apps.
 .DESCRIPTION
 The Get-AdminPowerApp looks up information about one or more apps depending on parameters. 
 Use Get-Help Get-AdminPowerApp -Examples for more detail.
 .PARAMETER Filter
 Finds apps matching the specified filter (wildcards supported).
 .PARAMETER AppName
 Finds a specific id.
 .PARAMETER EnvironmentName
 Limit apps returned to those in a specified environment.
 .PARAMETER Owner
 Limit apps returned to those owned by the specified user (you can specify a email address or object id)
 .EXAMPLE
 Get-AdminPowerApp 
 Returns all apps from all environments where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
 .EXAMPLE
 Get-AdminPowerApp *PowerApps*
 Returns all apps with the text "PowerApps" from all environments where the calling user is an Environment Admin  For Global admins, this will search across all environments in the tenant.
  .EXAMPLE
 Get-AdminPowerApp -CreatedBy foo@bar.onmicrosoft.com
 Returns all apps created by the user with an email of "foo@bar.onmicrosoft.com" from all environment where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
  .EXAMPLE
 Get-AdminPowerApp -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds apps within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment
 .EXAMPLE
 Get-AdminPowerApp *Foobar* -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 
 Finds all app in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 that contain the string "Foobar" in their display name.
 .EXAMPLE
 Get-AdminPowerApp -AppName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns the details for the app named 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in Environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "User")]
        [string[]]$Filter,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$Owner,

        [Parameter(Mandatory = $false, ParameterSetName = "App")]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        # If the app name is specified, just return the details for that app
        if (-not [string]::IsNullOrWhiteSpace($AppName))
        {
            $top = 250
            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps/{appName}?api-version={apiVersion}&top={top}&`$expand=unpublishedAppDefinition" `
            | ReplaceMacro -Macro "{appName}" -Value $AppName `
            | ReplaceMacro -Macro "{top}" -Value $top `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $appResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            CreateAppObject -AppObj $appResult;
        }
        else
        {
            $userId = $Global:currentSession.userId
            $expandPermissions = "permissions(`$filter=maxAssignedTo(`'$userId`'))"

            # If the caller passed in an environment scope, filter the query to only that environment 
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $top = 250
                
                $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps?api-version={apiVersion}&`$expand={expandPermissions}" `
                | ReplaceMacro -Macro "{expandPermissions}" -Value $expandPermissions `
                | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

                $appResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                Get-FilteredApps -Filter $Filter -Owner $Owner -AppResult $appResult
            }
            # otherwise search for the apps across all environments for this calling user
            else 
            {
                $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false

                foreach($environment in $environments)
                {
                    $top = 250
                
                    $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps?api-version={apiVersion}&`$expand={expandPermissions}" `
                    | ReplaceMacro -Macro "{expandPermissions}" -Value $expandPermissions `
                    | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName;

                    $appResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                    Get-FilteredApps -Filter $Filter -Owner $Owner -AppResult $appResult                    
                }
            }
        }
    }
}

function Remove-AdminPowerApp
{
<#
 .SYNOPSIS
 Deletes an app.
 .DESCRIPTION
 The Delete-AdminPowerApp deletes an app. 
 Use Delete-Help Get-AdminPowerApp -Examples for more detail.
 .PARAMETER AppName
 Specifies the app id.
 .PARAMETER EnvironmentName
 Limit apps returned to those in a specified environment.
 Delete-AdminPowerApp -AppName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Deletes the app named 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in Environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="App")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "App")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps/{appName}?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        $result = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }            
}

function Get-AdminPowerAppRoleAssignment
{
<#
 .SYNOPSIS
 Returns permission information about one or more apps.
 .DESCRIPTION
 The Get-AdminPowerAppRoleAssignment returns permission information about one or more apps.
 Use Get-Help Get-AdminPowerAppRoleAssignment -Examples for more detail.
 .PARAMETER AppName
 Finds a specific id.
 .PARAMETER EnvironmentName
 Limit apps returned to those in a specified environment.
 .PARAMETER UserId
 A objectId of the user you want to filter by.
 .EXAMPLE
 Get-AdminPowerAppRoleAssignments -UserId 53c0a918-ce7c-401e-98f9-1c60b3a723b3
 Returns all app role assignments across all environments for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
 .EXAMPLE
 Get-AdminPowerAppRoleAssignments -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -UserId 53c0a918-ce7c-401e-98f9-1c60b3a723b3
 Returns all app role assignemtns within environment with id 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
 .EXAMPLE
 Get-AdminPowerAppRoleAssignments -AppName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -UserId 53c0a918-ce7c-401e-98f9-1c60b3a723b3
 Returns all role assignments for the app with id 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
 .EXAMPLE
 Get-AdminPowerAppRoleAssignments -AppName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns all role assignments for the app with id 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Environment", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "App")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [Parameter(Mandatory = $true, ParameterSetName = "Environment")]
        [string]$UserId,

        [Parameter(Mandatory = $false, ParameterSetName = "App")]
        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Environment")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        if (-not [string]::IsNullOrWhiteSpace($AppName))
        {
            $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps/{appName}/permissions?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
            | ReplaceMacro -Macro "{appName}" -Value $AppName `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $appRoleAssignmentResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            $pattern = BuildFilterPattern -Filter $UserId

            foreach ($appRole in $appRoleAssignmentResult.Value)
            {
                if ($pattern.IsMatch($appRole.properties.principal.id ) -or
                    $pattern.IsMatch($appRole.properties.principal.email))
                {
                    CreateAppRoleAssignmentObject -AppRoleAssignmentObj $appRole
                }
            }
        }
        else
        {
            $environments = @();
 
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $environments += @{
                    EnvironmentName = $EnvironmentName
                }
            }
            else {
                $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false
            }

            foreach($environment in $environments)
            {                        
                $appResult = Get-AdminPowerApp -EnvironmentName $environment.EnvironmentName
    
                foreach ($app in $appResult)
                {
                    $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps/{appName}/permissions?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
                    | ReplaceMacro -Macro "{appName}" -Value $app.AppName `
                    | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName;
                    
                    $appRoleAssignmentResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                    $pattern = BuildFilterPattern -Filter $UserId

                    foreach ($appRole in $appRoleAssignmentResult.Value)
                    {
                        if ($pattern.IsMatch($appRole.properties.principal.id ) -or
                            $pattern.IsMatch($appRole.properties.principal.email))
                        {
                            CreateAppRoleAssignmentObject -AppRoleAssignmentObj $appRole
                        }
                    }
                }
            }
        }
    }
}

function Remove-AdminPowerAppRoleAssignment
{
<#
 .SYNOPSIS
 Deletes specific role of an app.
 .DESCRIPTION
 Deletes specific role of an app.
 Use Get-Help Remove-AdminPowerAppRoleAssignment -Examples for more detail.
 .PARAMETER AppName
 Specifies the app id.
 .PARAMETER EnvironmentName
 Limit apps returned to those in a specified environment.
 .PARAMETER RoleId
 Specifies the role assignment id.
 Remove-AdminPowerAppRoleAssignment -RoleId "4d1f7648-ad60-4871-91cb-b77d7ef3c239" -EnvironmentName "Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877" -AppName "73691d1f-0ff5-442c-87ce-1e3e2fba58dc"
 Deletes the role named 4d1f7648-ad60-4871-91cb-b77d7ef3c239 for app id 73691d1f-0ff5-442c-87ce-1e3e2fba58dc in Environment Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
 #>
    [CmdletBinding(DefaultParameterSetName="App")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "App")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps/{appName}/modifyPermissions?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

            #Construct the body 
        $requestbody = $null
    
        $requestbody = @{ 
            delete = @(
                @{ 
                    id = $RoleId
                 }
             )
             }

        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}

function Set-AdminPowerAppRoleAssignment
{
<#
 .SYNOPSIS
 sets permissions to the app.
 .DESCRIPTION
 The Set-AdminPowerAppRoleAssignment set up permission to app depending on parameters. 
 Use Get-Help Set-AdminPowerAppRoleAssignment -Examples for more detail.
 .PARAMETER AppName
 App name for the one which you want to set permission.
 .PARAMETER EnvironmentName
 Limit app returned to those in a specified environment.
 .PARAMETER RoleName
 Specifies the permission level given to the app: CanView, CanViewWithShare, CanEdit. Sharing with the entire tenant is only supported for CanView.
 .PARAMETER PrincipalType
 Specifies the type of principal this app is being shared with; a user, a security group, the entire tenant.
 .PARAMETER PrincipalObjectId
 If this app is being shared with a user or security group principal, this field specified the ObjectId for that principal. You can use the Get-UsersOrGroupsFromGraph API to look-up the ObjectId for a user or group in Azure Active Directory.
 .EXAMPLE
 Set-AdminPowerAppRoleAssignment -PrincipalType Group -PrincipalObjectId b049bf12-d56d-4b50-8176-c6560cbd35aa -RoleName CanEdit -AppName 1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488 -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
 Give the specified security group CanEdit permissions to the app with name 1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488 
 #> 
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [ValidateSet("CanView", "CanViewWithShare", "CanEdit")]
        [string]$RoleName,

        [Parameter(Mandatory = $true, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [ValidateSet("User", "Group", "Tenant")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Tenant")]
        [string]$ApiVersion = "2016-11-01"
    )
        
    process 
    {
        $TenantId = $Global:currentSession.tenantId

        if($PrincipalType -ne "Tenant") 
        {
            $userOrGroup = Get-UsersOrGroupsFromGraph -ObjectId $PrincipalObjectId
            $PrincipalEmail = $userOrGroup.Mail
        }

        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps/{appName}/modifyPermissions`?api-version={apiVersion}&`$filter=environment%20eq%20'{environment}'" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName `
        | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

        #Construct the body 
        $requestbody = $null

        If ($PrincipalType -eq "Tenant")
        {
            $requestbody = @{ 
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            capabilities = @()
                            NotifyShareTargetOption = "Notify"
                            principal = @{
                                email = ""
                                id = "null"
                                type = $PrincipalType
                                tenantId = $TenantId
                            }          
                        }
                    }
                )
            }
        }
        else
        {
            $requestbody = @{ 
                put = @(
                    @{ 
                        properties = @{
                            roleName = $RoleName
                            capabilities = @()
                            NotifyShareTargetOption = "Notify"
                            principal = @{
                                email = $PrincipalEmail
                                id = $PrincipalObjectId
                                type = $PrincipalType
                                tenantId = "null"
                            }               
                        }
                    }
                )
            }
        }

        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}

function Set-AdminPowerAppOwner
{
<#
 .SYNOPSIS
 Sets the app owner and changes the current owner to "Can View" role type.
 .DESCRIPTION
 The Set-AppOwner Sets the app owner and changes the current owner to "Can View" role type. 
 Use Get-Help Set-AppOwner -Examples for more detail.
 .PARAMETER AppName
 App name for the one which you want to set permission.
 .PARAMETER EnvironmentName
 Limit app returned to those in a specified environment.
 .PARAMETER AppOwner
 Id of new owner which you want to set.
 .EXAMPLE
 Set-AppOwner -AppName "73691d1f-0ff5-442c-87ce-1e3e2fba58dc" -EnvironmentName "Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877" -AppOwner "1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488"
 Sets the app owner to "1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488" and changes the current owner to "Can View" role type.
 #>
    [CmdletBinding(DefaultParameterSetName="App")]
    param
    (
        [Parameter(Mandatory = $false, ParameterSetName = "App")]
        [string]$ApiVersion = "2016-11-01",

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$AppName,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "App")]
        [string]$AppOwner
    )
        
    process 
    {

        $route = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/scopes/admin/environments/{environment}/apps/{appName}/modifyAppOwner?api-version={apiVersion}"`
        | ReplaceMacro -Macro "{appName}" -Value $AppName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        #Construct the body 
        $requestbody = $null

        $requestbody =
                @{ 
                    newAppOwner = $AppOwner
                    roleForOldAppOwner = "CanView"
                    }

        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)

    }
}

function Get-AdminFlow
{
<#
 .SYNOPSIS
 Returns information about one or more flows.
 .DESCRIPTION
 The Get-AdminFlow looks up information about one or more flows depending on parameters. 
 Use Get-Help Get-AdminFlow -Examples for more detail.
 .PARAMETER Filter
 Finds flows matching the specified filter (wildcards supported).
 .PARAMETER FlowName
 Finds a specific id.
 .PARAMETER EnvironmentName
 Limit flows returned to those in a specified environment.
 .PARAMETER CreatedBy
 Limit flows returned to those created by the specified user (you must specify a user's object id)
  .EXAMPLE
 Get-AdminFlow 
 Returns all flow from all environments where the current user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
 .EXAMPLE
 Get-AdminFlow -CreatedBy dbfad833-1e1e-4665-a20c-96391a1a39f0
 Returns all apps created by the user with an object of "dbfad833-1e1e-4665-a20c-96391a1a39f0" from all environment where the calling user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
 .EXAMPLE
 Get-AdminFlow *Flows*
 Returns all flows with the text "Flows" from all environments where the current user is an Environment Admin.  For Global admins, this will search across all environments in the tenant.
 .EXAMPLE
 Get-AdminFlow -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds flows within the 3c2f7648-ad60-4871-91cb-b77d7ef3c239 environment
 .EXAMPLE
 Get-AdminFlow *Foobar* -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 
 Finds all flows in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 that contain the string "Foobar" in their display name.
 .EXAMPLE
 Get-AdminFlow -FlowName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Returns the details for the flow named 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in Environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter")]
        [string[]]$Filter,

        [Parameter(Mandatory = $false, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "App", ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$CreatedBy,

        [Parameter(Mandatory = $false, ParameterSetName = "App")]
        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2016-11-01"
    )

    process 
    {
        if (-not [string]::IsNullOrWhiteSpace($FlowName))
        {
            $top = 50
            $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
            | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

            $flowResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            CreateFlowObject -FlowObj $flowResult;
        }
        else
        {
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $top = 50
                
                $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows?api-version={apiVersion}&top={top}" `
                | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName `
                | ReplaceMacro -Macro "{top}" -Value $top;

                $flowResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                Get-FilteredFlows -Filter $Filter -CreatedBy $CreatedBy -FlowResult $flowResult
            }
            else {
                $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false

                foreach($environment in $environments)
                {
                    $top = 50
                
                    $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows?api-version={apiVersion}&top={top}" `
                    | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName `
                    | ReplaceMacro -Macro "{top}" -Value $top;

                    $flowResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                    Get-FilteredFlows -Filter $Filter -CreatedBy $CreatedBy -FlowResult $flowResult
                }
            }
        }
    }
}


function Enable-AdminFlow 
{
<#
 .SYNOPSIS
 Starts the specific flow.
 .DESCRIPTION
 The Enable-AdminFlow starts the specific flow.
 Use Delete-Help Enable-AdminFlow -Examples for more detail.
 .PARAMETER FlowName
 Specifies the flow id.
 .PARAMETER EnvironmentName
 Limit apps returned to those in a specified environment.
 Enable-AdminFlow -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877 -FlowName 4d1f7648-ad60-4871-91cb-b77d7ef3c239
 Starts the 4d1f7648-ad60-4871-91cb-b77d7ef3c239 flow in environment "Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877"
 #>
    [CmdletBinding(DefaultParameterSetName="Flow")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Flow", ValueFromPipelineByPropertyName = $true)]
        [string] $EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Flow", ValueFromPipelineByPropertyName = $true)]
        [string] $FlowName,

        [Parameter(Mandatory = $false, ParameterSetName = "Flow")]
        [string] $ApiVersion = "2016-11-01"
    )
    process 
    {
        if ($ApiVersion -eq $null -or $ApiVersion -eq "")
        {
            Write-Error "Api Version must be set."
            throw
        }

        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}/start?api-version={apiVersion}"`
        | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        $result = InvokeApi -Method POST -Route $route -Body @{} -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}

function Disable-AdminFlow 
{
<#
 .SYNOPSIS
 Stops the specific flow.
 .DESCRIPTION
 The Disable-AdminFlow stops the specific flow.
 Use Delete-Help Disable-AdminFlow -Examples for more detail.
 .PARAMETER FlowName
 Specifies the flow id.
 .PARAMETER EnvironmentName
 Limit apps returned to those in a specified environment.
 Disable-AdminFlow -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877 -FlowName 4d1f7648-ad60-4871-91cb-b77d7ef3c239
 Stops the 4d1f7648-ad60-4871-91cb-b77d7ef3c239 flow in environment "Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877"
 #>
    [CmdletBinding(DefaultParameterSetName="Flow")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Flow", ValueFromPipelineByPropertyName = $true)]
        [string] $EnvironmentName,


        [Parameter(Mandatory = $true, ParameterSetName = "Flow", ValueFromPipelineByPropertyName = $true)]
        [string] $FlowName,

        [Parameter(Mandatory = $false, ParameterSetName = "Flow")]
        [string] $ApiVersion = "2016-11-01"
    )
    process 
    {
        if ($ApiVersion -eq $null -or $ApiVersion -eq "")
        {
            Write-Error "Api Version must be set."
            throw
        }

        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}/stop?api-version={apiVersion}"`
        | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        $result = InvokeApi -Method POST -Route $route -Body @{} -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}

function Remove-AdminFlow 
{
<#
 .SYNOPSIS
 Delete the specific flow.
 .DESCRIPTION
 The Remove-AdminFlow deletes the specific flow.
 Use Delete-Help Remove-AdminFlow -Examples for more detail.
 .PARAMETER FlowName
 Specifies the flow id.
 .PARAMETER EnvironmentName
 Limit apps returned to those in a specified environment.
 Remove-AdminFlow -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877 -FlowName 4d1f7648-ad60-4871-91cb-b77d7ef3c239
 Deletes the 4d1f7648-ad60-4871-91cb-b77d7ef3c239 flow in environment "Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877"
 #>
    [CmdletBinding(DefaultParameterSetName="Flow")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Flow", ValueFromPipelineByPropertyName = $true)]
        [string] $EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Flow", ValueFromPipelineByPropertyName = $true)]
        [string] $FlowName,

        [Parameter(Mandatory = $false, ParameterSetName = "Flow")]
        [string] $ApiVersion = "2016-11-01"
    )
    process 
    {
        if ($ApiVersion -eq $null -or $ApiVersion -eq "")
        {
            Write-Error "Api Version must be set."
            throw
        }

        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}?api-version={apiVersion}"`
        | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        $result = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}

function Set-AdminFlowOwnerRole
{
<#
 .SYNOPSIS
 sets owner permissions to the flow.
 .DESCRIPTION
 The Set-AdminFlowOwnerRole set up permission to flow depending on parameters. 
 Use Get-Help Set-AdminFlowOwnerRole -Examples for more detail.
 .PARAMETER EnvironmentName
 Limit app returned to those in a specified environment.
 .PARAMETER FlowName
 Specifies the flow id.
 .PARAMETER RoleName
 Specifies the access level for the user on the flow; CanView or CanEdit
 .PARAMETER PrincipalType
 Specifies the type of principal that is being added as an owner; User or Group (security group)
 .PARAMETER PrincipalObjectId
 Specifies the principal object Id of the user or security group.
 .EXAMPLE
 Set-AdminFlowOwnerRole -PrincipalType Group -PrincipalObjectId b049bf12-d56d-4b50-8176-c6560cbd35aa -RoleName CanEdit -FlowName 1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488 -EnvironmentName Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877
 Add the specified security group as an owner fo the flow with name 1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488 
 #> 
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [ValidateSet("User", "Group")]
        [string]$PrincipalType,

        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [ValidateSet("CanView", "CanEdit")]
        [string]$RoleName,

        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [string]$PrincipalObjectId = $null,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2016-11-01"
    )
        
    process 
    {
        $userOrGroup = Get-UsersOrGroupsFromGraph -ObjectId $PrincipalObjectId
        $PrincipalDisplayName = $userOrGroup.DisplayName
        $PrincipalEmail = $userOrGroup.Mail

        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}/modifyPermissions?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        #Construct the body 
        $requestbody = $null

        $requestbody = @{ 
            put = @(
                @{ 
                    properties = @{
                        principal = @{
                            email = $PrincipalEmail
                            id = $PrincipalObjectId
                            type = $PrincipalType
                            displayName = $PrincipalDisplayName
                        }         
                        roleName = $RoleName      
                    }
                }
            )
        }

        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}

function Remove-AdminFlowOwnerRole
{
<#
 .SYNOPSIS
 Removes owner permissions to the flow.
 .DESCRIPTION
 The Remove-AdminFlowOwnerRole sets up permission to flow depending on parameters. 
 Use Get-Help Remove-AdminFlowOwnerRole -Examples for more detail.
 .PARAMETER EnvironmentName
 The environment of the flow.
 .PARAMETER FlowName
 Specifies the flow id.
 .PARAMETER RoleId
 Specifies the role id of user or group or tenant.
 .EXAMPLE
 Remove-AdminFlowOwnerRole -EnvironmentName "Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877" -FlowName $flow.FlowName -RoleId "/providers/Microsoft.ProcessSimple/environments/Default-55abc7e5-2812-4d73-9d2f-8d9017f8c877/flows/791fc889-b9cc-4a76-9795-ae45f75d3e48/permissions/1ec3c80c-c2c0-4ea6-97a8-31d8c8c3d488"
 deletes flow permision for the given RoleId, FlowName and Environment name.
 #>
    [CmdletBinding(DefaultParameterSetName="Owner")]
    param
    (
        [Parameter(Mandatory = $false, ParameterSetName = "Owner")]
        [string]$ApiVersion = "2016-11-01",

        [Parameter(Mandatory = $true, ParameterSetName = "Owner", ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $true, ParameterSetName = "Owner", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Owner", ValueFromPipelineByPropertyName = $true)]
        [string]$RoleId
    )

    process
    {
        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}/modifyPermissions?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
        | ReplaceMacro -Macro "{environment}" -Value (ResolveEnvironment -OverrideId $EnvironmentName);

        $requestbody = $null

        $requestbody = @{ 
            delete = @(
                @{ 
                    id = $RoleId
                    }
                )
                }

        $result = InvokeApi -Method POST -Route $route -Body $requestbody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($result)
    }
}


function Remove-AdminFlowApprovals
{
 <#
 .SYNOPSIS
 Removes all active and inactive Flow Approvals.
 .DESCRIPTION
 The Remove-AdminFlowApprovals removes all Approval  
 Use Get-Help Remove-AdminFlowApprovals -Examples for more detail.
 .PARAMETER EnvironmentName
 Limits approvals deleted to the specified environment
 .EXAMPLE
 Remove-AdminFlowApprovals -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
 Finds all approvals assigned to the user in the current environment.
 #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        $currentEnvironment = ResolveEnvironment -OverrideId $EnvironmentName;

        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environmentName}/users/{currentUserId}/approvals" `
        | ReplaceMacro -Macro "{environmentName}" -Value $currentEnvironment `
        | ReplaceMacro -Macro "{currentUserId}" -Value $global:currentSession.UserId;

        $approvalRequests = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($approvalRequests);
    }
}

function Get-AdminFlowOwnerRole
{
<#
    .SYNOPSIS
    Gets owner permissions to the flow.
    .DESCRIPTION
    The Get-AdminFlowOwnerRole 
    Use Get-Help Get-AdminFlowOwnerRole -Examples for more detail.
    .PARAMETER EnvironmentName
    The environment of the flow.
    .PARAMETER FlowName
    Specifies the flow id.
    .PARAMETER Owner
    A objectId of the user you want to filter by.
    .EXAMPLE
    Get-AdminFlowOwnerRole -Owner 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    Returns all flow permissions across all environments for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    .EXAMPLE
    Get-AdminFlowOwnerRole -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -Owner 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    Returns all flow permissions within environment with id 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    .EXAMPLE
    Get-AdminFlowOwnerRole -FlowName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239 -Owner 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    Returns all flow permissions for the flow with id 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239 for the user with an object id of 53c0a918-ce7c-401e-98f9-1c60b3a723b3
    .EXAMPLE
    Get-AdminFlowOwnerRole -FlowName 4d1f7648-ad60-4871-91cb-b77d7ef3c239 -EnvironmentName 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    Returns all permissions for the flow with id 4d1f7648-ad60-4871-91cb-b77d7ef3c239 in environment 3c2f7648-ad60-4871-91cb-b77d7ef3c239
    #>
    [CmdletBinding(DefaultParameterSetName="Flow")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Flow", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Environment", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "Flow", ValueFromPipelineByPropertyName = $true)]
        [string]$FlowName,

        [Parameter(Mandatory = $false, ParameterSetName = "Flow")]
        [Parameter(Mandatory = $true, ParameterSetName = "User")]
        [Parameter(Mandatory = $true, ParameterSetName = "Environment")]
        [string]$Owner,

        [Parameter(Mandatory = $false, ParameterSetName = "Flow")]
        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [Parameter(Mandatory = $false, ParameterSetName = "Environment")]
        [string]$ApiVersion = "2016-11-01"
    )

    process
    {
        if (-not [string]::IsNullOrWhiteSpace($FlowName))
        {
            $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}/permissions?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{flowName}" -Value $FlowName `
            | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

            $flowRoleAssignmentResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            $pattern = BuildFilterPattern -Filter $Owner

            foreach ($flowRole in $flowRoleAssignmentResult.Value)
            {
                if ($pattern.IsMatch($flowRole.properties.principal.id))
                {
                    CreateFlowRoleAssignmentObject -FlowRoleAssignmentObj $flowRole
                }
            }
        }
        else
        {
            $environments = @();
 
            if (-not [string]::IsNullOrWhiteSpace($EnvironmentName))
            {
                $environments += @{
                    EnvironmentName = $EnvironmentName
                }
            }
            else {
                $environments = Get-AdminPowerAppEnvironment -ReturnCdsDatabaseType $false
            }

            foreach($environment in $environments)
            {                        
                $flowResult = Get-AdminFlow -EnvironmentName $environment.EnvironmentName
    
                foreach ($flow in $flowResult)
                {
                    $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{environment}/flows/{flowName}/permissions?api-version={apiVersion}" `
                    | ReplaceMacro -Macro "{flowName}" -Value $flow.FlowName `
                    | ReplaceMacro -Macro "{environment}" -Value $environment.EnvironmentName;

                    
                    $flowRoleAssignmentResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                    $pattern = BuildFilterPattern -Filter $Owner

                    foreach ($flowRole in $flowRoleAssignmentResult.Value)
                    {
                        if ($pattern.IsMatch($flowRole.properties.principal.id ))
                        {
                            CreateFlowRoleAssignmentObject -FlowRoleAssignmentObj $flowRole
                        }
                    }
                }
            }
        }
    }
}


function Get-AdminFlowUserDetails
{
<#
 .SYNOPSIS
 Returns the Flow user details for the input user Id.
 .DESCRIPTION
 The Get-AdminFlowUserDetails returns the values for ConsentTime, ConsentBusinessAppPlatformTime, IsDisallowedForInternalPlans, ObjectId, Puid, ServiceSettingsSelectionTime, and TenantId. 
 Use Get-Help Get-AdminFlowUserDetails -Examples for more detail.
 .PARAMETER UserId
 ID of the user query.
 .EXAMPLE
 Get-AdminFlowUserDetails -UserId 7557f390-5f70-4c93-8bc4-8c2faabd2ca0
 Retrieves the user details associated with the user Id 7557f390-5f70-4c93-8bc4-8c2faabd2ca0
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$UserId = $Global:currentSession.userId,

        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$ApiVersion = "2016-11-01"
    )
    process
    {
        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/users/{userId}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{userId}" -Value $userId `
        | ReplaceMacro -Macro "{apiVersion}" -Value $ApiVersion;

        $response = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateFlowUserDetailsObject($response)
    }
}

function Remove-AdminFlowUserDetails
{
<#
 .SYNOPSIS
 Removes the Flow user details for the input user Id. It will throw an error if the input user is an owner of any flows in the tenant.
 .DESCRIPTION
 The Remove-AdminFlowUserDetails deletes the Flow user details assocaited with the input user Id from the Flow database. 
 Use Get-Help Remove-AdminFlowUserDetails -Examples for more detail.
 .PARAMETER UserId
 Object Id of the user to delete.
 .EXAMPLE
 Remove-AdminFlowUserDetails -UserId 7557f390-5f70-4c93-8bc4-8c2faabd2ca0
 Removes the details associated with the input user Id 7557f390-5f70-4c93-8bc4-8c2faabd2ca0.
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$UserId,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-05-01"
    )
    process
    {
        $route = "https://{flowEndpoint}/providers/Microsoft.ProcessSimple/scopes/admin/users/{userId}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{userId}" -Value $userId `
        | ReplaceMacro -Macro "{apiVersion}" -Value $ApiVersion;

        $response = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        if ($response.StatusCode -eq 400)
        {
            Write-Error "All flows for this user must be deleted before user details can be deleted"
        }
        else
        {
            CreateHttpResponse($response)
        }
    }
}

function Set-AdminPowerAppAsFeatured
{
<#
 .SYNOPSIS
 Updates the input PowerApp to be a featured application for the tenant.
 .DESCRIPTION
 The Set-AdminPowerAppAsFeatured changes the isFeaturedApp flag of a PowerApp to true. 
 Use Get-Help Set-AdminPowerAppAsFeatured -Examples for more detail.
 .PARAMETER AppName
 App Id of PowerApp to operate on.
 .PARAMETER ApiVersion
 PowerApps Api version date, defaults to "2017-05-01"
 .PARAMETER ForceLease
 Forces the lease when overwriting the PowerApp fields. Defaults to false if no input is provided.
 .EXAMPLE
 Set-AdminPowerAppAsFeatured -PowerAppName c3dba9c8-0f42-4c88-8110-04b582f20735
 Updates the input PowerApp to be a featured application of that tenant.
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-05-01",

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Boolean]$ForceLease
    )
    process
    {
        $getPowerAppUri = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $powerApp = InvokeApi -Route $getPowerAppUri -Method Get -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        $powerApp.properties.isFeaturedApp = $true

        AcquireLeaseAndPutApp -AppName $AppName -ApiVersion $ApiVersion -PowerApp $powerApp -ForceLease $ForceLease
    }
}

function Clear-AdminPowerAppAsFeatured
{
<#
 .SYNOPSIS
 Removes the input PowerApp as a featured application for the tenant. The input app must not be set as a hero app to unset it as a featured app.
 .DESCRIPTION
 The Unset-AdminPowerAppAsFeatured changes the isFeaturedApp flag of a PowerApp to false. 
 Use Get-Help Unset-AdminPowerAppAsFeatured -Examples for more detail.
 .PARAMETER AppName
 App Id of PowerApp to operate on.
 .PARAMETER ApiVersion
 PowerApps Api version date, defaults to "2017-05-01"
 .PARAMETER ForceLease
 Forces the lease when overwriting the PowerApp fields. Defaults to false if no input is provided.
 .EXAMPLE
 Unset-AdminPowerAppAsFeatured -PowerAppName c3dba9c8-0f42-4c88-8110-04b582f20735
 Updates the input PowerApp to be a regular (not featured) application of that tenant.
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (    
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-05-01",

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Boolean]$ForceLease
    )
    process
    {
        $getPowerAppUri = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $powerApp = InvokeApi -Route $getPowerAppUri -Method Get -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        if($powerApp.properties.isHeroApp -eq $true)
        {
            Write-Error "Must unset the app as a Hero before unsetting the app as featured."
            return
        }

        $powerApp.properties.isFeaturedApp = $false

        AcquireLeaseAndPutApp -AppName $AppName -ApiVersion $ApiVersion -PowerApp $powerApp -ForceLease $ForceLease
    }
}

function Set-AdminPowerAppAsHero
{
<#
 .SYNOPSIS
 Identifies the input PowerApp as a hero application. The input app must be set as a featured app to be set as a hero.
 .DESCRIPTION
 The Set-AdminPowerAppAsHero changes the isHero flag of a PowerApp to true. 
 Use Get-Help Set-AdminPowerAppAsHero -Examples for more detail.
 .PARAMETER AppName
 App Id of PowerApp to operate on.
 .PARAMETER ApiVersion
 PowerApps Api version date, defaults to "2017-05-01"
 .PARAMETER ForceLease
 Forces the lease when overwriting the PowerApp fields. Defaults to false if no input is provided.
 .EXAMPLE
 Set-AdminPowerAppAsHero -PowerAppName c3dba9c8-0f42-4c88-8110-04b582f20735
 Updates the input PowerApp to be the hero application of that tenant.
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-05-01",

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Boolean]$ForceLease
    )
    process
    {
        $getPowerAppUri = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $powerApp = InvokeApi -Route $getPowerAppUri -Method Get -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        if($powerApp.properties.isFeaturedApp -ne $true)
        {
            Write-Error "Must set the app as a Featured app before setting it as a Hero."
            return
        }

        $powerApp.properties.isHeroApp = $true

        AcquireLeaseAndPutApp -AppName $AppName -ApiVersion $ApiVersion -PowerApp $powerApp -ForceLease $ForceLease
    }
}

function Clear-AdminPowerAppAsHero
{
<#
 .SYNOPSIS
 Removes the input PowerApp as a hero application.
 .DESCRIPTION
 The Unset-AdminPowerAppAsHero changes the isHero flag of a PowerApp to false. 
 Use Get-Help Unset-AdminPowerAppAsHero -Examples for more detail.
 .PARAMETER AppName
 App Id of PowerApp to operate on.
 .PARAMETER ApiVersion
 PowerApps Api version date, defaults to "2017-05-01"
 .PARAMETER ForceLease
 Forces the lease when overwriting the PowerApp fields. Defaults to false if no input is provided.
 .EXAMPLE
 Unset-AdminPowerAppAsHero -PowerAppName c3dba9c8-0f42-4c88-8110-04b582f20735
 Updates the input PowerApp to be a regular application.
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-05-01",

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Boolean]$ForceLease
    )
    process
    {
        $getPowerAppUri = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $powerApp = InvokeApi -Route $getPowerAppUri -Method Get -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        $powerApp.properties.isHeroApp = $false

        AcquireLeaseAndPutApp -AppName $AppName -ApiVersion $ApiVersion -PowerApp $powerApp -ForceLease $ForceLease
    }
}


function Set-AdminPowerAppApisToBypassConsent
{
<#
 .SYNOPSIS
 Sets the consent bypass flag so users are not required to authorize API connections for the input PowerApp.
 .DESCRIPTION
 The Set-AdminPowerAppApisToBypassConsent changes the bypassConsent flag of a PowerApp to true. 
 Use Get-Help Set-AdminPowerAppApisToBypassConsent -Examples for more detail.
 .PARAMETER AppName
 App Id of PowerApp to operate on.
 .PARAMETER ApiVersion
 PowerApps Api version date, defaults to "2017-05-01"
 .PARAMETER ForceLease
 Forces the lease when overwriting the PowerApp fields. Defaults to false if no input is provided.
 .EXAMPLE
 Set-AdminPowerAppApisToBypassConsent -PowerAppName c3dba9c8-0f42-4c88-8110-04b582f20735
 Updates the input PowerApp to not require consent for APIs in the production tenant of the logged in user.
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-05-01",

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Boolean]$ForceLease
    )
    process
    {
        $getPowerAppUri = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $powerApp = InvokeApi -Route $getPowerAppUri -Method Get -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
        $powerApp.properties.bypassConsent = $true

        AcquireLeaseAndPutApp -AppName $AppName -ApiVersion $ApiVersion -PowerApp $powerApp -ForceLease $ForceLease
    }
}

function Clear-AdminPowerAppApisToBypassConsent
{
<#
 .SYNOPSIS
 Removes the consent bypass so users are required to authorize API connections for the input PowerApp.
 .DESCRIPTION
 The Clear-AdminPowerAppApisToBypassConsent changes the bypassConsent flag of a PowerApp to false. 
 Use Get-Help Clear-AdminPowerAppApisToBypassConsent -Examples for more detail.
 .PARAMETER AppName
 App Id of PowerApp to operate on.
 .PARAMETER ApiVersion
 PowerApps Api version date, defaults to "2017-05-01"
 .PARAMETER ForceLease
 Forces the lease when overwriting the PowerApp fields. Defaults to false if no input is provided.
 .EXAMPLE
 Clear-AdminPowerAppApisToBypassConsent -PowerAppName c3dba9c8-0f42-4c88-8110-04b582f20735
 Updates the input PowerApp to require consent in the production tenant of the logged in user.
 #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "Name")]
        [string]$AppName,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2017-05-01",

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Boolean]$ForceLease
    )
    process
    {
        $getPowerAppUri = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

        $powerApp = InvokeApi -Route $getPowerAppUri -Method Get -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        $powerApp.properties.bypassConsent = $false

        AcquireLeaseAndPutApp -AppName $AppName -ApiVersion $ApiVersion -PowerApp $powerApp -ForceLease $ForceLease
    }
}


function Get-AdminDlpPolicy
{
    <#
    .SYNOPSIS
    Retrieves api policy objects and provides the option to print out the connectors in each data group.
    .DESCRIPTION
    Get-AdminDlpPolicy cmdlet gets policy objects for the logged in admin's tenant. 
    Use Get-Help Get-AdminDlpPolicy -Examples for more detail.
    .PARAMETER PolicyName
    Retrieves the policy with the input name (identifier).
    .PARAMETER ShowHbi
    Prints out the hbi/business data group api connections if true.
    .PARAMETER ApiVersion
    Specifies the Api version that is called.
    .EXAMPLE
    Get-AdminDlpPolicy
    Retrieves all policies in the tenant.
    .EXAMPLE
    Get-AdminDlpPolicy -PolicyName 78d6c98c-aaa0-4b2b-91c3-83d211754d8a
    Retrieves details on the policy 78d6c98c-aaa0-4b2b-91c3-83d211754d8a.
    #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = "Filter", ValueFromPipelineByPropertyName = $true)]
        [string]$Filter,
        
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = "Filter", ValueFromPipelineByPropertyName = $true)]
        [string]$PolicyName,

        [Parameter(Mandatory = $false)]
        [string]$CreatedBy,

        [Parameter(Mandatory = $false, ParameterSetName = "Filter")]
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [object]$ApiVersion = "2016-11-01"
    )
    process
    {
        # get all policies
        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{apiVersion}" -Value $ApiVersion;

        $response = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        # filter and returns policies that match parameters
        Get-FilteredApiPolicies -PolicyName $PolicyName -ApiPolicyResult $response -Filter $Filter -CreatedBy $CreatedBy
    }
}

function New-AdminDlpPolicy
{
    <#
    .SYNOPSIS
    Creates and inserts a new api policy into the tenant. By default the environment filter is off, and all api connections are in the no business data group (lbi).
    .DESCRIPTION
    New-AdminDlpPolicy cmdlet creates a new DLP policy for the logged in admin's tenant. 
    Use Get-Help New-AdminDlpPolicy -Examples for more detail.
    .PARAMETER DisplayName
    Creates the policy with the input display name.
    .PARAMETER EnvironmentName
    The Environment's identifier.
	.PARAMETER BlockNonBusinessDataGroup
    Block non business data group.
    .PARAMETER ApiVersion
    Specifies the Api version that is called.
    .PARAMETER SchemaVersion
    Specifies the schema version to use, 2016-11-01 or 2018-11-01 (HTTP connectors included).
    .EXAMPLE
    New-AdminDlpPolicy -DisplayName "MetroBank Policy"
    Creates a new policy with the display name 'MetroBank Policy' in the tenant.
    .EXAMPLE
    New-AdminDlpPolicy -DisplayName "MetroBank Policy" -EnvironmentName Default-02c201b0-db76-4a6a-b3e1-a69202b479e6
    Creates a new policy with the display name 'MetroBank Policy' in the environment Default-02c201b0-db76-4a6a-b3e1-a69202b479e6.
	.EXAMPLE
    New-AdminDlpPolicy -DisplayName "MetroBank Policy" -BlockNonBusinessDataGroup $true
    Creates a new policy with the display name 'MetroBank Policy' in the tenant and blocks lbi data group.
    .EXAMPLE
    New-AdminDlpPolicy -DisplayName "MRA Digital" -SchemaVersion 2018-11-01
    Creates a new policy with the display name 'MRA Digital' and schema version '2018-11-01' (includes HTTP connectors).
    #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Name")]
        [string]$DisplayName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,
		
		[Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [bool]$BlockNonBusinessDataGroup = $false,
        
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2016-11-01",

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [ValidateSet("2016-10-01-preview", "2018-11-01")][string]$SchemaVersion = "2016-10-01-preview"
    )
    process
    {
        if([string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $createApiPolicyRoute = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version={apiVersion}"
            $type = "Microsoft.BusinessAppPlatform/scopes/apiPolicies"
        }
        else
        {
            $createApiPolicyRoute = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/apiPolicies?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName
            $type = "Microsoft.BusinessAppPlatform/scopes/environments/apiPolicies"
        }

        $schema = "https://schema.management.azure.com/providers/Microsoft.BusinessAppPlatform/schemas/{schemaVersion}/apiPolicyDefinition.json#" `
        | ReplaceMacro -Macro "{schemaVersion}" -Value $SchemaVersion;
		
		$rules = @{ 
					dataFlowRule = @{
						actions = @{
							blockAction = @{
								type = "Block"
							}
						}
						parameters = @{
							destinationApiGroup = "lbi"
							sourceApiGroup = "hbi"
						}
						type = "DataFlowRestriction"
					}
                }

        $constraints = @{}
        if(-not [string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $getEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}?`$expand=permissions&api-version={apiVersion}" `
                | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName `
                | ReplaceMacro -Macro "{apiVersion}" -Value $ApiVersion
        
            $environmentInput = InvokeApi -Method GET -Route $getEnvironmentUri -ApiVersion $ApiVersion  -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)`
                | %{ New-Object -TypeName PSObject -Property @{ id = $_.id; name = $_.name; type = $_.type } }

            $constraints = @{
                environmentFilter1 = @{
                    parameters = @{
                        environments = @($environmentInput)
                        filterType = "include"
                    }
                    type = "environmentFilter"
                }
            }
        }
		
        $hbiApis = @()
        $lbiDescription = "No business data allowed"
		if ($BlockNonBusinessDataGroup -eq $true)
        {
			if([string]::IsNullOrWhiteSpace($EnvironmentName))
			{
				$EnvironmentName = Get-AdminPowerAppEnvironment -Default | Select -Expand EnvironmentName
			}
			
			if(-not [string]::IsNullOrWhiteSpace($EnvironmentName))
			{
				$getAllConnectorsRoute = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apis?showApisWithToS=true&api-version={apiVersion}&`$expand=permissions(`$filter=maxAssignedTo(%27{userId}%27))&`$filter=environment%20eq%20`'{environment}`'" `
				| ReplaceMacro -Macro "{userId}" -Value $Global:currentSession.userId `
				| ReplaceMacro -Macro "{apiVersion}" -Value $ApiVersion `
				| ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;
			
				$hbiApis = InvokeApi -Method GET -Route $getAllConnectorsRoute -ApiVersion $ApiVersion | Select -Expand value | `
				%{ New-Object -TypeName PSObject -Property @{ id = $_.id; name = $_.properties.displayName; type = $_.type } }
			}

            $DisplayName = $DisplayName + " (PREVIEW: BlockNonBusinessDataGroup)"
            $lbiDescription = $lbiDescription + " (Blocked)"
			$rules.Add("apiGroupRule", @{
                            actions = @{
                                blockAction = @{
                                    type = "Block"
                                }
                            }
                            parameters = @{
                                apiGroup = "lbi"
                            }
                            type = "ApiGroupRestriction"
                        })
		}

		$CreatedTime = Get-Date -Format "o"

        $newPolicy = @{ 
            id = ""
            name = ""
            type = $type
            tags = @{}
            properties = @{
				createdTime = $CreatedTime
                displayName = $DisplayName
                definition = @{
                    "`$schema" = $schema
                    defaultApiGroup = "lbi"
                    constraints = $constraints
                    apiGroups = @{
                        hbi = @{
                            apis = $hbiApis
                            description = "Business data only"
                        }
                        lbi = @{
                            apis =  @()
                            description = $lbiDescription
                        }
                    }
                    rules = $rules
                }
            }
        }

        $response = InvokeApi -Method POST -Route $createApiPolicyRoute -Body $newPolicy -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateApiPolicyObject -PolicyObject $response
    }
}


function Remove-AdminDlpPolicy
{
    <#
    .SYNOPSIS
    Deletes the specific Api policy. Delete is successful if it returns a 202 response, 204 means it did not delete.
    .DESCRIPTION
    Remove-AdminDlpPolicy cmdlet deletes a DLP policy. 
    Use Get-Help Remove-AdminDlpPolicy -Examples for more detail.
    .PARAMETER PolicyName
    Finds policy matching the specified name.
    .PARAMETER EnvironmentName
    The Environment's identifier.
    .PARAMETER ApiVersion
    Specifies the Api version that is called.
    .EXAMPLE
    Remove-AdminDlpPolicy -PolicyName 8c02d657-ad72-4bb9-97c5-afedc4bcf24b
    Deletes policy 8c02d657-ad72-4bb9-97c5-afedc4bcf24b from tenant.
    .EXAMPLE
    Remove-AdminDlpPolicy -EnvironmentName Default-02c201b0-db76-4a6a-b3e1-a69202b479e6 -PolicyName 8c02d657-ad72-4bb9-97c5-afedc4bcf24b
    Deletes policy 8c02d657-ad72-4bb9-97c5-afedc4bcf24b from environment Default-02c201b0-db76-4a6a-b3e1-a69202b479e6.
    #>
    [CmdletBinding(DefaultParameterSetName="Name")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$PolicyName,

        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$EnvironmentName,
        
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$ApiVersion = "2016-11-01"
    )
    process
    {
        if([string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies/{policyName}?api-version={apiVersion}"
        }
        else
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/apiPolicies/{policyName}?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName
        }

        $route = $route | ReplaceMacro -Macro "{policyName}" -Value $PolicyName;
        
        $response = InvokeApi -Method DELETE -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($response)
    }
}

function Set-AdminDlpPolicy
{
    <#
    .SYNOPSIS
    Updates a policy's environment and default api group settings. Upserts the environment list input (does not append).
    .DESCRIPTION
    Set-AdminDlpPolicy cmdlet updates details on the policy, such as environment filter and default api group. 
    Use Get-Help Set-AdminDlpPolicy -Examples for more detail.
    .PARAMETER PolicyName
    Policy name that will be updated.
    .PARAMETER FilterType
    Identifies which filter type the policy will have, none, include or exclude.
    .PARAMETER Environments
    Comma seperated string list used as input environments to either include or exclude, depending on the FilterType.
    .PARAMETER DefaultGroup
    The default group setting, hbi or lbi.
    .PARAMETER EnvironmentName
    The Environment's identifier.
	.PARAMETER SetNonBusinessDataGroupState
    Set non business data group(lbi) to Block or Unblock state.
    .PARAMETER ApiVersion
    Specifies the Api version that is called.
    .PARAMETER SchemaVersion
    Specifies the schema version to use, 2016-11-01-preview or 2018-11-01 (HTTP connectors included).
    .EXAMPLE
    Set-AdminDlpPolicy -PolicyName 78d6c98c-aaa0-4b2b-91c3-83d211754d8a -FilterType None
    Clears the environment filter for the policy 78d6c98c-aaa0-4b2b-91c3-83d211754d8a.
    .EXAMPLE
    Set-AdminDlpPolicy -PolicyName 78d6c98c-aaa0-4b2b-91c3-83d211754d8a -FilterType Include -Environments "febb5387-84d7-4717-8345-334a34402f3d,83d98843-bfd7-47ef-bfcd-dc628810ae7b"
    Only applies the policy to the environments febb5387-84d7-4717-8345-334a34402f3d and 83d98843-bfd7-47ef-bfcd-dc628810ae7b.
    .EXAMPLE
    Set-AdminDlpPolicy -PolicyName 78d6c98c-aaa0-4b2b-91c3-83d211754d8a -FilterType Exclude -Environments "febb5387-84d7-4717-8345-334a34402f3d,83d98843-bfd7-47ef-bfcd-dc628810ae7b"
    Applies the policy to all environments except febb5387-84d7-4717-8345-334a34402f3d and 83d98843-bfd7-47ef-bfcd-dc628810ae7b.
    .EXAMPLE
    Set-AdminDlpPolicy -PolicyName 78d6c98c-aaa0-4b2b-91c3-83d211754d8a -DefaultGroup hbi
    Sets the default data group attribute to be hbi (Business data only).
    .EXAMPLE
    Set-AdminDlpPolicy -PolicyName 78d6c98c-aaa0-4b2b-91c3-83d211754d8a -SchemaVersion 2018-11-01
    Sets the DLP Policy to schema version '2018-11-01', allowing for the use of HTTP connectors.
	.EXAMPLE
    Set-AdminDlpPolicy -PolicyName 78d6c98c-aaa0-4b2b-91c3-83d211754d8a -SetNonBusinessDataGroupState "Block"
    Sets non business data(lbi) to block state.
    #>
    [CmdletBinding(DefaultParameterSetName="TenantPolicy")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "TenantPolicy")]
        [Parameter(Mandatory = $true, ParameterSetName = "EnvironmentPolicy")]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $false, ParameterSetName = "TenantPolicy")]
        [ValidateSet("None","Include","Exclude")][string]$FilterType,

        [Parameter(Mandatory = $false, ParameterSetName = "TenantPolicy")]
        [string]$Environments,

        [Parameter(Mandatory = $false, ParameterSetName = "TenantPolicy")]
        [Parameter(Mandatory = $false, ParameterSetName = "EnvironmentPolicy")]
        [ValidateSet("hbi","lbi")][string]$DefaultGroup,

        [Parameter(Mandatory = $true, ParameterSetName = "EnvironmentPolicy")]
        [string]$EnvironmentName,
		
		[Parameter(Mandatory = $false, ParameterSetName = "TenantPolicy")]
        [Parameter(Mandatory = $false, ParameterSetName = "EnvironmentPolicy")]
        [ValidateSet("Block","Unblock")][string]$SetNonBusinessDataGroupState,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01",

        [Parameter(Mandatory = $false)]
        [ValidateSet("2016-11-01-preview","2018-11-01")][string]$SchemaVersion
    )
    process
    {
        if([string]::IsNullOrWhiteSpace($EnvironmentName))
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies/{policyName}?api-version={apiVersion}"
        }
        else
        {
            $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/apiPolicies/{policyName}?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName
            $FilterType = "Include"
            $Environments = $EnvironmentName
        }

        $route = $route | ReplaceMacro -Macro "{policyName}" -Value $PolicyName;

        $policy = InvokeApi -Route $route -Method GET -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        if ($FilterType -eq "None")
        {
            $policy.properties.definition.constraints = @{}
        }
        elseif (-not [string]::IsNullOrWhiteSpace($FilterType))
        {
            if ([string]::IsNullOrWhiteSpace($Environments))
            {
                Write-Error "Environments parameter cannot be empty if assigning included or excluded environments to a policy"
                return
            }

            $getEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}?`$expand=permissions&api-version={apiVersion}";

            $environmentInput = (($Environments -replace "` ","") -split ",") | %{ InvokeApi -Method GET -Route ($getEnvironmentUri | ReplaceMacro -Macro "{environmentName}" -Value $_) -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) } `
            | %{ New-Object -TypeName PSObject -Property @{ id = $_.id; name = $_.name; type = $_.type } }

            $constraints = @{
                environmentFilter1 = @{
                    parameters = @{
                        environments = @($environmentInput)
                        filterType = $FilterType.toLower()
                    }
                    type = "environmentFilter"
                }
            }

            $policy.properties.definition.constraints = $constraints
        }

        if (-not [string]::IsNullOrWhiteSpace($DefaultGroup))
        {
            $policy.properties.definition.defaultApiGroup = $DefaultGroup
        }
        if (-not [string]::IsNullOrWhiteSpace($SchemaVersion))
        {
            $schema = "https://schema.management.azure.com/providers/Microsoft.BusinessAppPlatform/schemas/{schemaVersion}/apiPolicyDefinition.json#" `
            | ReplaceMacro -Macro "{schemaVersion}" -Value $SchemaVersion;

            $policy.properties.definition."`$schema" = $schema
        }
		if (-not [string]::IsNullOrWhiteSpace($SetNonBusinessDataGroupState))
		{
			if([bool]($policy.properties.definition.rules.PSobject.Properties.name -match "apiGroupRule") -eq $false)
			{
				$policy.properties.definition.rules | Add-Member -NotePropertyName apiGroupRule -NotePropertyValue $null
			}
				
			if ($SetNonBusinessDataGroupState -eq "Block")
			{
				$apiGroupRule = @{
								actions = @{
									blockAction = @{
										type = "Block"
									}
								}
								parameters = @{
									apiGroup = "lbi"
								}
								type = "ApiGroupRestriction"
							}
							
				$policy.properties.definition.rules.apiGroupRule = $apiGroupRule

				$policy.properties.definition.apiGroups.lbi.description = "No business data allowed (Blocked)"
			}
			else
			{
				$policy.properties.definition.rules.PSObject.Properties.Remove("apiGroupRule")

				$policy.properties.definition.apiGroups.lbi.description = "No business data allowed"
			}
		}
        $response = InvokeApi -Method PUT -Route $route -Body $policy -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($response)
    }
}

function Add-AdminPowerAppsSyncUser
{
    <#
    .SYNOPSIS
    Adds a user to the CRM database.
    .DESCRIPTION
    Add-AdminPowerAppsSyncUser cmdlet adds a user to the CRM database. 
    Use Get-Help Add-AdminPowerAppsSyncUser -Examples for more detail.
    .PARAMETER EnvironmentName
    The Environment's identifier.
    .PARAMETER PrincipalObjectId
    The objectId of a user to be added.
    .PARAMETER ApiVersion
    Specifies the Api version that is called.
    .EXAMPLE
    Add-AdminPowerAppsSyncUser -EnvironmentName 8c02d657-ad72-4bb9-97c5-afedc4bcf24b -PrincipalObjectId 24a5b286-2abe-46b4-9ba5-9de73169ab9c
    Add the user (24a5b286-2abe-46b4-9ba5-9de73169ab9c) to the CRM database which is linked in environment 8c02d657-ad72-4bb9-97c5-afedc4bcf24b.
    #>
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $true, ParameterSetName = "User", ValueFromPipelineByPropertyName = $true)]
        [string]$PrincipalObjectId,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2019-05-01"
    )
    process
    {
        $route = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{environmentName}/addUser?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName

        $userToadd = @{
            ObjectId = $PrincipalObjectId
        }

        $response = InvokeApi -Method POST -Route $route -Body $userToadd -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        CreateHttpResponse($response)
    }
}

function Get-AdminPowerAppCdsAdditionalNotificationEmails
{
    <#
    .SYNOPSIS
    Returns email addresses of users other than default admins of CDS that receive notifications.
    .DESCRIPTION
    The Get-AdminPowerAppCdsAdditionalNotificationEmails cmdlet returns email addresses of users other than default admins of CDS linked to an environment that receive notifications.
    Use Get-Help Get-AdminPowerAppCdsAdditionalNotificationEmails -Examples for more details.
    .PARAMETER EnvironmentName
    The Environment's identifier.    
    .PARAMETER ApiVersion
    Specifies the Api version that is called.
    .EXAMPLE
    Get-AdminPowerAppCdsAdditionalNotificationEmails -EnvironmentName 02c201b0-db76-4a6a-b3e1-a69202b479e6
    Returns email addresses of users other than default admins of CDS linked to the environment 02c201b0-db76-4a6a-b3e1-a69202b479e6.
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentName,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2019-10-01"
    )

	$getAdditionalNotificationEmailsUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/environments/{environmentName}?`$expand=properties.linkedEnvironmentMetadata.additionalNotificationEmails&api-version={apiVersion}" `
	    | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;
    
    $additionalNotificationEmailsResponse = InvokeApi -Method GET -Route $getAdditionalNotificationEmailsUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

	if($additionalNotificationEmailsResponse.StatusCode -ne 200)
	{
	    CreateHttpResponse($additionalNotificationEmailsResponse)	
	}
	else
	{
		return $additionalNotificationEmailsResponse.properties.linkedEnvironmentMetadata.additionalNotificationEmails
	}
}

function Set-AdminPowerAppCdsAdditionalNotificationEmails
{
    <#
    .SYNOPSIS
    Sets email addresses of users other than default admins of CDS that should receive notifications.
    .DESCRIPTION
    The Set-AdminPowerAppCdsAdditionalNotificationEmails cmdlet sets email addresses of users other than default admins of CDS linked to an environment that should receive notifications.
    Use Get-Help Set-AdminPowerAppCdsAdditionalNotificationEmails -Examples for more details.
    .PARAMETER EnvironmentName
    The Environment's identifier.
	.PARAMETER AdditionalNotificationEmails
	The email addresses
    .PARAMETER ApiVersion
    Specifies the Api version that is called.
    .EXAMPLE
    Set-AdminPowerAppCdsAdditionalNotificationEmails -EnvironmentName 02c201b0-db76-4a6a-b3e1-a69202b479e6 -AdditionalNotificationEmails abc@test.com
    Returns email addresses of users other than default admins of CDS linked to the environment 02c201b0-db76-4a6a-b3e1-a69202b479e6.
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentName,

		[Parameter(Mandatory = $true)]
        [string[]]$AdditionalNotificationEmails,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2019-10-01"
    )

	$setAdditionalNotificationEmailsUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/environments/{environmentName}?api-version={apiVersion}" `
	    | ReplaceMacro -Macro "{environmentName}" -Value $EnvironmentName;

	$requestBody = @{            
            properties = @{
                linkedEnvironmentMetadata = @{
					additionalNotificationEmails = $AdditionalNotificationEmails
				}
            }            
        }
    
    $setAdditionalNotificationEmailsResponse = InvokeApi -Method PATCH -Route $setAdditionalNotificationEmailsUri -Body $requestBody -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

	if($setAdditionalNotificationEmailsResponse.StatusCode -ne 204)
	{
	    Write-Error "Operation to set email addresses failed!"    
	}

	CreateHttpResponse($setAdditionalNotificationEmailsResponse)
}

function Get-AdminPowerAppLicenses
{
    <#
    .SYNOPSIS
    Downloads the user licenses into a specified file.
    .DESCRIPTION
    The Get-AdminPowerAppLicenses cmdlet downloads the user licenses into a specified file.
    Use Get-Help Get-AdminPowerAppLicenses -Examples for more details.
    .PARAMETER OutputFilePath
    The output file path 
    .PARAMETER ApiVersion
    Specifies the Api version that is called.
    .EXAMPLE
    Get-AdminPowerAppLicenses -OutputFilePath C:\Users\testuser\licenses.json
    Donloads the licenses of calling user into specified path file C:\Users\testuser\licenses.json
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath = $null,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = "2016-11-01"
    )

    $getLicensesUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/scopes/admin/exportServicePlans?api-version={apiVersion}"
    
    $getLicensesResponse = InvokeApi -Method POST -Route $getLicensesUri -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

    if ($getLicensesResponse.StatusCode -eq 202)
    {
        $getLicensesUri = $getLicensesResponse.Headers['Location']
        $currentTime = Get-Date -format HH:mm:ss
        $nextTime = Get-Date -format HH:mm:ss
        $TimeDiff = New-TimeSpan $currentTime $nextTime
        $timeoutInSeconds = 3600
        
        #Wait until the operation complete, there is an error, or we hit a timeout
        while((-not [string]::IsNullOrEmpty($getLicensesUri)) -and ($getLicensesResponse.StatusCode -eq 202) -and ($TimeDiff.TotalSeconds -lt $timeoutInSeconds))
        {
            Start-Sleep -s 5
            $getLicensesResponse = InvokeApiNoParseContent -Route $getLicensesUri -Method GET -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
            $nextTime = Get-Date -format HH:mm:ss
            $TimeDiff = New-TimeSpan $currentTime $nextTime
        }

        if ($TimeDiff.TotalSeconds -ge $timeoutInSeconds)
        {
            Write-Error "Get-AdminPowerAppLicenses timeout."
            throw
        }
    }

    $jobject = ConvertFrom-Json($getLicensesResponse.Content)
    $csvFileUri = $jobject.sharedAccessSignature
    Invoke-WebRequest $csvFileUri -OutFile $OutputFilePath
    CreateHttpResponse($getLicensesResponse)
}

#internal, helper function
function Get-FilteredEnvironments
{
    param
    (
        [Parameter(Mandatory = $false)]
        [object]$Filter,

        [Parameter(Mandatory = $false)]
        [object]$CreatedBy,

        [Parameter(Mandatory = $false)]
        [object]$EnvironmentResult,

        [Parameter(Mandatory = $false)]
        [bool]$ReturnCdsDatabaseType = $false
    )

    $patternOwner = BuildFilterPattern -Filter $CreatedBy
    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($env in $EnvironmentResult.Value)
    {
        if ($patternOwner.IsMatch($env.properties.createdBy.displayName) -or
            $patternOwner.IsMatch($env.properties.createdBy.email) -or 
            $patternOwner.IsMatch($env.properties.createdBy.id) -or 
            $patternOwner.IsMatch($env.properties.createdBy.userPrincipalName))
        {
            if ($patternFilter.IsMatch($env.name) -or
                $patternFilter.IsMatch($env.properties.displayName))
            {
                CreateEnvironmentObject -EnvObject $env -ReturnCdsDatabaseType $ReturnCdsDatabaseType
            }
        }
    }
}

#internal, helper function
function Get-FilteredApiPolicies
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ApiPolicyResult,
        
        [Parameter(Mandatory = $false)]
        [string]$CreatedBy,
        
        [Parameter(Mandatory = $false)]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $false)]
        [string]$Filter
    )

    $patternPolicyName = BuildFilterPattern -Filter $PolicyName
    $patternOwner = BuildFilterPattern -Filter $CreatedBy
    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($pol in $ApiPolicyResult.Value)
    {
        if ($patternPolicyName.IsMatch($pol.name))
        {
            if ($patternOwner.IsMatch($pol.properties.createdBy.displayName) -or
                $patternOwner.IsMatch($pol.properties.createdBy.email) -or 
                $patternOwner.IsMatch($pol.properties.createdBy.id) -or 
                $patternOwner.IsMatch($pol.properties.createdBy.userPrincipalName))
            {
                if ($patternFilter.IsMatch($pol.name) -or
                    $patternFilter.IsMatch($pol.properties.displayName))
                { 
                    CreateApiPolicyObject -PolicyObject $pol
                }
            }
        }
    }
}

#internal, helper function
function Get-CdsOneDatabase(
    [string]$ApiVersion = "2016-11-01",
    [string]$EnvironmentName = "2016-11-01"
    
)
{
    $route = "https://{cdsOneEndpoint}/providers/Microsoft.CommonDataModel/namespaces?api-version={apiVersion}&`$filter=environment%20eq%20%27{environment}%27" `
    | ReplaceMacro -Macro "{environment}" -Value $EnvironmentName;

    $databaseResult = InvokeApi -Method GET -Route $route -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

    CreateCdsOneDatabasObject -DatabaseObject $databaseResult.Value
}

#internal, helper function
function Get-FilteredApps
{
     param
    (
        [Parameter(Mandatory = $false)]
        [object]$Filter,

        [Parameter(Mandatory = $false)]
        [object]$Owner,

        [Parameter(Mandatory = $false)]
        [object]$AppResult
    )

    $patternOwner = BuildFilterPattern -Filter $Owner
    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($app in $AppResult.Value)
    {
        if ($patternOwner.IsMatch($app.properties.owner.displayName) -or
            $patternOwner.IsMatch($app.properties.owner.email) -or 
            $patternOwner.IsMatch($app.properties.owner.id) -or 
            $patternOwner.IsMatch($app.properties.owner.userPrincipalName))
        {
            if ($patternFilter.IsMatch($app.name) -or
                $patternFilter.IsMatch($app.properties.displayName))
            {
                CreateAppObject -AppObj $app
            }
        }
    }
}

#internal, helper function
function Get-FilteredConnections
{
     param
    (
        [Parameter(Mandatory = $false)]
        [object]$Filter,

        [Parameter(Mandatory = $false)]
        [object]$CreatedBy,

        [Parameter(Mandatory = $false)]
        [object]$ConnectionResult
    )

    $patternCreatedBy = BuildFilterPattern -Filter $CreatedBy
    $patternFilter = BuildFilterPattern -Filter $Filter
            
    foreach ($connection in $ConnectionResult.Value)
    {
        if ($patternCreatedBy.IsMatch($connection.properties.createdBy.displayName) -or
            $patternCreatedBy.IsMatch($connection.properties.createdBy.email) -or 
            $patternCreatedBy.IsMatch($connection.properties.createdBy.id) -or 
            $patternCreatedBy.IsMatch($connection.properties.createdBy.userPrincipalName))
        {
            if ($patternFilter.IsMatch($connection.name) -or
                $patternFilter.IsMatch($connection.properties.displayName))
            {
                CreateConnectionObject -ConnectionObj $connection
            }
        }
    }
}

#internal, helper function
function Get-FilteredFlows
{
    param
    (
        [Parameter(Mandatory = $false)]
        [object]$Filter,

        [Parameter(Mandatory = $false)]
        [object]$CreatedBy,

        [Parameter(Mandatory = $false)]
        [object]$FlowResult
    )

    if (-not [string]::IsNullOrWhiteSpace($CreatedBy))
    {
        $pattern = BuildFilterPattern -Filter $CreatedBy
            
        foreach ($flow in $FlowResult.Value)
        {
            if ($flow -ne $null -and
                ($pattern.IsMatch($flow.properties.creator.objectId) -or
                $pattern.IsMatch($flow.properties.creator.userId)))
            {
                CreateFlowObject -FlowObj $flow
            }
        }
    }
    else
    {
        $pattern = BuildFilterPattern -Filter $Filter

        foreach ($flow in $flowResult.Value)
        {
            if ($flow -ne $null -and
                ($pattern.IsMatch($flow.name) -or
                $pattern.IsMatch($flow.properties.displayName)))
            {
                CreateFlowObject -FlowObj $flow
            }
        }
    }   
}


#internal, helper function
function CreateHttpResponse
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ResponseObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name Code -Value $ResponseObject.StatusCode `
        | Add-Member -PassThru -MemberType NoteProperty -Name Description -Value $ResponseObject.StatusDescription `
        | Add-Member -PassThru -MemberType NoteProperty -Name Headers -Value $ResponseObject.Headers `
        | Add-Member -PassThru -MemberType NoteProperty -Name Error -Value $ResponseObject.error `
        | Add-Member -PassThru -MemberType NoteProperty -Name Errors -Value $ResponseObject.errors `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $ResponseObject;
}

#internal, helper function
function CreateEnvironmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$EnvObject,

        [Parameter(Mandatory = $false)]
        [bool]$ReturnCdsDatabaseType
    )

    If($ReturnCdsDatabaseType)
    {
        $cdsDatabaseType = "None"

        # this property will be set if the environment has linked CDS 2.0 database
        $LinkedCdsTwoInstanceType = $EnvObject.properties.linkedEnvironmentMetadata.type;

        if ($LinkedCdsTwoInstanceType -ne $null)
        {
            if($LinkedCdsTwoInstanceType -eq "Dynamics365Instance")
            {
                $cdsDatabaseType = "Common Data Service for Apps"
            }
            else
            {
                #unfortunately there is no other way to determine if an environment has a database other than making a separate REST API call
                $cdsOneDatabase = Get-CdsOneDatabase -ApiVersion $ApiVersion -EnvironmentName $EnvObject.name

                if ($cdsOneDatabase.EnvironmentName -eq $EnvObject.name)
                {
                    $cdsDatabaseType = "Common Data Service (Previous Version)"
                }       
            }
        }
    }
    else {
        $cdsDatabaseType = "Unknown"
    }

    

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvObject.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $EnvObject.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name IsDefault -Value $EnvObject.properties.isDefault `
        | Add-Member -PassThru -MemberType NoteProperty -Name Location -Value $EnvObject.location `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $EnvObject.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedBy -value $EnvObject.properties.createdBy `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $EnvObject.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedBy -value $EnvObject.properties.lastModifiedBy.userPrincipalName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreationType -value $EnvObject.properties.creationType `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentType -value $EnvObject.properties.environmentSku `
        | Add-Member -PassThru -MemberType NoteProperty -Name CommonDataServiceDatabaseProvisioningState -Value $EnvObject.properties.provisioningState `
        | Add-Member -PassThru -MemberType NoteProperty -Name CommonDataServiceDatabaseType -Value $cdsDatabaseType `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $EnvObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name InternalCds -value $cdsOneDatabase;
}

#internal, helper function
function CreateEnvironmentLocationObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$EnvironmentLocationObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name LocationName -Value $EnvironmentLocationObject.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name LocationDisplayName -Value $EnvironmentLocationObject.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $EnvironmentLocationObject;
}

#internal, helper function
function CreateCurrencyObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$CurrencyObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name CurrencyName -Value $CurrencyObject.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name CurrencyCode -Value $CurrencyObject.properties.code `
        | Add-Member -PassThru -MemberType NoteProperty -Name IsTenantDefaultCurrency -Value $CurrencyObject.properties.isTenantDefault `
        | Add-Member -PassThru -MemberType NoteProperty -Name CurrencySymbol -Value $CurrencyObject.properties.symbol `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $CurrencyObject;
}

#internal, helper function
function CreateLanguageObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$LanguageObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name LanguageName -Value $LanguageObject.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name LanguageDisplayName -Value $LanguageObject.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name IsTenantDefaultLanguage -Value $LanguageObject.properties.isTenantDefault `
        | Add-Member -PassThru -MemberType NoteProperty -Name LanguageLocalizedDisplayName -Value $LanguageObject.properties.localizedName `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $LanguageObject;
}

#internal, helper function
function CreateTemplateObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$TemplateObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name TemplateName -Value $TemplateObject.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name TemplateLocation -Value $TemplateObject.location `
        | Add-Member -PassThru -MemberType NoteProperty -Name TemplateDisplayName -Value $TemplateObject.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name IsDisabled -Value $TemplateObject.properties.isDisabled
}

#internal, helper function
function CreateCdsOneDatabasObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$DatabaseObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name DatabaseId -Value $DatabaseObject.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name DatabaseName -Value $DatabaseObject.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $DatabaseObject.properties.environmentId `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $DatabaseObject.properties.createdDateTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $DatabaseObject.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name ProvisioningState -Value $DatabaseObject.properties.provisioningState `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -value $DatabaseObject;
}

#internal, helper function
function CreateAppObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$AppObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value $AppObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $AppObj.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $AppObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name Owner -Value $AppObj.properties.owner `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $AppObj.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $AppObj.properties.environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name UnpublishedAppDefinition -Value $AppObj.properties.unpublishedAppDefinition `
        | Add-Member -PassThru -MemberType NoteProperty -Name IsFeaturedApp -Value $AppObj.properties.isFeaturedApp `
        | Add-Member -PassThru -MemberType NoteProperty -Name IsHeroApp -Value $AppObj.properties.isHeroApp `
        | Add-Member -PassThru -MemberType NoteProperty -Name BypassConsent -Value $AppObj.properties.bypassConsent `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppObj;
        #bypassConsent
}

#internal, helper function
function CreateFlowObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$FlowObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name FlowName -Value $FlowObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Enabled -Value ($FlowObj.properties.state -eq 'Started') `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $FlowObj.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name UserType -Value $FlowObj.properties.userType `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $FlowObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedBy -Value $FlowObj.properties.creator `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $FlowObj.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $FlowObj.properties.environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $FlowObj;
}

#internal, helper function
function CreateAppRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$AppRoleAssignmentObj
    )
        
    If($AppRoleAssignmentObj.properties.principal.type -eq "Tenant")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $AppRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $AppRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $AppRoleAssignmentObj.properties.principal.tenantId `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $AppRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $AppRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value ((($AppRoleAssignmentObj.properties.scope -split "/apps/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($AppRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppRoleAssignmentObj;
    }
    elseif($AppRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $AppRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $AppRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $AppRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $AppRoleAssignmentObj.properties.principal.email `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $AppRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $AppRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $AppRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value ((($AppRoleAssignmentObj.properties.scope -split "/apps/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($AppRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppRoleAssignmentObj;
    }
    elseif($AppRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $AppRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $AppRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $AppRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $AppRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $AppRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $AppRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name AppName -Value ((($AppRoleAssignmentObj.properties.scope -split "/apps/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($AppRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $AppRoleAssignmentObj;
    }
    else {
        return $null
    }
}

#internal, helper function
function CreateFlowRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$FlowRoleAssignmentObj
    )
        
    if($FlowRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $FlowRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $FlowRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $FlowRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $FlowRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $FlowRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name FlowName -Value ((($FlowRoleAssignmentObj.id -split "/flows/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($FlowRoleAssignmentObj.id -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $FlowRoleAssignmentObj;
    }
    elseif($FlowRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $FlowRoleAssignmentObj.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $FlowRoleAssignmentObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $FlowRoleAssignmentObj.properties.principal.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $FlowRoleAssignmentObj.properties.principal.type `
        | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $FlowRoleAssignmentObj.properties.roleName `
        | Add-Member -PassThru -MemberType NoteProperty -Name FlowName -Value ((($FlowRoleAssignmentObj.id -split "/flows/")[1]) -split "/")[0] `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($FlowRoleAssignmentObj.id -split "/environments/")[1]) -split "/")[0] `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $FlowRoleAssignmentObj;
    }
    else {
        return $null
    }
}

#internal, helper function
function CreateEnvRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$EnvRoleAssignmentObj,

        [Parameter(Mandatory = $false)]
        [object]$EnvObj
    )
        
    If($EnvRoleAssignmentObj.properties.principal.type -eq "Tenant")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $EnvRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $EnvRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $EnvRoleAssignmentObj.properties.principal.tenantId `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $EnvRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $EnvRoleAssignmentObj.properties.roleDefinition.name`
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($EnvRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentObject -Value $EnvObj `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $EnvRoleAssignmentObj;
    }
    elseif($EnvRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $EnvRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $EnvRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $EnvRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $EnvRoleAssignmentObj.properties.principal.email `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $EnvRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $EnvRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $EnvRoleAssignmentObj.properties.roleDefinition.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($EnvRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentObject -Value $EnvObj `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $EnvRoleAssignmentObj;
    }
    elseif($EnvRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $EnvRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $EnvRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $EnvRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $EnvRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $EnvRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $EnvRoleAssignmentObj.properties.roleDefinition.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value ((($EnvRoleAssignmentObj.properties.scope -split "/environments/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentObject -Value $EnvObj `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $EnvRoleAssignmentObj;
    }
    else {
        return $null
    }
}

#internal, helper function
function CreateConnectionObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ConnectionObj
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionName -Value $ConnectionObj.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionId -Value $ConnectionObj.id `
        | Add-Member -PassThru -MemberType NoteProperty -Name FullConnectorName -Value $ConnectionObj.properties.apiId `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectionObj.properties.apiId -split "/apis/")[1]) -split "/")[0] `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $ConnectionObj.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $ConnectionObj.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedBy -Value $ConnectionObj.properties.createdBy `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $ConnectionObj.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $ConnectionObj.properties.environment.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Statuses -Value $ConnectionObj.properties.statuses `
        | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectionObj;
}

#internal, helper function
function CreateConnectionRoleAssignmentObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$ConnectionRoleAssignmentObj,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentName
    )

    If($ConnectionRoleAssignmentObj.properties.principal.type -eq "Tenant")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectionRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectionRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectionRoleAssignmentObj.properties.principal.tenantId `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectionRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectionRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionName -Value ((($ConnectionRoleAssignmentObj.id -split "/connections/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectionRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectionRoleAssignmentObj;
    }
    elseif($ConnectionRoleAssignmentObj.properties.principal.type -eq "User")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectionRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectionRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $ConnectionRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $ConnectionRoleAssignmentObj.properties.principal.email `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectionRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectionRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectionRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionName -Value ((($ConnectionRoleAssignmentObj.id -split "/connections/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectionRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectionRoleAssignmentObj;
    }
    elseif($ConnectionRoleAssignmentObj.properties.principal.type -eq "Group")
    {
        return New-Object -TypeName PSObject `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleId -Value $ConnectionRoleAssignmentObj.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleName -Value $ConnectionRoleAssignmentObj.name `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalDisplayName -Value $ConnectionRoleAssignmentObj.properties.principal.displayName `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalEmail -Value $null `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalObjectId -Value $ConnectionRoleAssignmentObj.properties.principal.id `
            | Add-Member -PassThru -MemberType NoteProperty -Name PrincipalType -Value $ConnectionRoleAssignmentObj.properties.principal.type `
            | Add-Member -PassThru -MemberType NoteProperty -Name RoleType -Value $ConnectionRoleAssignmentObj.properties.roleName `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectionName -Value ((($ConnectionRoleAssignmentObj.id -split "/permission/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name ConnectorName -Value ((($ConnectionRoleAssignmentObj.id -split "/apis/")[1]) -split "/")[0] `
            | Add-Member -PassThru -MemberType NoteProperty -Name EnvironmentName -Value $EnvironmentName `
            | Add-Member -PassThru -MemberType NoteProperty -Name Internal -Value $ConnectionRoleAssignmentObj;
    }
    else {
        return $null
    }
}

#internal, helper function
function CreateFlowUserDetailsObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$FlowUserObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConsentBusinessAppPlatformTime -Value $FlowUserObject.consentBusinessAppPlatformTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name ConsentTime -Value $FlowUserObject.consentTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name IsDisallowedForInternalPlans -Value $FlowUserObject.isDisallowedForInternalPlans `
        | Add-Member -PassThru -MemberType NoteProperty -Name ObjectId -Value $FlowUserObject.objectId `
        | Add-Member -PassThru -MemberType NoteProperty -Name Puid -Value $FlowUserObject.puid `
        | Add-Member -PassThru -MemberType NoteProperty -Name ServiceSettingsSelectionTime -Value $FlowUserObject.serviceSettingsSelectionTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name TenantId -Value $FlowUserObject.tenantId;
}

#internal, helper method
function CreateApiPolicyObject
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object]$PolicyObject
    )

    return New-Object -TypeName PSObject `
        | Add-Member -PassThru -MemberType NoteProperty -Name PolicyName -Value $PolicyObject.name `
        | Add-Member -PassThru -MemberType NoteProperty -Name Type -Value $PolicyObject.type `
        | Add-Member -PassThru -MemberType NoteProperty -Name DisplayName -Value $PolicyObject.properties.displayName `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedTime -Value $PolicyObject.properties.createdTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name CreatedBy -Value $PolicyObject.properties.createdBy `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedTime -Value $PolicyObject.properties.lastModifiedTime `
        | Add-Member -PassThru -MemberType NoteProperty -Name LastModifiedBy -Value $PolicyObject.properties.lastModifiedBy `
        | Add-Member -PassThru -MemberType NoteProperty -Name Constraints -Value $PolicyObject.properties.definition.constraints `
        | Add-Member -PassThru -MemberType NoteProperty -Name BusinessDataGroup -Value $PolicyObject.properties.definition.apiGroups.hbi.apis`
        | Add-Member -PassThru -MemberType NoteProperty -Name NonBusinessDataGroup -Value $PolicyObject.properties.definition.apiGroups.lbi.apis`
        | Add-Member -PassThru -MemberType NoteProperty -Name FilterType -Value $PolicyObject.properties.definition.constraints.environmentFilter1.parameters.filterType `
        | Add-Member -PassThru -MemberType NoteProperty -Name Environments -Value $PolicyObject.properties.definition.constraints.environmentFilter1.parameters.environments;
}

#internal, helper method
function AcquireLeaseAndPutApp(
    [CmdletBinding()]
    
    [string]$AppName,
    [string]$ApiVersion,
    [Object]$PowerApp,
    [Boolean]$ForceLease
)
{
    if ($ApiVersion -eq $null -or $ApiVersion -eq "")
    {
        Write-Error "Api Version must be set."
        throw
    }
    
    $apiVersionsBeforePublishSave = @("2016-11-01", "2017-02-01", "2017-04-01")
    foreach ($apiVersionPrefix in $apiVersionsBeforePublishSave)
    {
        $doesNotNeedPublish = $ApiVersion -Match $apiVersionPrefix
        if ($doesNotNeedPublish)
        {
            Write-Warning "Older API version, please use 2017-05-01 or newer."
            break;
        }
    }

    if ($ForceLease)
    {
        $forceLeaseFlag = "true"
    }
    else
    {
        $forceLeaseFlag = "false" 
    }

    $powerAppBaseUri = "https://{powerAppsEndpoint}/providers/Microsoft.PowerApps/apps/{appName}" `
        | ReplaceMacro -Macro "{powerAppsEndpoint}" -Value $Global:currentSession.powerAppsEndpoint `
        | ReplaceMacro -Macro "{appName}" -Value $AppName;

    $acquireLeaseUri = "{powerAppBaseUri}/acquireLease`?api-version={apiVersion}&forceLeaseAcquisition={forceLeaseFlag}" `
        | ReplaceMacro -Macro "{powerAppBaseUri}" -Value $powerAppBaseUri `
        | ReplaceMacro -Macro "{forceLeaseFlag}" -Value $forceLeaseFlag;
        
    $releaseLeaseUri = "{powerAppBaseUri}/releaseLease`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{powerAppBaseUri}" -Value $powerAppBaseUri;

    $putPowerAppUri = "{powerAppBaseUri}/`?api-version={apiVersion}" `
        | ReplaceMacro -Macro "{powerAppBaseUri}" -Value $powerAppBaseUri;

    $leaseResponse = InvokeApi -Route $acquireLeaseUri -Method Post -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

    if ($doesNotNeedPublish)
    {
        $response = InvokeApi -Route $putPowerAppUri -Method Put -Body $PowerApp -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    }
    else
    {
        $powerApp.Properties.LifeCycleId = "Draft"
        $response = InvokeApi -Route $putPowerAppUri -Method Put -Body $PowerApp -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

        $publishPowerAppUri = "{powerAppBaseUri}/publish`?api-version={apiVersion}" `
            | ReplaceMacro -Macro "{powerAppBaseUri}" -Value $powerAppBaseUri `
            | ReplaceMacro -Macro "{apiVersion}" -Value $ApiVersion;

        $publishResponse = InvokeApi -Route $publishPowerAppUri -Method Post -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    }

    $response = InvokeApi -Route $releaseLeaseUri -Method Post -Body $leaseResponse -ThrowOnFailure -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
    CreateHttpResponse($response)
}
# SIG # Begin signature block
# MIIdhAYJKoZIhvcNAQcCoIIddTCCHXECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxuiwEcxRXXW6W4tlm9gNupBD
# fDCgghhuMIIE2jCCA8KgAwIBAgITMwAAAUvV9fuWDIQscwAAAAABSzANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTkxMTEzMjE0MjIw
# WhcNMjEwMjExMjE0MjIwWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIzM0MxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQDVej07Z5ElWXLq968Y6+iILD03VUdVVriXdU6l8qNlZqck
# Zak3anRa3nJO8CrDeXWZ8AH7KmbnNIgNMt3d1ZBEfakY7+VRGYltvBxY3cYDujsF
# M5m/yDAE2VVm+ZGYEKfh7fdILMmh7Og0qXbYyUkSrR2uGtYmgpbcT/hcmTM5d2RI
# DVaWppH2yLOurNhVEcBWfn7yea/iQAwOKW7+zur+1/mDvEhv7Kr8FaBMFLq2jRtO
# UAVtUmrzTZ+9EU9kH4SVb8gzt0bNL0Q88AKgrzlm8AGyos58NVvRpjvfIBBrIlVd
# 9FOU+94a3P7pT4lOAUn1XbWeM0T9j0ys34eM1RqZAgMBAAGjggEJMIIBBTAdBgNV
# HQ4EFgQU4fI3Ff9NFrVBOm6onIthr3VbfMowHwYDVR0jBBgwFoAUIzT42VJGcArt
# QPt2+7MrsMM1sw8wVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC5taWNyb3Nv
# ZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljcm9zb2Z0VGltZVN0YW1wUENBLmNy
# bDBYBggrBgEFBQcBAQRMMEowSAYIKwYBBQUHMAKGPGh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljcm9zb2Z0VGltZVN0YW1wUENBLmNydDATBgNV
# HSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAQEAibCHTqTSgk+NzyCI
# CgTgp58mRzpiXj32Md5BQy97JLUpjBbAhhULDSbCa6EzGN87YirjGuLzs0bhYZqw
# eHVOsW8a5rvfaqTM11qlw0ppnv2YtBA/WUvI8AafmCAUOaCEKf6NTWDTKg7jF5x8
# 1Ruz1gvPgFgkFED4aNIftcRA9jW6rqDa1Xs8xk2WMGqUR6y1cXE2dGC4pf1CGNf3
# tmX0mewtA4OjHXQC+ITitBmB5dw/4G2M6p9q+Xxf+dvyL4wT4frnhCHUpjfxMV5K
# wLlJfqXAWgZKHUV/qK9afp9++26uMMOwGfVwZvE3fRS1NCl7yl/yUGHvleQMurnz
# PcaoTTCCBgMwggProAMCAQICEzMAAAFSm0CfUFaZdYgAAAAAAVIwDQYJKoZIhvcN
# AQELBQAwfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYG
# A1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTAeFw0xOTA1MDIy
# MTM3NDZaFw0yMDA1MDIyMTM3NDZaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xHjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALGnidP2p+707XSInJ7BhceU35YS
# Hv02iiv2eEzp6dQ1sJuFf29L7xz/d4hVrNJidUFOovNbvFY3VsJwi0NuwTMoQTYG
# zBK6fsn3EJovBwYcoWv6pZSXPuGH1FyaNhKQ4Y3Js5+uCPeybQNK2gryWPATJRV5
# F8wfH0T/sJr84SrZxcFPcvR9WeUSR9qXfXQQUIsOjYGsTfk0ZGMb7+edmKoqoSHm
# VY2TfclXz8jR8hxQqssSZQau/QKALvDZyOZsGEEgn7QrNKdJaKeBeiX/eJR0EHLh
# BA0fvruRga6cl5jTxGMcwiCMkJ0CgQz7aZe/WmFpXuP4zd03Nn9x2zPegN8CAwEA
# AaOCAYIwggF+MB8GA1UdJQQYMBYGCisGAQQBgjdMCAEGCCsGAQUFBwMDMB0GA1Ud
# DgQWBBTd/wDDWxbvZZwnZuj9BJgbNWtFhzBUBgNVHREETTBLpEkwRzEtMCsGA1UE
# CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMRYwFAYDVQQF
# Ew0yMzAwMTIrNDU0MTM2MB8GA1UdIwQYMBaAFEhuZOVQBdOCqhc3NyK1bajKdQKV
# MFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0wNy0wOC5jcmwwYQYIKwYBBQUH
# AQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0wNy0wOC5jcnQwDAYDVR0T
# AQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAlPBE5oe+iBeCLFaPKO8t+JGCojZA
# rwagbbd6oCA2NftX9Z1RYFuzRogLeTj1x3TN2r4kkiaLFxfpQ5OnPYtk8VKHbeXT
# 8yjfnAbsldTGA7RT7l2ttCG3nGgyXWfv9NDiIpyYBhIA/FOrmUWehXb58B6WNUDs
# 7jezOOzstHT0PTAUfDNlyj+ITweVqSXbdlPsWcHkB9TaHB+/zvLerdrmoWK6BLKQ
# gukrT++qeURUHQoB1BXNhQtD9Th4USOeKzcmz1SsC+0iEizbrjjlGPdQ/pTgaA6O
# BCieVED6YOWyHvzAVIZsBIi8r5+Q41SG+PwHxkc2fhMV+dy35rRm55jh/ppE/Gvx
# t41JQqftBb8VCafjbZsTsp+epadywfu9s2Eb3b2mtUc+xprsnbaL3DIePubSgBNc
# n5iN/KgQC13n83IhhoThS7SPUSG5hSjlVokmcxpMRHSpfz79hlFasU3+F6mzjVc1
# WOIBrClsBrR9RrdH1E0GM+IGczSC80+iszh2xXZUnwaW4hA6smU6+4Ks5gMaKsad
# p06ZDbXA8GgYUJakrno/HOWIqzLk02YBdwTHtBv29SNjVaVi2t3A5dOnE3iyXMiG
# 3r0FpmUsiMtVbCoh+42uEco0Mz0r6/u+Csht/uXn/rrmDSCNAIMI3pDmzG621MAQ
# q0l5L+mSkj4Ntn8wggYHMIID76ADAgECAgphFmg0AAAAAAAcMA0GCSqGSIb3DQEB
# BQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAXBgoJkiaJk/IsZAEZFgltaWNy
# b3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhv
# cml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMxMzAzMDlaMHcxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ+h
# bLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn0UytdDAgEesH1VSVFUmUG0KS
# rphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0Zxws/HvniB3q506jocEjU8qN
# +kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4nrIZPVVIM5AMs+2qQkDBuh/NZ
# MJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YRJylmqJfk0waBSqL5hKcRRxQJ
# gp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54QTF3zJvfO4OToWECtR0Nsfz3
# m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsGA1UdDwQEAwIBhjAQBgkrBgEE
# AYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJgQFYnl+UlE/wq4QpTlVnkpKFj
# pGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jv
# c29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
# aXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL21pY3Jvc29mdHJvb3Rj
# ZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYBBQUHMAKGOGh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9zb2Z0Um9vdENlcnQuY3J0MBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBBQUAA4ICAQAQl4rDXANENt3p
# tK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1iuFcCy04gE1CZ3XpA4le7r1ia
# HOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+rkuTnjWrVgMHmlPIGL4UD6ZEq
# JCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGctxVEO6mJcPxaYiyA/4gcaMvnM
# MUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/FNSteo7/rvH0LQnvUU3Ih7jDK
# u3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbonXCUbKw5TNT2eb+qGHpiKe+i
# myk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0NbhOxXEjEiZ2CzxSjHFaRkMU
# vLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPpK+m79EjMLNTYMoBMJipIJF9a
# 6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2JoXZhtG6hE6a/qkfwEm/9ijJs
# sv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0eFQF1EEuUKyUsKV4q7OglnUa
# 2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng9wFlb4kLfchpyOZu6qeXzjEp
# /w7FW1zYTRuh2Povnj8uVRZryROj/TCCB3owggVioAMCAQICCmEOkNIAAAAAAAMw
# DQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhv
# cml0eSAyMDExMB4XDTExMDcwODIwNTkwOVoXDTI2MDcwODIxMDkwOVowfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKvw+nIQHC6t2G6qghBNNLrytlghn0IbKmvpWlCquAY4GgRJun/D
# DB7dN2vGEtgL8DjCmQawyDnVARQxQtOJDXlkh36UYCRsr55JnOloXtLfm1OyCizD
# r9mpK656Ca/XllnKYBoF6WZ26DJSJhIv56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW
# 9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN1Vx5pUkp5w2+oBN3vpQ97/vjK1oQH01W
# KKJ6cuASOrdJXtjt7UORg9l7snuGG9k+sYxd6IlPhBryoS9Z5JA7La4zWMW3Pv4y
# 07MDPbGyr5I4ftKdgCz1TlaRITUlwzluZH9TupwPrRkjhMv0ugOGjfdf8NBSv4yU
# h7zAIXQlXxgotswnKDglmDlKNs98sZKuHCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLE
# tVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhE
# fEXkwcNyeuBy5yTfv0aZxe/CHFfbg43sTUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L
# 50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/dygo8e1twyiPLI9AN0/B4YVEicQJTMXU
# pUMvdJX3bvh4IFgsE11glZo+TzOE2rCIF96eTvSWsLxGoGyY0uDWiIwLAgMBAAGj
# ggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3
# IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUci06AjGQQ7kUBU7h6qfHMdEj
# iTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNybDBe
# BggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNydDCB
# nwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBA
# BggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBwAG8AbABpAGMAeQBfAHMAdABh
# AHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPY
# dGcimwuWEeFjkplCln3SeQyQwWVfLiw++MNy0W2D/r4/6ArKO79HqaPzadtjvyI1
# pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJ
# RD14eiPzE32mkHSDjfTLJgJGKsKKELukqQUMm+1o+mgulaAqPyprWEljHwlpblqY
# luSD9MCP80Yr3vw70L01724lruWvJ+3Q3fMOr5kol5hNDj0L8giJ1h/DMhji8MUt
# zluetEk5CsYKwsatruWy2dsViFFFWDgycScaf7H0J/jeLDogaZiyWYlobm+nt3TD
# QAUGpgEqKD6CPxNNZgvAs0314Y9/HG8VfUWnduVAKmWjw11SYobDHWM2l4bf2vP4
# 8hahmifhzaWX0O5dY0HjWwechz4GdwbRBrF1HxS+YWG18NzGGwS+30HHDiju3mUv
# 7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/QACnFsZulP0V3HjXG0qKin3p6IvpIlR+r
# +0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL/9azI2h15q/6/IvrC4DqaTuv/DDtBEyO
# 3991bWORPdGdVk5Pv4BXIqF4ETIheu9BCrE/+6jMpF3BoYibV3FWTkhFwELJm3Zb
# CoBIa/15n8G9bW1qyVJzEw16UM0xggSAMIIEfAIBATCBlTB+MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29k
# ZSBTaWduaW5nIFBDQSAyMDExAhMzAAABUptAn1BWmXWIAAAAAAFSMAkGBSsOAwIa
# BQCggZQwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCKA7TFQZ7OJ8W4Mt/OJYxxh
# +mQRMDQGCisGAQQBgjcCAQwxJjAkoBKAEABUAGUAcwB0AFMAaQBnAG6hDoAMaHR0
# cDovL3Rlc3QgMA0GCSqGSIb3DQEBAQUABIIBAKZYtPintzb6h4RT1KgnPPRskyiK
# a3bqvgI2qP1GIX/2t9N620hyBXa+QPX6gkRtAGDp7O3Bxh/RJw9Av3FQKipHW80b
# HiGgeb9RoD6ekrtg11TQPQ61VhLgrot4j5NohEIayALgS5jT/XhQYYE0pbAkwmO8
# lk8vosqRV/PrPA5WbZ5Qdb2Il/E2eWx03qztbvM6ykyYUNRBnUjeiYF1NZQqKLRB
# FQhxYwIyVWIJYe4CJapYAZI8/wNP9pIRTvwwobH7jhlxBSnP3R+IPxXHksPqKBJI
# nFsMy6bA70IxLWNDVn8dteBphILWY8dx9InHFxIJ9FEGw6AbJpx8OCqT5EShggIo
# MIICJAYJKoZIhvcNAQkGMYICFTCCAhECAQEwgY4wdzELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBAhMzAAABS9X1+5YMhCxzAAAAAAFLMAkGBSsOAwIaBQCgXTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMDAzMTAyMjUxMDFa
# MCMGCSqGSIb3DQEJBDEWBBTMyP9Nlw/9oQiYQWrTGAmOBeP2WjANBgkqhkiG9w0B
# AQUFAASCAQDNM6A6PBcl/u6OZY5gGIqQHDsVsVdU9R3YzoEBRUK4hCgDnhUXByw+
# u642hm8VW87BRxauOzo001DnZug05VW+zWRoxLEDQJJwq4ja3Xi3BMQ72GrRgpbO
# niaaYjx1Ro/ACbDqawhBj9IKq+E37CO0RMi5Hlp28V5Go1rFzOnBRoVrwERu8os6
# 3ZOM6FcLFlFExCN6z+je+suwlD8Gyli3xsVQD+c0A72W96OKC78aw6B4xoX2iaVV
# j3Cecl0Sctrq2phwH/MF1Vdif8umEX+ja9BYtOWRidKAN+667jJ+mAvwI77xoQqD
# EThiBEm4cUb+ucSRp2d6pBjzGefRpqcj
# SIG # End signature block

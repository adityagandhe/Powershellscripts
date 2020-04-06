@{

# Script module or binary module file associated with this manifest.
RootModule = 'Microsoft.PowerApps.Administration.Powershell.psm1'

# Version number of this module.
ModuleVersion = '2.0.45'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '1c40b0da-ee6a-4226-9a3d-e60092e1daae'

# Author of this module
Author = 'Microsoft Common Data Service Team'

# Company or vendor of this module
CompanyName = 'Microsoft'

# Copyright statement for this module
Copyright = '© 2019 Microsoft Corporation. All rights reserved'

# Description of the functionality provided by this module
Description = 'PowerShell interface for Microsoft PowerApps and Flow Administrative features'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = '1.0'

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.0.0.0'

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
#RequiredModules = @(@{ModuleName = "Microsoft.PowerApps.RestClientModule"; ModuleVersion = "1.0"; Guid = "04800678-e13e-4b41-8d46-424e707ea733"}) 
#RequiredModules = @(@{ModuleName = "Microsoft.PowerApps.RestClientModule"; ModuleVersion = "1.0"; Guid = "04800678-e13e-4b41-8d46-424e707ea733"}) 

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @("Microsoft.IdentityModel.Clients.ActiveDirectory.dll", "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll")

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
#NestedModules = @('Microsoft.PowerApps.AuthModule', 'Microsoft.PowerApps.RestClientModule')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'New-AdminPowerAppCdsDatabase', `
    'Get-AdminPowerAppCdsDatabaseLanguages', `
    'Get-AdminPowerAppCdsDatabaseCurrencies', `
    'Get-AdminPowerAppEnvironmentLocations', `
    'Get-AdminPowerAppCdsDatabaseTemplates', `
    'New-AdminPowerAppEnvironment', `
    'Set-AdminPowerAppEnvironmentDisplayName', `
    'Get-AdminPowerAppEnvironment', `
    'Get-AdminPowerAppSoftDeletedEnvironment', `
    'Remove-AdminPowerAppEnvironment', `
    'Recover-AdminPowerAppEnvironment', `
    'Get-AdminPowerAppEnvironmentRoleAssignment', `
    'Set-AdminPowerAppEnvironmentRoleAssignment', `
    'Remove-AdminPowerAppEnvironmentRoleAssignment', `
    'Get-AdminPowerApp', `
    'Remove-AdminPowerApp', `
    'Get-AdminPowerAppRoleAssignment', `
    'Remove-AdminPowerAppRoleAssignment', `
    'Set-AdminPowerAppRoleAssignment', `
    'Set-AdminPowerAppOwner', `
    'Get-AdminFlow', `
    'Enable-AdminFlow', `
    'Disable-AdminFlow', `
    'Remove-AdminFlow', `
	'Remove-AdminFlowApprovals', `
    'Set-AdminFlowOwnerRole', `
    'Remove-AdminFlowOwnerRole', `
    'Get-AdminFlowOwnerRole', `
	'Get-AdminPowerAppConnector',
	'Get-AdminPowerAppConnectorRoleAssignment', `
	'Set-AdminPowerAppConnectorRoleAssignment', `
	'Remove-AdminPowerAppConnectorRoleAssignment', `
    'Remove-AdminPowerAppConnector', `
    'Get-AdminPowerAppConnection', `
    'Remove-AdminPowerAppConnection', `
    'Get-AdminPowerAppConnectionRoleAssignment', `
    'Set-AdminPowerAppConnectionRoleAssignment', `
    'Remove-AdminPowerAppConnectionRoleAssignment', `
	'Get-AdminPowerAppsUserDetails', `
    'Get-AdminFlowUserDetails', `
    'Remove-AdminFlowUserDetails', `
    'Set-AdminPowerAppAsFeatured', `
    'Clear-AdminPowerAppAsFeatured', `
    'Set-AdminPowerAppAsHero', `
    'Clear-AdminPowerAppAsHero', `
    'Set-AdminPowerAppApisToBypassConsent', `
    'Clear-AdminPowerAppApisToBypassConsent', `
    'Get-AdminDlpPolicy', `
    'New-AdminDlpPolicy', `
    'Remove-AdminDlpPolicy', `
    'Set-AdminDlpPolicy', `
    'Add-ConnectorToBusinessDataGroup', `
    'Remove-ConnectorFromBusinessDataGroup', `
    'Get-AdminPowerAppConnectionReferences', `
    'Add-CustomConnectorToPolicy', `
    'Remove-CustomConnectorFromPolicy', `
    'Remove-LegacyCDSDatabase', `
    #from Rest and Auth Module Helpers
    'Select-CurrentEnvironment', `
    'Add-PowerAppsAccount', `
    'Remove-PowerAppsAccount',`
    'Test-PowerAppsAccount', `
    'Get-TenantDetailsFromGraph', `
    'Get-UsersOrGroupsFromGraph', `
    'Get-JwtToken', `
    'ReplaceMacro', `
    'Set-TenantSettings', `
	'Get-TenantSettings', `
    'InvokeApi', `
    'InvokeApiNoParseContent', `
    'Add-AdminPowerAppsSyncUser', `
    'Remove-AllowedConsentPlans', `
    'Add-AllowedConsentPlans', `
    'Get-AllowedConsentPlans', `
	'Get-AdminPowerAppCdsAdditionalNotificationEmails', `
	'Set-AdminPowerAppCdsAdditionalNotificationEmails', `
    'Get-AdminPowerAppLicenses'
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
# CmdletsToExport = @()

# Variables to export from this module
# VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
# AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
ModuleList = @("Microsoft.PowerApps.Administration.PowerShell" )# , "Microsoft.PowerApps.AuthModule" , "Microsoft.PowerApps.RestClientModule.psm1"  )

# List of all files packaged with this module
FileList = @(
    "Microsoft.PowerApps.Administration.PowerShell.psm1", `
    "Microsoft.PowerApps.Administration.PowerShell.psd1", `
    "Microsoft.PowerApps.AuthModule.psm1", `
    "Microsoft.PowerApps.RestClientModule.psm1", `
    "Microsoft.IdentityModel.Clients.ActiveDirectory.dll", `
    "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" `
)

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
         LicenseUri = 'https://aka.ms/powerappspowershellprereleaseterms'

        # A URL to the main website for this project.
         ProjectUri = 'https://docs.microsoft.com/en-us/powerapps/administrator/powerapps-powershell'

        # A URL to an icon representing this module.
         IconUri = 'https://connectoricons-prod.azureedge.net/powerplatformforadmins/icon_1.0.1056.1255.png'

        # ReleaseNotes of this module
         ReleaseNotes = 'https://docs.microsoft.com/en-us/powerapps/administrator/powerapps-powershell'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = 'PowerApp'

}

# SIG # Begin signature block
# MIIdhAYJKoZIhvcNAQcCoIIddTCCHXECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5x0ciHpGz8fyTmZfBMmQTuSY
# duWgghhuMIIE2jCCA8KgAwIBAgITMwAAAUvV9fuWDIQscwAAAAABSzANBgkqhkiG
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
# MAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFImsn4297Z2MeFZ+gq2/DvIf
# bCJBMDQGCisGAQQBgjcCAQwxJjAkoBKAEABUAGUAcwB0AFMAaQBnAG6hDoAMaHR0
# cDovL3Rlc3QgMA0GCSqGSIb3DQEBAQUABIIBAFQ7YUO3UbzJVnCgWyejsNDaud/Y
# UsCDPc7bTArNcDVJgH7udYPOeGL1l0QF2o3Mz1bV5C3pdSZCzvkhkb4/U0DZv5Jd
# EvZo+SFjDZUl+Sch8Lc8ABVTIbxbCqoxosaTH4P5K3piZCXc/xgH1Az8bjbyxDqQ
# zlXx727xIKyhQ9DxwntLZZ8K5C+xsLRv/fMZyloRjLroGeX/riI9wLVYqTZiMKRv
# opWSowmOCDqKOBwCbscXbCFU++fCvDFQ/3Mt891x+jrH7qD/mFvXptpxt6kKjNfd
# flmX6Ajm28jNZkGnzkZBNMNH/oYaS1Y+V8EogCrU8fTvJ2IU4LVyITC5tE+hggIo
# MIICJAYJKoZIhvcNAQkGMYICFTCCAhECAQEwgY4wdzELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBAhMzAAABS9X1+5YMhCxzAAAAAAFLMAkGBSsOAwIaBQCgXTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMDAzMTAyMjUxMDBa
# MCMGCSqGSIb3DQEJBDEWBBTVGWghuh7C6ZY/RD45lwYwwuv5mTANBgkqhkiG9w0B
# AQUFAASCAQBGfbgN1AbfEPUlyeYdWtuq10cJ+ghhv7KivYK3q3qwxrT7M+1C37p5
# X0i2gBbDAGACh+FDIKOCNNqoOTQPJCIru3Tca3L1/mNJv/U9hTen2sVVbheBDW8d
# +T+LjEVacQ6JUlqXgL6hM++fp0eEzyHI6OT07cwmaLGnqIpbIo1/D6Uj2WxwvzvD
# vpVBXoQzfLtau8VaPeoFsFLNPnrWC2qZTtAyorYY50tCT5gV50thO61AlxIhGJ5v
# vrFrICtHywC9hcZLHb4FK9LivfcpZ5ogxH4As2GNFhRREtw1HpT6gIuCP3oGZP91
# GTINKuSAVRegcUCh+4iE0sQ3SRMUAmVM
# SIG # End signature block

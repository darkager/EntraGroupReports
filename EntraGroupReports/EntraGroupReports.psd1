@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'EntraGroupReports.psm1'

    # Version number of this module.
    ModuleVersion     = '1.2.3'

    # Supported PSEditions
    CompatiblePSEditions = @('Core', 'Desktop')

    # ID used to uniquely identify this module
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'

    # Author of this module
    Author            = 'EntraGroupReports Project'

    # Company or vendor of this module
    CompanyName       = 'Unknown'

    # Copyright statement for this module
    Copyright         = '(c) 2025. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'PowerShell module for reporting on Entra ID groups. Provides functions to query and report on group membership, directory role assignments, and Privileged Identity Management (PIM) eligibility and assignments.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Beta.Applications'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Beta.Groups'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Beta.Identity.Governance'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Beta.Users'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Identity.Governance'; ModuleVersion = '2.0.0' }
    )

    # Functions to export from this module - using approved verbs only
    FunctionsToExport = @(
        'Get-PIMGroupEligibility',
        'Get-PIMGroupAssignment',
        'Get-PIMGroup',
        'Get-PIMGroups',
        'Get-PIMGroupsLegacy',
        'Export-PIMGroupReport',
        'Get-GroupDirectoryRoles',
        'Export-EntraGroupReport'
    )

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport   = @()

    # List of all files packaged with this module
    FileList          = @(
        'EntraGroupReports.psd1',
        'EntraGroupReports.psm1',
        'Public\Get-PIMGroupEligibility.ps1',
        'Public\Get-PIMGroupAssignment.ps1',
        'Public\Get-PIMGroup.ps1',
        'Public\Get-PIMGroups.ps1',
        'Public\Get-PIMGroupsLegacy.ps1',
        'Public\Export-PIMGroupReport.ps1',
        'Public\Get-GroupDirectoryRoles.ps1',
        'Public\Export-EntraGroupReport.ps1'
    )

    # Private data to pass to the module specified in RootModule
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module - helps with discoverability
            Tags         = @('PIM', 'PrivilegedIdentityManagement', 'AzureAD', 'MicrosoftGraph', 'Groups', 'EntraID', 'Identity', 'Governance', 'Security')

            # A URL to the license for this module
            LicenseUri   = ''

            # A URL to the main website for this project
            ProjectUri   = ''

            # A URL to an icon representing this module
            IconUri      = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
## Version 1.2.3
- Added missing module dependencies: Microsoft.Graph.Authentication, Microsoft.Graph.Beta.Applications
  - Required for Invoke-MgGraphRequest and Get-MgBetaServicePrincipal cmdlets

## Version 1.2.2
- Performance improvement: Replaced generic arrays and hashtables with strongly-typed generic collections
  - Lists use System.Collections.Generic.List[T] instead of @() arrays
  - Dictionaries use System.Collections.Generic.Dictionary[TKey,TValue] instead of @{} hashtables

## Version 1.2.1
- Initial public release to GitHub

## Version 1.2.0
- Renamed module from GraphPIMGroups to EntraGroupReports
- Added MembershipType column to summary report (Assigned, DynamicUser, DynamicDevice)
- Fixed PowerShell 5.1 compatibility (removed null-coalescing operator)
- Added README.md documentation

## Version 1.1.0
- Added Get-GroupDirectoryRoles: Retrieve directory role assignments for role-assignable groups
- Added Export-EntraGroupReport: Generate comprehensive security reports for all Entra ID groups
  - Summary report with counts (members, owners, directory roles, PIM eligibility/assignments)
  - Detail report with flattened data (Membership, DirectoryRole, PIMAccess record categories)
  - Supports transitive group member expansion

## Version 1.0.0
- Initial release
- Get-PIMGroupEligibility: Retrieve eligibility schedules and instances for PIM groups
- Get-PIMGroupAssignment: Retrieve assignment schedules and instances for PIM groups
- Get-PIMGroup: Composite function for retrieving full PIM data for a single group
- Get-PIMGroups: List all PIM-enabled groups using the new identityGovernance API (Global cloud only)
- Get-PIMGroupsLegacy: List all PIM-enabled groups using the legacy privilegedAccess API (deprecated Oct 2026)
- Export-PIMGroupReport: Generate comprehensive CSV report of all PIM group data with resolved principal names
'@

            # Prerelease string of this module (remove for production release)
            # Prerelease = 'alpha'

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            RequireLicenseAcceptance = $false

            # External dependent modules of this module
            ExternalModuleDependencies = @()
        }
    }

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Beta.Applications, Microsoft.Graph.Beta.Groups, Microsoft.Graph.Beta.Identity.Governance, Microsoft.Graph.Beta.Users, Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    EntraGroupReports - PowerShell module for Entra ID group reporting

.DESCRIPTION
    This module provides functions for reporting on Entra ID groups using the
    Microsoft Graph API.

    Group Reporting Functions:
    - Export-EntraGroupReport: Generate comprehensive security reports for all Entra ID groups
    - Get-GroupDirectoryRoles: Get directory role assignments for a group

    PIM Group Functions:
    - Get-PIMGroupEligibility: Get eligibility schedules and instances
    - Get-PIMGroupAssignment: Get assignment schedules and instances
    - Get-PIMGroup: Get comprehensive PIM data for a single group
    - Get-PIMGroups: List all PIM-enabled groups (new API)
    - Get-PIMGroupsLegacy: List all PIM-enabled groups (legacy API)
    - Export-PIMGroupReport: Generate CSV report of PIM group data

.NOTES
    Author: EntraGroupReports Project
    Requires: Microsoft.Graph.Authentication
    Requires: Microsoft.Graph.Beta.Applications
    Requires: Microsoft.Graph.Beta.Groups
    Requires: Microsoft.Graph.Beta.Identity.Governance
    Requires: Microsoft.Graph.Beta.Users
    Requires: Microsoft.Graph.Identity.Governance

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagement-for-groups-api-overview
#>

# Get public and private function definition files
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)

# Dot source the files
foreach ($import in @($Public + $Private)) {
    try {
        Write-Verbose "Importing function: $($import.BaseName)"
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

# Export only the public functions (functions in Public folder)
Export-ModuleMember -Function $Public.BaseName

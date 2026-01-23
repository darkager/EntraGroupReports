# EntraGroupReports

PowerShell module for reporting on Microsoft Entra ID groups. Provides functions to query and report on group membership, directory role assignments, and Privileged Identity Management (PIM) eligibility and assignments.

## Table of Contents

- [Prerequisites](#prerequisites)
  - [Required Permissions](#required-permissions)
- [Installation](#installation)
- [Connection](#connection)
- [Export Commands](#export-commands)
  - [Export-EntraGroupReport](#export-entragroupreport)
  - [Summary Report Columns](#summary-report-columns)
  - [Detail Report](#detail-report)
  - [Sample Output](#sample-output)
- [Other Functions](#other-functions)
  - [Get-PIMGroup](#get-pimgroup)
  - [Get-PIMGroups](#get-pimgroups)
  - [Get-PIMGroupsLegacy](#get-pimgroupslegacy)
  - [Get-GroupDirectoryRoles](#get-groupdirectoryroles)
  - [Get-PIMGroupEligibility](#get-pimgroupeligibility)
  - [Get-PIMGroupAssignment](#get-pimgroupassignment)
- [Performance](#performance)
- [Notes](#notes)
- [Changelog](#changelog)
- [License](#license)

## Prerequisites

- PowerShell 5.1 or later (PowerShell 7+ recommended)
- Microsoft Graph PowerShell SDK modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Beta.Applications`
  - `Microsoft.Graph.Beta.Groups`
  - `Microsoft.Graph.Beta.Identity.Governance`
  - `Microsoft.Graph.Beta.Users`
  - `Microsoft.Graph.Identity.Governance`

### Required Permissions

| Scope | Required For |
|-------|--------------|
| `Group.Read.All` | Reading group information |
| `GroupMember.Read.All` | Reading group membership |
| `User.Read.All` | Resolving user display names |
| `Application.Read.All` | Resolving service principal names |
| `RoleManagement.Read.Directory` | Reading directory role assignments |
| `PrivilegedAccess.Read.AzureADGroup` | Legacy PIM group discovery |
| `PrivilegedEligibilitySchedule.Read.AzureADGroup` | Reading PIM eligibility data |
| `PrivilegedAssignmentSchedule.Read.AzureADGroup` | Reading PIM assignment data |

## Installation

1. Install the required Microsoft Graph modules:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Applications -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Identity.Governance -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser
```

2. Clone or download this repository

3. Import the module:

```powershell
Import-Module .\EntraGroupReports\EntraGroupReports.psd1
```

## Connection

Connect to Microsoft Graph with the required scopes before using the module:

```powershell
Connect-MgGraph -Scopes @(
    'Group.Read.All',
    'GroupMember.Read.All',
    'User.Read.All',
    'Application.Read.All',
    'RoleManagement.Read.Directory',
    'PrivilegedAccess.Read.AzureADGroup',
    'PrivilegedEligibilitySchedule.Read.AzureADGroup',
    'PrivilegedAssignmentSchedule.Read.AzureADGroup'
)
```

### Minimal Scopes

For membership-only reporting (no PIM or directory roles):

```powershell
Connect-MgGraph -Scopes 'Group.Read.All', 'GroupMember.Read.All', 'User.Read.All'
```

## Export Commands

### Export-EntraGroupReport

The primary export function that generates comprehensive CSV reports for all Entra ID groups. Creates two files: a summary report and a detailed report.

```powershell
# Export all groups with full security data
Export-EntraGroupReport

# Export to specific path
Export-EntraGroupReport -OutputPath "C:\Reports\EntraGroups"
# Creates: C:\Reports\EntraGroups-Summary.csv and C:\Reports\EntraGroups-Report.csv

# Export specific groups only
Export-EntraGroupReport -GroupIds "abc-123-...", "def-456-..."

# Export membership only (faster, no PIM or directory role data)
Export-EntraGroupReport -IncludePIMData:$false -IncludeDirectoryRoles:$false

# Expand nested group membership
Export-EntraGroupReport -ExpandGroupMembers
```

### Summary Report Columns

| Column | Description |
|--------|-------------|
| GroupId | Group GUID |
| DisplayName | Group display name |
| GroupType | M365, Security, Distribution, or Other |
| MembershipType | Assigned, DynamicUser, or DynamicDevice |
| MembershipRule | Dynamic membership filter expression (null for assigned groups) |
| SecurityEnabled | Boolean |
| MailEnabled | Boolean |
| IsAssignableToRole | Boolean (role-assignable group) |
| IsPIMEnabled | Boolean (PIM-enabled group) |
| MemberCount | Direct member count |
| OwnerCount | Owner count |
| DirectoryRoleCount | Number of directory roles assigned |
| PIMEligible_Members | PIM member eligibility count |
| PIMEligible_Owners | PIM owner eligibility count |
| PIMAssigned_Members | PIM member assignment count |
| PIMAssigned_Owners | PIM owner assignment count |

### Detail Report

The detail report uses a `RecordCategory` column to distinguish record types:

- **Membership** - Group members and owners (direct and inherited)
- **DirectoryRole** - Directory roles assigned to the group
- **PIMAccess** - PIM eligibility and assignment records

### Sample Output

**Summary Report** (`*-Summary.csv`):

| GroupId | DisplayName | GroupType | MembershipType | MembershipRule | IsPIMEnabled | MemberCount |
|---------|-------------|-----------|----------------|----------------|--------------|-------------|
| abc-123... | IT Admins | Security | Assigned | | True | 15 |
| def-456... | HR Team | M365 | DynamicUser | (user.department -eq "HR") | False | 42 |
| ghi-789... | Global Admins | Security | Assigned | | True | 3 |

**Detail Report** (`*-Report.csv`):

| GroupId | GroupDisplayName | RecordCategory | RecordType | PrincipalDisplayName | PrincipalType | AccessType | RoleDisplayName | StartDateTime | EndDateTime |
|---------|------------------|----------------|------------|---------------------|---------------|------------|-----------------|---------------|-------------|
| abc-123... | IT Admins | Membership | DirectMember | John Smith | User | member | | | |
| abc-123... | IT Admins | Membership | Owner | Jane Doe | User | owner | | | |
| abc-123... | IT Admins | DirectoryRole | ActiveAssignment | | | | User Administrator | | |
| abc-123... | IT Admins | PIMAccess | EligibilitySchedule | Alex Johnson | User | member | | 2024-01-01 | 2024-12-31 |
| abc-123... | IT Admins | PIMAccess | AssignmentInstance | Service Account | ServicePrincipal | member | | 2024-06-01 | |

> **Note:** Large environments can generate substantial reports. One environment produced over 250,000 rows in the detail report. Use `-IncludePIMData:$false` and `-IncludeDirectoryRoles:$false` for faster membership-only exports.

## Other Functions

### Get-PIMGroup

Gets comprehensive PIM data for a single group.

```powershell
Get-PIMGroup -GroupId "12345678-1234-1234-1234-123456789012"
```

### Get-PIMGroups

Lists all PIM-enabled groups using the new identityGovernance API.

```powershell
Get-PIMGroups
```

### Get-PIMGroupsLegacy

Lists all PIM-enabled groups using the legacy privilegedAccess API.

> **Note:** This function uses a deprecated API that will be retired on October 28, 2026. Use `Get-PIMGroups` instead where possible.

```powershell
Get-PIMGroupsLegacy
```

### Get-GroupDirectoryRoles

Gets directory role assignments for a specific group.

```powershell
Get-GroupDirectoryRoles -GroupId "12345678-1234-1234-1234-123456789012"
```

### Get-PIMGroupEligibility

Gets eligibility schedules and instances for PIM groups.

```powershell
Get-PIMGroupEligibility -GroupId "12345678-1234-1234-1234-123456789012"
```

### Get-PIMGroupAssignment

Gets assignment schedules and instances for PIM groups.

```powershell
Get-PIMGroupAssignment -GroupId "12345678-1234-1234-1234-123456789012"
```

## Performance

### Strongly-Typed Collections

This module uses strongly-typed .NET generic collections instead of PowerShell's native arrays and hashtables for improved performance in large environments.

**Why this matters:** PowerShell arrays (`@()`) are immutable. Every `+=` operation creates a new array, copies all existing elements, and adds the new item. This becomes exponentially slower as the collection grows. In environments with 250,000+ records, this can cause significant delays.

**Collections used:**

| PowerShell Native | .NET Generic Replacement | Use Case |
|-------------------|--------------------------|----------|
| `@()` with `+=` | `System.Collections.Generic.List[T]` | Report data rows, group members |
| `@{}` | `System.Collections.Generic.Dictionary[TKey,TValue]` | Principal cache, group member cache, PIM-enabled group lookup |

**Example - Array vs List:**

```powershell
# Slow - creates new array on each iteration
$data = @()
foreach ($item in $items) {
    $data += [PSCustomObject]@{ Name = $item }  # O(n) copy each time
}

# Fast - appends in-place
$data = New-Object -TypeName "System.Collections.Generic.List[PSCustomObject]"
foreach ($item in $items) {
    $data.Add([PSCustomObject]@{ Name = $item })  # O(1) amortized
}
```

**Example - Hashtable vs Dictionary:**

```powershell
# Standard PowerShell hashtable
$cache = @{}
$cache[$key] = $value

# Strongly-typed dictionary with better performance for large datasets
$cache = New-Object -TypeName "System.Collections.Generic.Dictionary[[String],[PSCustomObject]]"
$cache.Add($key, $value)
```

**Types used in this module:**

- `List[PSCustomObject]` - Summary data, detail data, group members
- `List[Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphGroup]` - Groups to process
- `Dictionary[[String],[PSCustomObject]]` - Principal info cache
- `Dictionary[[String],[List[PSCustomObject]]]` - Group transitive member cache
- `Dictionary[[String],[bool]]` - PIM-enabled group ID lookup

## Notes

- Role-assignable groups (`IsAssignableToRole = $true`) are required for directory role assignments.
- PIM-enabled groups are groups that have been onboarded to Privileged Identity Management for Groups.

## Changelog

### Version 1.2.7
- Remove deprecated `Export-PIMGroupReport` function (superseded by `Export-EntraGroupReport`)
- Add `MembershipRule` column to summary report for dynamic group filter expressions
- Restructure README with table of contents and anchor links

### Version 1.2.6
- Added Performance section to README documenting strongly-typed collections
- Added detailed Performance Considerations section to research.md with code examples and usage patterns

### Version 1.2.5
- Added sample output tables for `Export-EntraGroupReport` summary and detail reports in documentation
- Added note about large environment report sizes (250,000+ rows observed)

### Version 1.2.4
- Added `PrivilegedAccess.Read.AzureADGroup` to required scopes documentation
  - Required for the legacy `/privilegedAccess/aadGroups/resources` endpoint used by `Get-PIMGroupsLegacy`

### Version 1.2.3
- Added missing module dependencies: `Microsoft.Graph.Authentication`, `Microsoft.Graph.Beta.Applications`
  - Required for `Invoke-MgGraphRequest` and `Get-MgBetaServicePrincipal` cmdlets

### Version 1.2.2
- Performance improvement: Replaced generic arrays and hashtables with strongly-typed generic collections
  - Lists use `System.Collections.Generic.List[T]` instead of `@()` arrays
  - Dictionaries use `System.Collections.Generic.Dictionary[TKey,TValue]` instead of `@{}` hashtables

### Version 1.2.1
- Initial public release to GitHub

### Version 1.2.0
- Renamed module from GraphPIMGroups to EntraGroupReports
- Added MembershipType column to summary report (Assigned, DynamicUser, DynamicDevice)
- Fixed PowerShell 5.1 compatibility (removed null-coalescing operator)
- Added README.md documentation

### Version 1.1.0
- Added Get-GroupDirectoryRoles: Retrieve directory role assignments for role-assignable groups
- Added Export-EntraGroupReport: Generate comprehensive security reports for all Entra ID groups
  - Summary report with counts (members, owners, directory roles, PIM eligibility/assignments)
  - Detail report with flattened data (Membership, DirectoryRole, PIMAccess record categories)
  - Supports transitive group member expansion

### Version 1.0.0
- Initial release
- Get-PIMGroupEligibility: Retrieve eligibility schedules and instances for PIM groups
- Get-PIMGroupAssignment: Retrieve assignment schedules and instances for PIM groups
- Get-PIMGroup: Composite function for retrieving full PIM data for a single group
- Get-PIMGroups: List all PIM-enabled groups using the new identityGovernance API (Global cloud only)
- Get-PIMGroupsLegacy: List all PIM-enabled groups using the legacy privilegedAccess API (deprecated Oct 2026)

## License

MIT License

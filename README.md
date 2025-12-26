# EntraGroupReports

PowerShell module for reporting on Microsoft Entra ID groups. Provides functions to query and report on group membership, directory role assignments, and Privileged Identity Management (PIM) eligibility and assignments.

## Requirements

- PowerShell 5.1 or later (PowerShell 7+ recommended)
- Microsoft Graph PowerShell SDK modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Beta.Applications`
  - `Microsoft.Graph.Beta.Groups`
  - `Microsoft.Graph.Beta.Identity.Governance`
  - `Microsoft.Graph.Beta.Users`
  - `Microsoft.Graph.Identity.Governance`

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

## Authentication

Connect to Microsoft Graph with the required scopes before using the module:

```powershell
Connect-MgGraph -Scopes @(
    'Group.Read.All',
    'GroupMember.Read.All',
    'User.Read.All',
    'Application.Read.All',
    'RoleManagement.Read.Directory',
    'PrivilegedEligibilitySchedule.Read.AzureADGroup',
    'PrivilegedAssignmentSchedule.Read.AzureADGroup'
)
```

### Minimal Scopes

For membership-only reporting (no PIM or directory roles):

```powershell
Connect-MgGraph -Scopes 'Group.Read.All', 'GroupMember.Read.All', 'User.Read.All'
```

## Functions

### Group Reporting

| Function | Description |
|----------|-------------|
| `Export-EntraGroupReport` | Generates comprehensive CSV reports for all Entra ID groups |
| `Get-GroupDirectoryRoles` | Gets directory role assignments for a specific group |

### PIM Group Functions

| Function | Description |
|----------|-------------|
| `Get-PIMGroupEligibility` | Gets eligibility schedules and instances for PIM groups |
| `Get-PIMGroupAssignment` | Gets assignment schedules and instances for PIM groups |
| `Get-PIMGroup` | Gets comprehensive PIM data for a single group |
| `Get-PIMGroups` | Lists all PIM-enabled groups (new API) |
| `Get-PIMGroupsLegacy` | Lists all PIM-enabled groups (legacy API, deprecated Oct 2026) |
| `Export-PIMGroupReport` | Generates CSV report of PIM group data |

## Usage Examples

### Export Comprehensive Group Report

Generates two CSV files: a summary and a detailed report.

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

### Export PIM-Only Report

```powershell
# Export PIM data for all PIM-enabled groups
Export-PIMGroupReport

# Export with transitive group member expansion
Export-PIMGroupReport -ExpandGroupMembers

# Use legacy API for group discovery
Export-PIMGroupReport -UseLegacyDiscovery
```

### Query Individual Groups

```powershell
# Get PIM data for a specific group
Get-PIMGroup -GroupId "12345678-1234-1234-1234-123456789012"

# Get directory roles for a group
Get-GroupDirectoryRoles -GroupId "12345678-1234-1234-1234-123456789012"

# Get PIM eligibility data
Get-PIMGroupEligibility -GroupId "12345678-1234-1234-1234-123456789012"

# Get PIM assignment data
Get-PIMGroupAssignment -GroupId "12345678-1234-1234-1234-123456789012"
```

## Notes

- The `Get-PIMGroupsLegacy` function uses a deprecated API that will be retired on October 28, 2026. Use `Get-PIMGroups` instead where possible.
- Role-assignable groups (`IsAssignableToRole = $true`) are required for directory role assignments.
- PIM-enabled groups are groups that have been onboarded to Privileged Identity Management for Groups.

## Changelog

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
- Export-PIMGroupReport: Generate comprehensive CSV report of all PIM group data with resolved principal names

## License

MIT License

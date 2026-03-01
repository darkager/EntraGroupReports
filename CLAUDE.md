# EntraGroupReports

PowerShell module (v1.2.7) for reporting on Microsoft Entra ID groups. Generates comprehensive security-focused CSV reports covering group membership, directory role assignments, and Privileged Identity Management (PIM) eligibility and assignments.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | PowerShell 5.1+ (PowerShell 7+ recommended) |
| API | Microsoft Graph PowerShell SDK (v1.0 + Beta endpoints) |
| Module format | `.psm1` / `.psd1` manifest |

## Directory Structure

| Path | Content |
|------|---------|
| `EntraGroupReports/EntraGroupReports.psm1` | Module root — dot-sources Public and Private functions |
| `EntraGroupReports/EntraGroupReports.psd1` | Module manifest (version, required modules, exports) |
| `EntraGroupReports/Public/` | Exported cmdlets |
| `EntraGroupReports/Private/` | Internal helpers |
| `Remove-EntraGroups.ps1` | Standalone script for bulk group removal |
| `research.md` | Research notes |
| `_pp/meta.md` | Project metadata |

## Public Cmdlets

| Cmdlet | Description |
|--------|-------------|
| `Export-EntraGroupReport` | Main report generator: produces a Summary CSV and a Detail CSV for all (or specified) groups |
| `Get-PIMGroup` | Get comprehensive PIM data for a single group |
| `Get-PIMGroups` | List all PIM-enabled groups (new Microsoft Graph API) |
| `Get-PIMGroupsLegacy` | List all PIM-enabled groups (legacy API) |
| `Get-GroupDirectoryRoles` | Get directory role assignments for a group |
| `Get-PIMGroupEligibility` | Get PIM eligibility schedules and instances for a group |
| `Get-PIMGroupAssignment` | Get PIM assignment schedules and instances for a group |

### Export-EntraGroupReport Output

Generates two CSV files (base path configurable via `-OutputPath`):

- `*-Summary.csv` — one row per group; member/owner/role/PIM counts for quick triage
- `*-Report.csv` — flattened detail rows; `RecordCategory` column distinguishes `Membership`, `DirectoryRole`, `PIMAccess`

Parameters: `-OutputPath`, `-GroupIds` (scope to specific groups), `-IncludePIMData` (default `$true`), `-IncludeDirectoryRoles` (default `$true`)

## Installation & Usage

```powershell
# Install required Graph modules
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Applications -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Identity.Governance -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser

# Connect with required scopes
Connect-MgGraph -Scopes "Group.Read.All","GroupMember.Read.All","User.Read.All","Application.Read.All","RoleManagement.Read.Directory","PrivilegedAccess.Read.AzureADGroup","PrivilegedEligibilitySchedule.Read.AzureADGroup","PrivilegedAssignmentSchedule.Read.AzureADGroup"

# Import module
Import-Module .\EntraGroupReports\EntraGroupReports.psd1

# Generate full tenant report
Export-EntraGroupReport -OutputPath C:\Reports\EntraGroups

# Scope to specific groups
Export-EntraGroupReport -OutputPath C:\Reports\EntraGroups -GroupIds @("guid1","guid2")
```

## Required Graph Permissions

| Scope | Required For |
|-------|--------------|
| `Group.Read.All` | Reading group information |
| `GroupMember.Read.All` | Reading group membership |
| `User.Read.All` | Resolving user display names |
| `Application.Read.All` | Resolving service principal names |
| `RoleManagement.Read.Directory` | Directory role assignments |
| `PrivilegedAccess.Read.AzureADGroup` | Legacy PIM group discovery |
| `PrivilegedEligibilitySchedule.Read.AzureADGroup` | PIM eligibility data |
| `PrivilegedAssignmentSchedule.Read.AzureADGroup` | PIM assignment data |

## Conventions

- Public functions follow PowerShell `Verb-Noun` naming with approved verbs
- Beta Graph API endpoints used throughout (check `Get-GroupDirectoryRoles.ps1` if v1.0 vs beta matters for a specific call)
- Module auto-dot-sources all `.ps1` files under `Public/` and `Private/` at import time
- Compatible with both PowerShell 5.1 (Desktop) and 7+ (Core)

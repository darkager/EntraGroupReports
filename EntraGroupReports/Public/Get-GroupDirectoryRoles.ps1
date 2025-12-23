function Get-GroupDirectoryRoles {
    <#
    .SYNOPSIS
        Gets directory role assignments for a group.

    .DESCRIPTION
        Retrieves all Microsoft Entra directory roles that have been assigned
        or made eligible to a specified group. This includes:
        - Active role assignments (permanent)
        - PIM role eligibility schedules (can be activated)
        - PIM role assignment schedules (time-bound active)

        Only role-assignable groups (isAssignableToRole = true) can have
        directory role assignments.

    .PARAMETER GroupId
        The GUID of the group to retrieve directory role assignments for.

    .PARAMETER IncludeRoleDefinitions
        If specified, expands role definitions to include display names.
        Default is $true.

    .EXAMPLE
        Get-GroupDirectoryRoles -GroupId "12345678-1234-1234-1234-123456789012"

    .EXAMPLE
        Get-GroupDirectoryRoles -GroupId "12345678-1234-1234-1234-123456789012" -IncludeRoleDefinitions:$false

    .OUTPUTS
        PSCustomObject
        Object containing ActiveAssignments, EligibilitySchedules, and AssignmentSchedules.

    .NOTES
        Requires Microsoft.Graph.Identity.Governance module.
        Requires RoleManagement.Read.Directory or RoleManagement.Read.All permission.

        Only works for groups with isAssignableToRole = $true.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$GroupId,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeRoleDefinitions = $true
    )

    begin {
        # Cache for role definitions
        $roleDefinitionCache = @{}

        function Get-RoleDisplayName {
            param([string]$RoleDefinitionId)

            if (-not $IncludeRoleDefinitions) {
                return $null
            }

            if ($roleDefinitionCache.ContainsKey($RoleDefinitionId)) {
                return $roleDefinitionCache[$RoleDefinitionId]
            }

            try {
                $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $RoleDefinitionId -ErrorAction Stop
                $roleDefinitionCache[$RoleDefinitionId] = $roleDef.DisplayName
                return $roleDef.DisplayName
            }
            catch {
                Write-Verbose "Could not resolve role definition: $RoleDefinitionId"
                return $null
            }
        }
    }

    process {
        try {
            $result = [PSCustomObject]@{
                GroupId              = $GroupId
                ActiveAssignments    = @()
                EligibilitySchedules = @()
                AssignmentSchedules  = @()
            }

            # Get active role assignments
            Write-Verbose "Fetching active role assignments for group: $GroupId"
            try {
                $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$GroupId'" -All -ErrorAction Stop

                foreach ($assignment in $activeAssignments) {
                    $result.ActiveAssignments += [PSCustomObject]@{
                        Id               = $assignment.Id
                        RoleDefinitionId = $assignment.RoleDefinitionId
                        RoleDisplayName  = Get-RoleDisplayName -RoleDefinitionId $assignment.RoleDefinitionId
                        DirectoryScopeId = $assignment.DirectoryScopeId
                        AppScopeId       = $assignment.AppScopeId
                        AssignmentType   = 'Active'
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve active role assignments: $_"
            }

            # Get PIM role eligibility schedules
            Write-Verbose "Fetching role eligibility schedules for group: $GroupId"
            try {
                $eligibilitySchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$GroupId'" -All -ErrorAction Stop

                foreach ($schedule in $eligibilitySchedules) {
                    $endDateTime = $null
                    $expirationType = $null
                    if ($schedule.ScheduleInfo -and $schedule.ScheduleInfo.Expiration) {
                        $endDateTime = $schedule.ScheduleInfo.Expiration.EndDateTime
                        $expirationType = $schedule.ScheduleInfo.Expiration.Type
                    }

                    $result.EligibilitySchedules += [PSCustomObject]@{
                        Id               = $schedule.Id
                        RoleDefinitionId = $schedule.RoleDefinitionId
                        RoleDisplayName  = Get-RoleDisplayName -RoleDefinitionId $schedule.RoleDefinitionId
                        DirectoryScopeId = $schedule.DirectoryScopeId
                        Status           = $schedule.Status
                        MemberType       = $schedule.MemberType
                        StartDateTime    = $schedule.ScheduleInfo.StartDateTime
                        EndDateTime      = $endDateTime
                        ExpirationType   = $expirationType
                        CreatedDateTime  = $schedule.CreatedDateTime
                        AssignmentType   = 'Eligible'
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve role eligibility schedules: $_"
            }

            # Get PIM role assignment schedules
            Write-Verbose "Fetching role assignment schedules for group: $GroupId"
            try {
                $assignmentSchedules = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -Filter "principalId eq '$GroupId'" -All -ErrorAction Stop

                foreach ($schedule in $assignmentSchedules) {
                    $endDateTime = $null
                    $expirationType = $null
                    if ($schedule.ScheduleInfo -and $schedule.ScheduleInfo.Expiration) {
                        $endDateTime = $schedule.ScheduleInfo.Expiration.EndDateTime
                        $expirationType = $schedule.ScheduleInfo.Expiration.Type
                    }

                    $result.AssignmentSchedules += [PSCustomObject]@{
                        Id               = $schedule.Id
                        RoleDefinitionId = $schedule.RoleDefinitionId
                        RoleDisplayName  = Get-RoleDisplayName -RoleDefinitionId $schedule.RoleDefinitionId
                        DirectoryScopeId = $schedule.DirectoryScopeId
                        Status           = $schedule.Status
                        MemberType       = $schedule.MemberType
                        AssignmentType   = $schedule.AssignmentType
                        StartDateTime    = $schedule.ScheduleInfo.StartDateTime
                        EndDateTime      = $endDateTime
                        ExpirationType   = $expirationType
                        CreatedDateTime  = $schedule.CreatedDateTime
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve role assignment schedules: $_"
            }

            return $result
        }
        catch {
            Write-Error "Failed to retrieve directory roles for group $GroupId : $_"
            throw
        }
    }
}

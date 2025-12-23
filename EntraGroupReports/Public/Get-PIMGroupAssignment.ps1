function Get-PIMGroupAssignment {
    <#
    .SYNOPSIS
        Gets PIM assignment data for a group (principals who currently HAVE member/owner).

    .DESCRIPTION
        Retrieves both AssignmentSchedules (full schedule definitions) and
        AssignmentScheduleInstances (currently active assignments) for a PIM-enabled group.

        At least one of -GroupId or -PrincipalId is required (API constraint).

    .PARAMETER GroupId
        The GUID of the target group. Required if PrincipalId is not specified.

    .PARAMETER PrincipalId
        The GUID of the target principal. Required if GroupId is not specified.

    .PARAMETER AccessType
        Filter by access type: 'member', 'owner', or 'all'. Default is 'all'.

    .PARAMETER AssignmentType
        Filter by assignment type: 'assigned', 'activated', or 'all'. Default is 'all'.
        - 'assigned': Directly assigned (permanent or time-bound)
        - 'activated': Activated from an eligible assignment

    .EXAMPLE
        Get-PIMGroupAssignment -GroupId "12345678-1234-1234-1234-123456789012"

    .EXAMPLE
        Get-PIMGroupAssignment -PrincipalId "87654321-4321-4321-4321-210987654321"

    .EXAMPLE
        Get-PIMGroupAssignment -GroupId "12345678-1234-1234-1234-123456789012" -AccessType "owner" -AssignmentType "activated"

    .OUTPUTS
        PSCustomObject
        Custom object with Schedules and Instances properties containing PIM assignment data.

    .NOTES
        Requires Microsoft.Graph.Beta.Identity.Governance module.
        Requires PrivilegedAssignmentSchedule.Read.AzureADGroup permission.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$GroupId,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$PrincipalId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('member', 'owner', 'all')]
        [string]$AccessType = 'all',

        [Parameter(Mandatory = $false)]
        [ValidateSet('assigned', 'activated', 'all')]
        [string]$AssignmentType = 'all'
    )

    begin {
        # Validate that at least one filter is provided
        if (-not $GroupId -and -not $PrincipalId) {
            throw "At least one of -GroupId or -PrincipalId must be specified."
        }

        # Build the filter string
        $filterParts = @()
        if ($GroupId) {
            $filterParts += "groupId eq '$GroupId'"
        }
        if ($PrincipalId) {
            $filterParts += "principalId eq '$PrincipalId'"
        }
        $filter = $filterParts -join ' and '
    }

    process {
        try {
            # Get AssignmentSchedules
            Write-Verbose "Fetching AssignmentSchedules with filter: $filter"
            $schedules = Get-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentSchedule -Filter $filter -All -ErrorAction Stop

            # Get AssignmentScheduleInstances
            Write-Verbose "Fetching AssignmentScheduleInstances with filter: $filter"
            $instances = Get-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleInstance -Filter $filter -All -ErrorAction Stop

            # Filter by AccessType if specified
            if ($AccessType -ne 'all') {
                $schedules = $schedules | Where-Object { $_.AccessId -eq $AccessType }
                $instances = $instances | Where-Object { $_.AccessId -eq $AccessType }
            }

            # Filter by AssignmentType if specified
            if ($AssignmentType -ne 'all') {
                $schedules = $schedules | Where-Object { $_.AssignmentType -eq $AssignmentType }
                $instances = $instances | Where-Object { $_.AssignmentType -eq $AssignmentType }
            }

            # Return combined result
            [PSCustomObject]@{
                Schedules = $schedules
                Instances = $instances
            }
        }
        catch {
            Write-Error "Failed to retrieve PIM group assignment data: $_"
            throw
        }
    }
}

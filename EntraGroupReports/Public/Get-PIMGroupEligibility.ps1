function Get-PIMGroupEligibility {
    <#
    .SYNOPSIS
        Gets PIM eligibility data for a group (principals who CAN activate member/owner).

    .DESCRIPTION
        Retrieves both EligibilitySchedules (full schedule definitions) and
        EligibilityScheduleInstances (currently active eligibilities) for a PIM-enabled group.

        At least one of -GroupId or -PrincipalId is required (API constraint).

    .PARAMETER GroupId
        The GUID of the target group. Required if PrincipalId is not specified.

    .PARAMETER PrincipalId
        The GUID of the target principal. Required if GroupId is not specified.

    .PARAMETER AccessType
        Filter by access type: 'member', 'owner', or 'all'. Default is 'all'.

    .EXAMPLE
        Get-PIMGroupEligibility -GroupId "12345678-1234-1234-1234-123456789012"

    .EXAMPLE
        Get-PIMGroupEligibility -PrincipalId "87654321-4321-4321-4321-210987654321"

    .EXAMPLE
        Get-PIMGroupEligibility -GroupId "12345678-1234-1234-1234-123456789012" -AccessType "member"

    .OUTPUTS
        PSCustomObject
        Custom object with Schedules and Instances properties containing PIM eligibility data.

    .NOTES
        Requires Microsoft.Graph.Beta.Identity.Governance module.
        Requires PrivilegedEligibilitySchedule.Read.AzureADGroup permission.
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
        [string]$AccessType = 'all'
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
            # Get EligibilitySchedules
            Write-Verbose "Fetching EligibilitySchedules with filter: $filter"
            $schedules = Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter $filter -All -ErrorAction Stop

            # Get EligibilityScheduleInstances
            Write-Verbose "Fetching EligibilityScheduleInstances with filter: $filter"
            $instances = Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleInstance -Filter $filter -All -ErrorAction Stop

            # Filter by AccessType if specified
            if ($AccessType -ne 'all') {
                $schedules = $schedules | Where-Object { $_.AccessId -eq $AccessType }
                $instances = $instances | Where-Object { $_.AccessId -eq $AccessType }
            }

            # Return combined result
            [PSCustomObject]@{
                Schedules = $schedules
                Instances = $instances
            }
        }
        catch {
            Write-Error "Failed to retrieve PIM group eligibility data: $_"
            throw
        }
    }
}

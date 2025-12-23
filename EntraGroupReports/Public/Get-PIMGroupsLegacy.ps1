function Get-PIMGroupsLegacy {
    <#
    .SYNOPSIS
        Gets all PIM-enabled groups using the legacy privilegedAccess endpoint.

    .DESCRIPTION
        Retrieves all PIM-enabled groups from the tenant using the legacy
        /privilegedAccess/aadGroups/resources endpoint.

        WARNING: This endpoint is DEPRECATED and will be retired on October 28, 2026.
        Use Get-PIMGroups for new implementations where possible.

        This endpoint returns richer metadata than the newer endpoint, including:
        - displayName
        - type
        - status
        - registeredDateTime
        - registeredRoot
        - externalId
        - roleDefinitionCount
        - roleAssignmentCount

    .PARAMETER IncludePIMData
        If specified, retrieves full PIM eligibility and assignment data for each group
        using Get-PIMGroup. This can be slow for tenants with many PIM groups.
        Default is $true.

    .PARAMETER AccessType
        Filter by access type when IncludePIMData is true: 'member', 'owner', or 'all'.
        Default is 'all'.

    .EXAMPLE
        Get-PIMGroupsLegacy
        # Returns all PIM-enabled groups with legacy metadata and PIM data

    .EXAMPLE
        Get-PIMGroupsLegacy -IncludePIMData:$false
        # Returns only legacy metadata (faster, no eligibility/assignment data)

    .EXAMPLE
        Get-PIMGroupsLegacy -AccessType "member"
        # Returns PIM data filtered to member access only

    .OUTPUTS
        PSCustomObject[]
        Array of PSCustomObjects representing PIM-enabled groups with legacy metadata.

    .NOTES
        DEPRECATED: This function uses an endpoint that will be retired on October 28, 2026.

        Requires Microsoft.Graph.Beta.Identity.Governance module.
        Requires PrivilegedAccess.Read.AzureADGroup permission.

        Uses Get-MgBetaPrivilegedAccessResource cmdlet.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$IncludePIMData = $true,

        [Parameter(Mandatory = $false)]
        [ValidateSet('member', 'owner', 'all')]
        [string]$AccessType = 'all'
    )

    begin {
        Write-Warning "This function uses a DEPRECATED endpoint that will be retired on October 28, 2026. Consider using Get-PIMGroups instead."
    }

    process {
        try {
            Write-Verbose "Fetching PIM-enabled groups from legacy endpoint"

            # Get all PIM-enabled groups using the legacy endpoint
            $legacyGroups = Get-MgBetaPrivilegedAccessResource -PrivilegedAccessId 'aadGroups' -All -ErrorAction Stop

            Write-Verbose "Found $($legacyGroups.Count) PIM-enabled groups"

            # Process each group
            $results = foreach ($group in $legacyGroups) {
                $result = [PSCustomObject]@{
                    Id                  = $group.Id
                    DisplayName         = $group.DisplayName
                    Type                = $group.Type
                    Status              = $group.Status
                    ExternalId          = $group.ExternalId
                    RegisteredDateTime  = $group.RegisteredDateTime
                    RegisteredRoot      = $group.RegisteredRoot
                    RoleDefinitionCount = $group.RoleDefinitionCount
                    RoleAssignmentCount = $group.RoleAssignmentCount
                    PIMData             = $null
                }

                # Get full PIM data if requested
                if ($IncludePIMData) {
                    Write-Verbose "Fetching PIM data for group: $($group.Id) ($($group.DisplayName))"
                    try {
                        $result.PIMData = Get-PIMGroup -GroupId $group.Id -IncludeGroupDetails:$false -AccessType $AccessType
                    }
                    catch {
                        Write-Warning "Could not retrieve PIM data for group $($group.Id): $_"
                    }
                }

                $result
            }

            $results
        }
        catch {
            Write-Error "Failed to retrieve PIM-enabled groups (legacy): $_"
            throw
        }
    }
}

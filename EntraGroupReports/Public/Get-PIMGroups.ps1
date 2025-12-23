function Get-PIMGroups {
    <#
    .SYNOPSIS
        Gets all PIM-enabled groups using the new identityGovernance endpoint.

    .DESCRIPTION
        Retrieves all PIM-enabled groups from the tenant using the newer
        /identityGovernance/privilegedAccess/group/resources endpoint.

        NOTE: This endpoint is relatively new and only returns minimal data
        (id and deletedDateTime). To get full group metadata, use -EnrichWithDetails
        which will call Get-MgBetaGroup for each returned group.

        This endpoint only works in Global cloud (not GCC, GCC High, DoD, or other
        national clouds).

    .PARAMETER EnrichWithDetails
        If specified, retrieves additional group metadata (displayName, description, etc.)
        for each PIM-enabled group by calling Get-MgBetaGroup. Default is $true.

    .PARAMETER IncludePIMData
        If specified, retrieves full PIM eligibility and assignment data for each group
        using Get-PIMGroup. This can be slow for tenants with many PIM groups.
        Default is $true.

    .PARAMETER AccessType
        Filter by access type when IncludePIMData is true: 'member', 'owner', or 'all'.
        Default is 'all'.

    .EXAMPLE
        Get-PIMGroups
        # Returns all PIM-enabled groups with details and PIM data

    .EXAMPLE
        Get-PIMGroups -EnrichWithDetails:$false -IncludePIMData:$false
        # Returns only group IDs (minimal data, fastest)

    .EXAMPLE
        Get-PIMGroups -AccessType "owner"
        # Returns PIM data filtered to owner access only

    .OUTPUTS
        PSCustomObject[]
        Array of PSCustomObjects representing PIM-enabled groups.

    .NOTES
        Requires Microsoft.Graph.Beta.Identity.Governance module.
        Requires PrivilegedAccess.Read.AzureADGroup permission.
        Only available in Global cloud environment.

        Uses Invoke-MgGraphRequest as there is no dedicated cmdlet for this endpoint.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)]
        [bool]$EnrichWithDetails = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IncludePIMData = $true,

        [Parameter(Mandatory = $false)]
        [ValidateSet('member', 'owner', 'all')]
        [string]$AccessType = 'all'
    )

    begin {
        $uri = 'https://graph.microsoft.com/beta/identityGovernance/privilegedAccess/group/resources'
        $allGroups = @()
    }

    process {
        try {
            Write-Verbose "Fetching PIM-enabled groups from: $uri"

            # Use pagination to get all results
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop

                if ($response.value) {
                    $allGroups += $response.value
                }

                # Check for next page
                $uri = $response.'@odata.nextLink'
            } while ($uri)

            Write-Verbose "Found $($allGroups.Count) PIM-enabled groups"

            # Process each group
            $results = foreach ($group in $allGroups) {
                $result = [PSCustomObject]@{
                    Id              = $group.id
                    DeletedDateTime = $group.deletedDateTime
                    DisplayName     = $null
                    Description     = $null
                    Mail            = $null
                    GroupTypes      = $null
                    PIMData         = $null
                }

                # Enrich with group details if requested
                if ($EnrichWithDetails) {
                    Write-Verbose "Enriching group details for: $($group.id)"
                    try {
                        $groupDetails = Get-MgBetaGroup -GroupId $group.id -Property Id, DisplayName, Description, Mail, GroupTypes -ErrorAction Stop
                        $result.DisplayName = $groupDetails.DisplayName
                        $result.Description = $groupDetails.Description
                        $result.Mail = $groupDetails.Mail
                        $result.GroupTypes = $groupDetails.GroupTypes
                    }
                    catch {
                        Write-Warning "Could not retrieve details for group $($group.id): $_"
                    }
                }

                # Get full PIM data if requested
                if ($IncludePIMData) {
                    Write-Verbose "Fetching PIM data for group: $($group.id)"
                    try {
                        $result.PIMData = Get-PIMGroup -GroupId $group.id -IncludeGroupDetails:$false -AccessType $AccessType
                    }
                    catch {
                        Write-Warning "Could not retrieve PIM data for group $($group.id): $_"
                    }
                }

                $result
            }

            $results
        }
        catch {
            Write-Error "Failed to retrieve PIM-enabled groups: $_"
            throw
        }
    }
}

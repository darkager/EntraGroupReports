function Get-PIMGroup {
    <#
    .SYNOPSIS
        Gets comprehensive PIM data for a specific group.

    .DESCRIPTION
        Retrieves all PIM-related data for a group including:
        - Group metadata (displayName, description)
        - Eligibility schedules and instances (who CAN activate)
        - Assignment schedules and instances (who currently HAS access)

        This is a composite function that calls Get-PIMGroupEligibility and
        Get-PIMGroupAssignment internally.

    .PARAMETER GroupId
        The GUID of the target PIM-enabled group.

    .PARAMETER IncludeGroupDetails
        If specified, retrieves additional group metadata from Microsoft Graph.
        Default is $true.

    .PARAMETER AccessType
        Filter by access type: 'member', 'owner', or 'all'. Default is 'all'.

    .EXAMPLE
        Get-PIMGroup -GroupId "12345678-1234-1234-1234-123456789012"

    .EXAMPLE
        Get-PIMGroup -GroupId "12345678-1234-1234-1234-123456789012" -AccessType "owner"

    .EXAMPLE
        Get-PIMGroup -GroupId "12345678-1234-1234-1234-123456789012" -IncludeGroupDetails:$false

    .OUTPUTS
        PSCustomObject
        Custom object with GroupId, GroupDetails, Eligibility, and Assignment properties.

    .NOTES
        Requires Microsoft.Graph.Beta.Identity.Governance module.
        Requires Microsoft.Graph.Beta.Groups module (for group details).
        Requires PrivilegedEligibilitySchedule.Read.AzureADGroup permission.
        Requires PrivilegedAssignmentSchedule.Read.AzureADGroup permission.
        Requires Group.Read.All permission (for group details).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [Alias('Id')]
        [string]$GroupId,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeGroupDetails = $true,

        [Parameter(Mandatory = $false)]
        [ValidateSet('member', 'owner', 'all')]
        [string]$AccessType = 'all'
    )

    process {
        try {
            $result = [PSCustomObject]@{
                GroupId      = $GroupId
                GroupDetails = $null
                Eligibility  = $null
                Assignment   = $null
            }

            # Get group details if requested
            if ($IncludeGroupDetails) {
                Write-Verbose "Fetching group details for: $GroupId"
                try {
                    $group = Get-MgBetaGroup -GroupId $GroupId -Property Id, DisplayName, Description, Mail, GroupTypes -ErrorAction Stop
                    $result.GroupDetails = [PSCustomObject]@{
                        Id          = $group.Id
                        DisplayName = $group.DisplayName
                        Description = $group.Description
                        Mail        = $group.Mail
                        GroupTypes  = $group.GroupTypes
                    }
                }
                catch {
                    Write-Warning "Could not retrieve group details for $GroupId : $_"
                }
            }

            # Get eligibility data
            Write-Verbose "Fetching eligibility data for group: $GroupId"
            $result.Eligibility = Get-PIMGroupEligibility -GroupId $GroupId -AccessType $AccessType

            # Get assignment data
            Write-Verbose "Fetching assignment data for group: $GroupId"
            $result.Assignment = Get-PIMGroupAssignment -GroupId $GroupId -AccessType $AccessType

            $result
        }
        catch {
            Write-Error "Failed to retrieve PIM group data for $GroupId : $_"
            throw
        }
    }
}

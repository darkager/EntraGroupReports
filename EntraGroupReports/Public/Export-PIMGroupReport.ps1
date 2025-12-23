function Export-PIMGroupReport {
    <#
    .SYNOPSIS
        Exports a comprehensive CSV report of all PIM group data.

    .DESCRIPTION
        Generates a flat CSV report containing eligibility and assignment data
        for PIM-enabled groups. The report includes both schedule definitions
        and active instances, with resolved display names for groups and principals.

        The function can use either the new API (Get-PIMGroups) or the legacy API
        (Get-PIMGroupsLegacy) to discover PIM-enabled groups.

    .PARAMETER OutputPath
        The file path for the CSV output. If not specified, outputs to
        PIMGroupReport_<timestamp>.csv in the current directory.

    .PARAMETER GroupIds
        Optional array of specific group IDs to include in the report.
        If not specified, all PIM-enabled groups are included.

    .PARAMETER UseLegacyDiscovery
        If specified, uses Get-PIMGroupsLegacy (deprecated API) to discover groups.
        This provides better metadata but relies on an endpoint retiring Oct 2026.
        Default is $false (uses the new API).

    .PARAMETER AccessType
        Filter by access type: 'member', 'owner', or 'all'. Default is 'all'.

    .PARAMETER ResolvePrincipalNames
        If specified, resolves principal IDs to display names.
        This adds additional API calls and can slow down report generation.
        Default is $true.

    .PARAMETER ExpandGroupMembers
        If specified, expands group principals to show their transitive members.
        When a group is assigned eligibility/assignment, this will add rows for
        each user/service principal that is a member (direct or nested) of that group.
        Default is $false.

    .EXAMPLE
        Export-PIMGroupReport

    .EXAMPLE
        Export-PIMGroupReport -OutputPath "C:\Reports\PIMReport.csv"

    .EXAMPLE
        Export-PIMGroupReport -GroupIds "12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321"

    .EXAMPLE
        Export-PIMGroupReport -UseLegacyDiscovery -AccessType "owner"

    .EXAMPLE
        Export-PIMGroupReport -ExpandGroupMembers
        # Expands nested group members to show all users who inherit eligibility/assignments

    .OUTPUTS
        System.IO.FileInfo
        FileInfo object representing the created CSV file.

    .NOTES
        Requires Microsoft.Graph.Beta.Identity.Governance module.
        Requires Microsoft.Graph.Beta.Groups module.
        Requires Microsoft.Graph.Beta.Users module (for principal name resolution).

        CSV Columns:
        - GroupId, GroupDisplayName
        - PrincipalId, PrincipalDisplayName, PrincipalUserPrincipalName, PrincipalType
        - AccessType (member/owner)
        - RecordType (EligibilitySchedule/EligibilityInstance/AssignmentSchedule/AssignmentInstance)
        - IsCurrentlyActive (true for Instance records - means eligibility/assignment is in effect now)
        - IsPermanent (true if no expiration date)
        - AssignmentType (assigned/activated - assignments only)
        - MemberType (direct/inherited (group))
        - TransitiveMemberId, TransitiveMemberDisplayName, TransitiveMemberUPN, TransitiveMemberType
          (populated when ExpandGroupMembers is used and principal is a group)
        - Status
        - StartDateTime, EndDateTime, ExpirationType
        - ScheduleId, CreatedDateTime
    #>
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string[]]$GroupIds,

        [Parameter(Mandatory = $false)]
        [switch]$UseLegacyDiscovery,

        [Parameter(Mandatory = $false)]
        [ValidateSet('member', 'owner', 'all')]
        [string]$AccessType = 'all',

        [Parameter(Mandatory = $false)]
        [bool]$ResolvePrincipalNames = $true,

        [Parameter(Mandatory = $false)]
        [switch]$ExpandGroupMembers
    )

    begin {
        # Set default output path if not specified
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $OutputPath = Join-Path -Path (Get-Location) -ChildPath "PIMGroupReport_$timestamp.csv"
        }

        # Cache for resolved principal info
        $principalCache = @{}

        # Cache for group transitive members
        $groupMemberCache = @{}

        # Helper function to resolve principal details
        function Get-PrincipalInfo {
            param(
                [string]$PrincipalId
            )

            if (-not $ResolvePrincipalNames) {
                return [PSCustomObject]@{
                    DisplayName       = $null
                    UserPrincipalName = $null
                    Type              = 'Unknown'
                }
            }

            if ($principalCache.ContainsKey($PrincipalId)) {
                return $principalCache[$PrincipalId]
            }

            $result = [PSCustomObject]@{
                DisplayName       = $null
                UserPrincipalName = $null
                Type              = 'Unknown'
            }

            # Try to resolve as user first
            try {
                $user = Get-MgBetaUser -UserId $PrincipalId -Property Id, DisplayName, UserPrincipalName -ErrorAction Stop
                $result.DisplayName = $user.DisplayName
                $result.UserPrincipalName = $user.UserPrincipalName
                $result.Type = 'User'
            }
            catch {
                # Try as service principal
                try {
                    $sp = Get-MgBetaServicePrincipal -ServicePrincipalId $PrincipalId -Property Id, DisplayName -ErrorAction Stop
                    $result.DisplayName = $sp.DisplayName
                    $result.UserPrincipalName = $null
                    $result.Type = 'ServicePrincipal'
                }
                catch {
                    # Try as group (for nested group membership)
                    try {
                        $group = Get-MgBetaGroup -GroupId $PrincipalId -Property Id, DisplayName -ErrorAction Stop
                        $result.DisplayName = $group.DisplayName
                        $result.UserPrincipalName = $null
                        $result.Type = 'Group'
                    }
                    catch {
                        Write-Verbose "Could not resolve principal: $PrincipalId"
                    }
                }
            }

            $principalCache[$PrincipalId] = $result
            return $result
        }

        # Helper function to get transitive members of a group
        function Get-GroupTransitiveMembers {
            param(
                [string]$GroupId,
                [string]$GroupDisplayName
            )

            if ($groupMemberCache.ContainsKey($GroupId)) {
                return $groupMemberCache[$GroupId]
            }

            $members = @()

            try {
                Write-Verbose "Fetching transitive members for group: $GroupId ($GroupDisplayName)"
                $transitiveMembers = Get-MgBetaGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop

                foreach ($member in $transitiveMembers) {
                    # Get the OData type to determine member type
                    $odataType = $member.AdditionalProperties.'@odata.type'

                    $memberInfo = [PSCustomObject]@{
                        Id                = $member.Id
                        DisplayName       = $member.AdditionalProperties.displayName
                        UserPrincipalName = $null
                        Type              = 'Unknown'
                    }

                    switch ($odataType) {
                        '#microsoft.graph.user' {
                            $memberInfo.Type = 'User'
                            $memberInfo.UserPrincipalName = $member.AdditionalProperties.userPrincipalName
                        }
                        '#microsoft.graph.servicePrincipal' {
                            $memberInfo.Type = 'ServicePrincipal'
                        }
                        '#microsoft.graph.device' {
                            $memberInfo.Type = 'Device'
                        }
                        '#microsoft.graph.orgContact' {
                            $memberInfo.Type = 'OrgContact'
                        }
                        '#microsoft.graph.group' {
                            # Skip nested groups - we only want end principals
                            continue
                        }
                        default {
                            # For any other type, extract from the odata.type if possible
                            if ($odataType -match '#microsoft\.graph\.(\w+)$') {
                                $memberInfo.Type = $Matches[1]
                            }
                            else {
                                $memberInfo.Type = 'Unknown'
                            }
                        }
                    }

                    # Only add non-group members (skip groups, add everything else)
                    if ($odataType -ne '#microsoft.graph.group') {
                        $members += $memberInfo

                        # Also cache in principal cache for later lookups
                        if (-not $principalCache.ContainsKey($member.Id)) {
                            $principalCache[$member.Id] = [PSCustomObject]@{
                                DisplayName       = $memberInfo.DisplayName
                                UserPrincipalName = $memberInfo.UserPrincipalName
                                Type              = $memberInfo.Type
                            }
                        }
                    }
                }
            }
            catch {
                Write-Warning "Could not retrieve transitive members for group $GroupId : $_"
            }

            $groupMemberCache[$GroupId] = $members
            return $members
        }

        # Helper function to extract schedule info
        function Get-ScheduleDetails {
            param(
                $ScheduleInfo
            )

            $details = [PSCustomObject]@{
                StartDateTime  = $null
                EndDateTime    = $null
                ExpirationType = $null
                IsPermanent    = $false
            }

            if ($ScheduleInfo) {
                $details.StartDateTime = $ScheduleInfo.StartDateTime

                if ($ScheduleInfo.Expiration) {
                    $details.EndDateTime = $ScheduleInfo.Expiration.EndDateTime
                    $details.ExpirationType = $ScheduleInfo.Expiration.Type
                    # Determine if permanent (noExpiration or no end date)
                    $details.IsPermanent = ($ScheduleInfo.Expiration.Type -eq 'noExpiration') -or
                                           (($null -eq $ScheduleInfo.Expiration.EndDateTime) -and ($ScheduleInfo.Expiration.Type -ne 'afterDuration'))
                }
                else {
                    # No expiration info means permanent
                    $details.IsPermanent = $true
                }
            }

            return $details
        }

        # Helper function to create a report row
        function New-ReportRow {
            param(
                [string]$GroupId,
                [string]$GroupDisplayName,
                [string]$PrincipalId,
                [string]$PrincipalDisplayName,
                [string]$PrincipalUserPrincipalName,
                [string]$PrincipalType,
                [string]$AccessType,
                [string]$RecordType,
                [bool]$IsCurrentlyActive,
                [bool]$IsPermanent,
                [string]$AssignmentType,
                [string]$MemberType,
                [string]$TransitiveMemberId,
                [string]$TransitiveMemberDisplayName,
                [string]$TransitiveMemberUPN,
                [string]$TransitiveMemberType,
                [string]$Status,
                $StartDateTime,
                $EndDateTime,
                [string]$ExpirationType,
                [string]$ScheduleId,
                $CreatedDateTime
            )

            return [PSCustomObject]@{
                GroupId                       = $GroupId
                GroupDisplayName              = $GroupDisplayName
                PrincipalId                   = $PrincipalId
                PrincipalDisplayName          = $PrincipalDisplayName
                PrincipalUserPrincipalName    = $PrincipalUserPrincipalName
                PrincipalType                 = $PrincipalType
                AccessType                    = $AccessType
                RecordType                    = $RecordType
                IsCurrentlyActive             = $IsCurrentlyActive
                IsPermanent                   = $IsPermanent
                AssignmentType                = $AssignmentType
                MemberType                    = $MemberType
                TransitiveMemberId            = $TransitiveMemberId
                TransitiveMemberDisplayName   = $TransitiveMemberDisplayName
                TransitiveMemberUPN           = $TransitiveMemberUPN
                TransitiveMemberType          = $TransitiveMemberType
                Status                        = $Status
                StartDateTime                 = $StartDateTime
                EndDateTime                   = $EndDateTime
                ExpirationType                = $ExpirationType
                ScheduleId                    = $ScheduleId
                CreatedDateTime               = $CreatedDateTime
            }
        }

        $reportData = @()
    }

    process {
        try {
            # Get list of groups to process
            $groupsToProcess = @()

            if ($GroupIds) {
                # Use specified group IDs
                Write-Verbose "Processing specified group IDs: $($GroupIds.Count) groups"
                foreach ($id in $GroupIds) {
                    $groupsToProcess += [PSCustomObject]@{
                        Id          = $id
                        DisplayName = $null
                    }
                }
            }
            elseif ($UseLegacyDiscovery) {
                # Use legacy API to discover groups (only need group list, not PIM data)
                Write-Verbose "Discovering PIM-enabled groups using legacy API"
                $legacyGroups = Get-PIMGroupsLegacy -IncludePIMData:$false
                foreach ($group in $legacyGroups) {
                    $groupsToProcess += [PSCustomObject]@{
                        Id          = $group.Id
                        DisplayName = $group.DisplayName
                    }
                }
            }
            else {
                # Use new API to discover groups (only need group list, not PIM data)
                Write-Verbose "Discovering PIM-enabled groups using new API"
                $newGroups = Get-PIMGroups -EnrichWithDetails:$true -IncludePIMData:$false
                foreach ($group in $newGroups) {
                    $groupsToProcess += [PSCustomObject]@{
                        Id          = $group.Id
                        DisplayName = $group.DisplayName
                    }
                }
            }

            Write-Verbose "Processing $($groupsToProcess.Count) PIM-enabled groups"

            # Process each group
            $groupIndex = 0
            foreach ($group in $groupsToProcess) {
                $groupIndex++
                $groupName = if ($group.DisplayName) { $group.DisplayName } else { $group.Id }
                Write-Progress -Activity "Processing PIM Groups" -Status "Group $groupIndex of $($groupsToProcess.Count): $groupName" -PercentComplete (($groupIndex / $groupsToProcess.Count) * 100)

                # Get full PIM data for the group
                try {
                    $pimData = Get-PIMGroup -GroupId $group.Id -IncludeGroupDetails:($null -eq $group.DisplayName) -AccessType $AccessType

                    # Use group display name from PIM data if not already available
                    $groupDisplayName = $group.DisplayName
                    if (-not $groupDisplayName -and $pimData.GroupDetails) {
                        $groupDisplayName = $pimData.GroupDetails.DisplayName
                    }

                    # Process Eligibility Schedules
                    foreach ($schedule in $pimData.Eligibility.Schedules) {
                        $principal = Get-PrincipalInfo -PrincipalId $schedule.PrincipalId
                        $scheduleDetails = Get-ScheduleDetails -ScheduleInfo $schedule.ScheduleInfo

                        # Add the direct row
                        $reportData += New-ReportRow `
                            -GroupId $group.Id `
                            -GroupDisplayName $groupDisplayName `
                            -PrincipalId $schedule.PrincipalId `
                            -PrincipalDisplayName $principal.DisplayName `
                            -PrincipalUserPrincipalName $principal.UserPrincipalName `
                            -PrincipalType $principal.Type `
                            -AccessType $schedule.AccessId `
                            -RecordType 'EligibilitySchedule' `
                            -IsCurrentlyActive $false `
                            -IsPermanent $scheduleDetails.IsPermanent `
                            -AssignmentType $null `
                            -MemberType $schedule.MemberType `
                            -TransitiveMemberId $null `
                            -TransitiveMemberDisplayName $null `
                            -TransitiveMemberUPN $null `
                            -TransitiveMemberType $null `
                            -Status $schedule.Status `
                            -StartDateTime $scheduleDetails.StartDateTime `
                            -EndDateTime $scheduleDetails.EndDateTime `
                            -ExpirationType $scheduleDetails.ExpirationType `
                            -ScheduleId $schedule.Id `
                            -CreatedDateTime $schedule.CreatedDateTime

                        # Expand group members if requested and principal is a group
                        if ($ExpandGroupMembers -and $principal.Type -eq 'Group') {
                            $groupMembers = Get-GroupTransitiveMembers -GroupId $schedule.PrincipalId -GroupDisplayName $principal.DisplayName

                            foreach ($member in $groupMembers) {
                                $reportData += New-ReportRow `
                                    -GroupId $group.Id `
                                    -GroupDisplayName $groupDisplayName `
                                    -PrincipalId $schedule.PrincipalId `
                                    -PrincipalDisplayName $principal.DisplayName `
                                    -PrincipalUserPrincipalName $null `
                                    -PrincipalType $principal.Type `
                                    -AccessType $schedule.AccessId `
                                    -RecordType 'EligibilitySchedule' `
                                    -IsCurrentlyActive $false `
                                    -IsPermanent $scheduleDetails.IsPermanent `
                                    -AssignmentType $null `
                                    -MemberType 'inherited (group)' `
                                    -TransitiveMemberId $member.Id `
                                    -TransitiveMemberDisplayName $member.DisplayName `
                                    -TransitiveMemberUPN $member.UserPrincipalName `
                                    -TransitiveMemberType $member.Type `
                                    -Status $schedule.Status `
                                    -StartDateTime $scheduleDetails.StartDateTime `
                                    -EndDateTime $scheduleDetails.EndDateTime `
                                    -ExpirationType $scheduleDetails.ExpirationType `
                                    -ScheduleId $schedule.Id `
                                    -CreatedDateTime $schedule.CreatedDateTime
                            }
                        }
                    }

                    # Process Eligibility Instances (currently active eligibilities)
                    foreach ($instance in $pimData.Eligibility.Instances) {
                        $principal = Get-PrincipalInfo -PrincipalId $instance.PrincipalId
                        # For instances, determine permanence from end date
                        $isPermanent = $null -eq $instance.EndDateTime

                        # Add the direct row
                        $reportData += New-ReportRow `
                            -GroupId $group.Id `
                            -GroupDisplayName $groupDisplayName `
                            -PrincipalId $instance.PrincipalId `
                            -PrincipalDisplayName $principal.DisplayName `
                            -PrincipalUserPrincipalName $principal.UserPrincipalName `
                            -PrincipalType $principal.Type `
                            -AccessType $instance.AccessId `
                            -RecordType 'EligibilityInstance' `
                            -IsCurrentlyActive $true `
                            -IsPermanent $isPermanent `
                            -AssignmentType $null `
                            -MemberType $instance.MemberType `
                            -TransitiveMemberId $null `
                            -TransitiveMemberDisplayName $null `
                            -TransitiveMemberUPN $null `
                            -TransitiveMemberType $null `
                            -Status 'Active' `
                            -StartDateTime $instance.StartDateTime `
                            -EndDateTime $instance.EndDateTime `
                            -ExpirationType $(if ($isPermanent) { 'noExpiration' } else { 'afterDateTime' }) `
                            -ScheduleId $instance.EligibilityScheduleId `
                            -CreatedDateTime $null

                        # Expand group members if requested and principal is a group
                        if ($ExpandGroupMembers -and $principal.Type -eq 'Group') {
                            $groupMembers = Get-GroupTransitiveMembers -GroupId $instance.PrincipalId -GroupDisplayName $principal.DisplayName

                            foreach ($member in $groupMembers) {
                                $reportData += New-ReportRow `
                                    -GroupId $group.Id `
                                    -GroupDisplayName $groupDisplayName `
                                    -PrincipalId $instance.PrincipalId `
                                    -PrincipalDisplayName $principal.DisplayName `
                                    -PrincipalUserPrincipalName $null `
                                    -PrincipalType $principal.Type `
                                    -AccessType $instance.AccessId `
                                    -RecordType 'EligibilityInstance' `
                                    -IsCurrentlyActive $true `
                                    -IsPermanent $isPermanent `
                                    -AssignmentType $null `
                                    -MemberType 'inherited (group)' `
                                    -TransitiveMemberId $member.Id `
                                    -TransitiveMemberDisplayName $member.DisplayName `
                                    -TransitiveMemberUPN $member.UserPrincipalName `
                                    -TransitiveMemberType $member.Type `
                                    -Status 'Active' `
                                    -StartDateTime $instance.StartDateTime `
                                    -EndDateTime $instance.EndDateTime `
                                    -ExpirationType $(if ($isPermanent) { 'noExpiration' } else { 'afterDateTime' }) `
                                    -ScheduleId $instance.EligibilityScheduleId `
                                    -CreatedDateTime $null
                            }
                        }
                    }

                    # Process Assignment Schedules
                    foreach ($schedule in $pimData.Assignment.Schedules) {
                        $principal = Get-PrincipalInfo -PrincipalId $schedule.PrincipalId
                        $scheduleDetails = Get-ScheduleDetails -ScheduleInfo $schedule.ScheduleInfo

                        # Add the direct row
                        $reportData += New-ReportRow `
                            -GroupId $group.Id `
                            -GroupDisplayName $groupDisplayName `
                            -PrincipalId $schedule.PrincipalId `
                            -PrincipalDisplayName $principal.DisplayName `
                            -PrincipalUserPrincipalName $principal.UserPrincipalName `
                            -PrincipalType $principal.Type `
                            -AccessType $schedule.AccessId `
                            -RecordType 'AssignmentSchedule' `
                            -IsCurrentlyActive $false `
                            -IsPermanent $scheduleDetails.IsPermanent `
                            -AssignmentType $schedule.AssignmentType `
                            -MemberType $schedule.MemberType `
                            -TransitiveMemberId $null `
                            -TransitiveMemberDisplayName $null `
                            -TransitiveMemberUPN $null `
                            -TransitiveMemberType $null `
                            -Status $schedule.Status `
                            -StartDateTime $scheduleDetails.StartDateTime `
                            -EndDateTime $scheduleDetails.EndDateTime `
                            -ExpirationType $scheduleDetails.ExpirationType `
                            -ScheduleId $schedule.Id `
                            -CreatedDateTime $schedule.CreatedDateTime

                        # Expand group members if requested and principal is a group
                        if ($ExpandGroupMembers -and $principal.Type -eq 'Group') {
                            $groupMembers = Get-GroupTransitiveMembers -GroupId $schedule.PrincipalId -GroupDisplayName $principal.DisplayName

                            foreach ($member in $groupMembers) {
                                $reportData += New-ReportRow `
                                    -GroupId $group.Id `
                                    -GroupDisplayName $groupDisplayName `
                                    -PrincipalId $schedule.PrincipalId `
                                    -PrincipalDisplayName $principal.DisplayName `
                                    -PrincipalUserPrincipalName $null `
                                    -PrincipalType $principal.Type `
                                    -AccessType $schedule.AccessId `
                                    -RecordType 'AssignmentSchedule' `
                                    -IsCurrentlyActive $false `
                                    -IsPermanent $scheduleDetails.IsPermanent `
                                    -AssignmentType $schedule.AssignmentType `
                                    -MemberType 'inherited (group)' `
                                    -TransitiveMemberId $member.Id `
                                    -TransitiveMemberDisplayName $member.DisplayName `
                                    -TransitiveMemberUPN $member.UserPrincipalName `
                                    -TransitiveMemberType $member.Type `
                                    -Status $schedule.Status `
                                    -StartDateTime $scheduleDetails.StartDateTime `
                                    -EndDateTime $scheduleDetails.EndDateTime `
                                    -ExpirationType $scheduleDetails.ExpirationType `
                                    -ScheduleId $schedule.Id `
                                    -CreatedDateTime $schedule.CreatedDateTime
                            }
                        }
                    }

                    # Process Assignment Instances (currently active assignments)
                    foreach ($instance in $pimData.Assignment.Instances) {
                        $principal = Get-PrincipalInfo -PrincipalId $instance.PrincipalId
                        # For instances, determine permanence from end date
                        $isPermanent = $null -eq $instance.EndDateTime

                        # Add the direct row
                        $reportData += New-ReportRow `
                            -GroupId $group.Id `
                            -GroupDisplayName $groupDisplayName `
                            -PrincipalId $instance.PrincipalId `
                            -PrincipalDisplayName $principal.DisplayName `
                            -PrincipalUserPrincipalName $principal.UserPrincipalName `
                            -PrincipalType $principal.Type `
                            -AccessType $instance.AccessId `
                            -RecordType 'AssignmentInstance' `
                            -IsCurrentlyActive $true `
                            -IsPermanent $isPermanent `
                            -AssignmentType $instance.AssignmentType `
                            -MemberType $instance.MemberType `
                            -TransitiveMemberId $null `
                            -TransitiveMemberDisplayName $null `
                            -TransitiveMemberUPN $null `
                            -TransitiveMemberType $null `
                            -Status 'Active' `
                            -StartDateTime $instance.StartDateTime `
                            -EndDateTime $instance.EndDateTime `
                            -ExpirationType $(if ($isPermanent) { 'noExpiration' } else { 'afterDateTime' }) `
                            -ScheduleId $instance.AssignmentScheduleId `
                            -CreatedDateTime $null

                        # Expand group members if requested and principal is a group
                        if ($ExpandGroupMembers -and $principal.Type -eq 'Group') {
                            $groupMembers = Get-GroupTransitiveMembers -GroupId $instance.PrincipalId -GroupDisplayName $principal.DisplayName

                            foreach ($member in $groupMembers) {
                                $reportData += New-ReportRow `
                                    -GroupId $group.Id `
                                    -GroupDisplayName $groupDisplayName `
                                    -PrincipalId $instance.PrincipalId `
                                    -PrincipalDisplayName $principal.DisplayName `
                                    -PrincipalUserPrincipalName $null `
                                    -PrincipalType $principal.Type `
                                    -AccessType $instance.AccessId `
                                    -RecordType 'AssignmentInstance' `
                                    -IsCurrentlyActive $true `
                                    -IsPermanent $isPermanent `
                                    -AssignmentType $instance.AssignmentType `
                                    -MemberType 'inherited (group)' `
                                    -TransitiveMemberId $member.Id `
                                    -TransitiveMemberDisplayName $member.DisplayName `
                                    -TransitiveMemberUPN $member.UserPrincipalName `
                                    -TransitiveMemberType $member.Type `
                                    -Status 'Active' `
                                    -StartDateTime $instance.StartDateTime `
                                    -EndDateTime $instance.EndDateTime `
                                    -ExpirationType $(if ($isPermanent) { 'noExpiration' } else { 'afterDateTime' }) `
                                    -ScheduleId $instance.AssignmentScheduleId `
                                    -CreatedDateTime $null
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to process group $($group.Id): $_"
                }
            }

            Write-Progress -Activity "Processing PIM Groups" -Completed

            # Export to CSV
            if ($reportData.Count -gt 0) {
                Write-Verbose "Exporting $($reportData.Count) records to: $OutputPath"
                $reportData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

                # Return file info
                Get-Item -Path $OutputPath
            }
            else {
                Write-Warning "No PIM data found to export."
                return $null
            }
        }
        catch {
            Write-Error "Failed to generate PIM group report: $_"
            throw
        }
    }
}

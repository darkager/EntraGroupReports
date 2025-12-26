function Export-EntraGroupReport {
    <#
    .SYNOPSIS
        Exports comprehensive security reports for all Entra ID groups in the tenant.

    .DESCRIPTION
        Generates two CSV reports containing security-relevant information for groups:

        1. Summary Report (*-Summary.csv):
           - High-level overview with counts for quick analysis
           - One row per group with member/owner counts, directory role counts, PIM counts

        2. Detail Report (*-Report.csv):
           - Flattened single CSV with all security data
           - RecordCategory column distinguishes: Membership, DirectoryRole, PIMAccess
           - Supports filtering and pivoting

        The function collects:
        - Group metadata (type, security-enabled, mail-enabled, role-assignable, PIM-enabled)
        - Direct and transitive group membership
        - Group owners
        - Directory role assignments (for role-assignable groups)
        - PIM eligibility and assignment data (for PIM-enabled groups)

    .PARAMETER OutputPath
        Base path for the CSV outputs. The function appends '-Summary.csv' and '-Report.csv'.
        If not specified, outputs to EntraGroupReport_<timestamp> in the current directory.

    .PARAMETER GroupIds
        Optional array of specific group IDs to include in the report.
        If not specified, all groups in the tenant are included.

    .PARAMETER IncludePIMData
        If specified, includes PIM eligibility and assignment data for PIM-enabled groups.
        Default is $true.

    .PARAMETER IncludeDirectoryRoles
        If specified, includes directory role assignments for role-assignable groups.
        Default is $true.

    .PARAMETER IncludeMembership
        If specified, includes group membership (members and owners).
        Default is $true.

    .PARAMETER ExpandGroupMembers
        If specified, expands nested group membership to show transitive members.
        Default is $false.

    .PARAMETER ResolvePrincipalNames
        If specified, resolves principal IDs to display names.
        Default is $true.

    .EXAMPLE
        Export-EntraGroupReport
        # Exports all groups with full security data

    .EXAMPLE
        Export-EntraGroupReport -OutputPath "C:\Reports\EntraGroups"
        # Exports to C:\Reports\EntraGroups-Summary.csv and C:\Reports\EntraGroups-Report.csv

    .EXAMPLE
        Export-EntraGroupReport -IncludePIMData:$false -IncludeDirectoryRoles:$false
        # Exports only membership data (faster)

    .EXAMPLE
        Export-EntraGroupReport -GroupIds "abc-123", "def-456"
        # Exports only specified groups

    .OUTPUTS
        PSCustomObject
        Object with SummaryReport and DetailReport properties containing FileInfo objects.

    .NOTES
        Requires Microsoft.Graph.Beta.Groups module.
        Requires Microsoft.Graph.Beta.Users module.
        Requires Microsoft.Graph.Identity.Governance module (for directory roles).
        Requires Microsoft.Graph.Beta.Identity.Governance module (for PIM data).

        Permissions required:
        - Group.Read.All
        - User.Read.All
        - RoleManagement.Read.Directory (for directory roles)
        - PrivilegedEligibilitySchedule.Read.AzureADGroup (for PIM data)
        - PrivilegedAssignmentSchedule.Read.AzureADGroup (for PIM data)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string[]]$GroupIds,

        [Parameter(Mandatory = $false)]
        [bool]$IncludePIMData = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeDirectoryRoles = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeMembership = $true,

        [Parameter(Mandatory = $false)]
        [switch]$ExpandGroupMembers,

        [Parameter(Mandatory = $false)]
        [bool]$ResolvePrincipalNames = $true
    )

    begin {
        # Set default output path if not specified
        if (-not $OutputPath) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $OutputPath = Join-Path -Path (Get-Location) -ChildPath "EntraGroupReport_$timestamp"
        }

        $summaryPath = "$OutputPath-Summary.csv"
        $detailPath = "$OutputPath-Report.csv"

        # Cache for resolved principal info
        $principalCache = New-Object -TypeName "System.Collections.Generic.Dictionary[[String],[PSCustomObject]]"

        # Cache for group transitive members
        $groupMemberCache = New-Object -TypeName "System.Collections.Generic.Dictionary[[String],[System.Collections.Generic.List[PSCustomObject]]]"

        # Cache for PIM-enabled group IDs
        $pimEnabledGroupIds = New-Object -TypeName "System.Collections.Generic.Dictionary[[String],[bool]]"

        # Helper function to resolve principal details
        function Get-PrincipalInfo {
            param([string]$PrincipalId)

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
                    $result.Type = 'ServicePrincipal'
                }
                catch {
                    # Try as group
                    try {
                        $group = Get-MgBetaGroup -GroupId $PrincipalId -Property Id, DisplayName -ErrorAction Stop
                        $result.DisplayName = $group.DisplayName
                        $result.Type = 'Group'
                    }
                    catch {
                        Write-Verbose "Could not resolve principal: $PrincipalId"
                    }
                }
            }

            $principalCache.Add($PrincipalId, $result)
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

            $members = New-Object -TypeName "System.Collections.Generic.List[PSCustomObject]"

            try {
                Write-Verbose "Fetching transitive members for group: $GroupId ($GroupDisplayName)"
                $transitiveMembers = Get-MgBetaGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop

                foreach ($member in $transitiveMembers) {
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
                            # Skip nested groups
                            continue
                        }
                        default {
                            if ($odataType -match '#microsoft\.graph\.(\w+)$') {
                                $memberInfo.Type = $Matches[1]
                            }
                        }
                    }

                    if ($odataType -ne '#microsoft.graph.group') {
                        $members.Add($memberInfo)

                        # Cache for later lookups
                        if (-not $principalCache.ContainsKey($member.Id)) {
                            $principalCache.Add($member.Id, [PSCustomObject]@{
                                DisplayName       = $memberInfo.DisplayName
                                UserPrincipalName = $memberInfo.UserPrincipalName
                                Type              = $memberInfo.Type
                            })
                        }
                    }
                }
            }
            catch {
                Write-Warning "Could not retrieve transitive members for group $GroupId : $_"
            }

            $groupMemberCache.Add($GroupId, $members)
            return $members
        }

        # Helper to determine group type
        function Get-GroupType {
            param($Group)

            if ($Group.GroupTypes -contains 'Unified') {
                return 'M365'
            }
            elseif ($Group.SecurityEnabled) {
                return 'Security'
            }
            elseif ($Group.MailEnabled) {
                return 'Distribution'
            }
            else {
                return 'Other'
            }
        }

        # Helper to determine membership type (Assigned, DynamicUser, DynamicDevice)
        function Get-MembershipType {
            param($Group)

            if ($Group.GroupTypes -contains 'DynamicMembership') {
                $rule = $Group.MembershipRule
                if ($rule -match 'device\.' -or $rule -match '\(device\)') {
                    return 'DynamicDevice'
                }
                else {
                    return 'DynamicUser'
                }
            }
            else {
                return 'Assigned'
            }
        }

        # Helper to check if group is PIM-enabled
        function Test-GroupPIMEnabled {
            param([string]$GroupId)

            if ($pimEnabledGroupIds.Count -eq 0) {
                # Populate cache on first call
                try {
                    Write-Verbose "Building PIM-enabled groups cache..."
                    $pimGroups = Get-PIMGroups -EnrichWithDetails:$false -IncludePIMData:$false -ErrorAction Stop
                    foreach ($pg in $pimGroups) {
                        $pimEnabledGroupIds.Add($pg.Id, $true)
                    }
                }
                catch {
                    Write-Verbose "Could not retrieve PIM-enabled groups list: $_"
                }
            }

            return $pimEnabledGroupIds.ContainsKey($GroupId)
        }

        $summaryData = New-Object -TypeName "System.Collections.Generic.List[PSCustomObject]"
        $detailData = New-Object -TypeName "System.Collections.Generic.List[PSCustomObject]"
    }

    process {
        try {
            # Get list of groups to process
            $groupsToProcess = New-Object -TypeName "System.Collections.Generic.List[Microsoft.Graph.Beta.PowerShell.Models.MicrosoftGraphGroup]"

            if ($GroupIds) {
                Write-Verbose "Processing specified group IDs: $($GroupIds.Count) groups"
                foreach ($id in $GroupIds) {
                    try {
                        $group = Get-MgBetaGroup -GroupId $id -Property Id, DisplayName, Description, Mail, GroupTypes, SecurityEnabled, MailEnabled, IsAssignableToRole, MembershipRule -ErrorAction Stop
                        $groupsToProcess.Add($group)
                    }
                    catch {
                        Write-Warning "Could not retrieve group $id : $_"
                    }
                }
            }
            else {
                Write-Verbose "Fetching all groups from tenant"
                $allGroups = Get-MgBetaGroup -All -Property Id, DisplayName, Description, Mail, GroupTypes, SecurityEnabled, MailEnabled, IsAssignableToRole, MembershipRule -ErrorAction Stop
                foreach ($g in $allGroups) {
                    $groupsToProcess.Add($g)
                }
            }

            Write-Verbose "Processing $($groupsToProcess.Count) groups"

            # Process each group
            $groupIndex = 0
            foreach ($group in $groupsToProcess) {
                $groupIndex++
                Write-Progress -Activity "Processing Groups" -Status "Group $groupIndex of $($groupsToProcess.Count): $($group.DisplayName)" -PercentComplete (($groupIndex / $groupsToProcess.Count) * 100)

                $groupType = Get-GroupType -Group $group
                $membershipType = Get-MembershipType -Group $group
                $isPIMEnabled = Test-GroupPIMEnabled -GroupId $group.Id
                $isRoleAssignable = $group.IsAssignableToRole -eq $true

                # Initialize counters for summary
                $memberCount = 0
                $ownerCount = 0
                $directoryRoleCount = 0
                $pimEligibleMembers = 0
                $pimEligibleOwners = 0
                $pimAssignedMembers = 0
                $pimAssignedOwners = 0

                # --- MEMBERSHIP DATA ---
                if ($IncludeMembership) {
                    # Get direct members
                    try {
                        $members = Get-MgBetaGroupMember -GroupId $group.Id -All -ErrorAction Stop
                        $memberCount = $members.Count

                        foreach ($member in $members) {
                            $odataType = $member.AdditionalProperties.'@odata.type'
                            $principalType = 'Unknown'

                            switch ($odataType) {
                                '#microsoft.graph.user' { $principalType = 'User' }
                                '#microsoft.graph.servicePrincipal' { $principalType = 'ServicePrincipal' }
                                '#microsoft.graph.device' { $principalType = 'Device' }
                                '#microsoft.graph.orgContact' { $principalType = 'OrgContact' }
                                '#microsoft.graph.group' { $principalType = 'Group' }
                                default {
                                    if ($odataType -match '#microsoft\.graph\.(\w+)$') {
                                        $principalType = $Matches[1]
                                    }
                                }
                            }

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'Membership'
                                PrincipalId                 = $member.Id
                                PrincipalDisplayName        = $member.AdditionalProperties.displayName
                                PrincipalUPN                = $member.AdditionalProperties.userPrincipalName
                                PrincipalType               = $principalType
                                RelationType                = 'member'
                                MembershipType              = 'direct'
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $null
                                DirectoryRoleDisplayName    = $null
                                DirectoryRoleAssignmentType = $null
                                DirectoryRoleStatus         = $null
                                PIMAccessType               = $null
                                PIMRecordType               = $null
                                PIMIsCurrentlyActive        = $null
                                PIMIsPermanent              = $null
                                PIMAssignmentType           = $null
                                PIMMemberType               = $null
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $null
                                EndDateTime                 = $null
                            })

                            # Expand nested group members
                            if ($ExpandGroupMembers -and $principalType -eq 'Group') {
                                $nestedMembers = Get-GroupTransitiveMembers -GroupId $member.Id -GroupDisplayName $member.AdditionalProperties.displayName

                                foreach ($nestedMember in $nestedMembers) {
                                    $detailData.Add([PSCustomObject]@{
                                        GroupId                     = $group.Id
                                        GroupDisplayName            = $group.DisplayName
                                        GroupType                   = $groupType
                                        IsAssignableToRole          = $isRoleAssignable
                                        IsPIMEnabled                = $isPIMEnabled
                                        RecordCategory              = 'Membership'
                                        PrincipalId                 = $member.Id
                                        PrincipalDisplayName        = $member.AdditionalProperties.displayName
                                        PrincipalUPN                = $null
                                        PrincipalType               = 'Group'
                                        RelationType                = 'member'
                                        MembershipType              = 'inherited'
                                        InheritedFromGroupId        = $member.Id
                                        InheritedFromGroupName      = $member.AdditionalProperties.displayName
                                        DirectoryRoleId             = $null
                                        DirectoryRoleDisplayName    = $null
                                        DirectoryRoleAssignmentType = $null
                                        DirectoryRoleStatus         = $null
                                        PIMAccessType               = $null
                                        PIMRecordType               = $null
                                        PIMIsCurrentlyActive        = $null
                                        PIMIsPermanent              = $null
                                        PIMAssignmentType           = $null
                                        PIMMemberType               = $null
                                        TransitiveMemberId          = $nestedMember.Id
                                        TransitiveMemberDisplayName = $nestedMember.DisplayName
                                        TransitiveMemberUPN         = $nestedMember.UserPrincipalName
                                        TransitiveMemberType        = $nestedMember.Type
                                        StartDateTime               = $null
                                        EndDateTime                 = $null
                                    })
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Could not retrieve members for group $($group.Id): $_"
                    }

                    # Get owners
                    try {
                        $owners = Get-MgBetaGroupOwner -GroupId $group.Id -All -ErrorAction Stop
                        $ownerCount = $owners.Count

                        foreach ($owner in $owners) {
                            $odataType = $owner.AdditionalProperties.'@odata.type'
                            $principalType = 'Unknown'

                            switch ($odataType) {
                                '#microsoft.graph.user' { $principalType = 'User' }
                                '#microsoft.graph.servicePrincipal' { $principalType = 'ServicePrincipal' }
                                '#microsoft.graph.group' { $principalType = 'Group' }
                                default {
                                    if ($odataType -match '#microsoft\.graph\.(\w+)$') {
                                        $principalType = $Matches[1]
                                    }
                                }
                            }

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'Membership'
                                PrincipalId                 = $owner.Id
                                PrincipalDisplayName        = $owner.AdditionalProperties.displayName
                                PrincipalUPN                = $owner.AdditionalProperties.userPrincipalName
                                PrincipalType               = $principalType
                                RelationType                = 'owner'
                                MembershipType              = 'direct'
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $null
                                DirectoryRoleDisplayName    = $null
                                DirectoryRoleAssignmentType = $null
                                DirectoryRoleStatus         = $null
                                PIMAccessType               = $null
                                PIMRecordType               = $null
                                PIMIsCurrentlyActive        = $null
                                PIMIsPermanent              = $null
                                PIMAssignmentType           = $null
                                PIMMemberType               = $null
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $null
                                EndDateTime                 = $null
                            })
                        }
                    }
                    catch {
                        Write-Warning "Could not retrieve owners for group $($group.Id): $_"
                    }
                }

                # --- DIRECTORY ROLE DATA ---
                if ($IncludeDirectoryRoles -and $isRoleAssignable) {
                    try {
                        $roleData = Get-GroupDirectoryRoles -GroupId $group.Id -IncludeRoleDefinitions:$true

                        # Active assignments
                        foreach ($assignment in $roleData.ActiveAssignments) {
                            $directoryRoleCount++

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'DirectoryRole'
                                PrincipalId                 = $null
                                PrincipalDisplayName        = $null
                                PrincipalUPN                = $null
                                PrincipalType               = $null
                                RelationType                = $null
                                MembershipType              = $null
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $assignment.RoleDefinitionId
                                DirectoryRoleDisplayName    = $assignment.RoleDisplayName
                                DirectoryRoleAssignmentType = 'active'
                                DirectoryRoleStatus         = 'Active'
                                PIMAccessType               = $null
                                PIMRecordType               = $null
                                PIMIsCurrentlyActive        = $null
                                PIMIsPermanent              = $null
                                PIMAssignmentType           = $null
                                PIMMemberType               = $null
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $null
                                EndDateTime                 = $null
                            })
                        }

                        # Eligibility schedules
                        foreach ($schedule in $roleData.EligibilitySchedules) {
                            $directoryRoleCount++

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'DirectoryRole'
                                PrincipalId                 = $null
                                PrincipalDisplayName        = $null
                                PrincipalUPN                = $null
                                PrincipalType               = $null
                                RelationType                = $null
                                MembershipType              = $null
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $schedule.RoleDefinitionId
                                DirectoryRoleDisplayName    = $schedule.RoleDisplayName
                                DirectoryRoleAssignmentType = 'eligible'
                                DirectoryRoleStatus         = $schedule.Status
                                PIMAccessType               = $null
                                PIMRecordType               = $null
                                PIMIsCurrentlyActive        = $null
                                PIMIsPermanent              = $null
                                PIMAssignmentType           = $null
                                PIMMemberType               = $null
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $schedule.StartDateTime
                                EndDateTime                 = $schedule.EndDateTime
                            })
                        }

                        # Assignment schedules
                        foreach ($schedule in $roleData.AssignmentSchedules) {
                            $directoryRoleCount++

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'DirectoryRole'
                                PrincipalId                 = $null
                                PrincipalDisplayName        = $null
                                PrincipalUPN                = $null
                                PrincipalType               = $null
                                RelationType                = $null
                                MembershipType              = $null
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $schedule.RoleDefinitionId
                                DirectoryRoleDisplayName    = $schedule.RoleDisplayName
                                DirectoryRoleAssignmentType = $schedule.AssignmentType
                                DirectoryRoleStatus         = $schedule.Status
                                PIMAccessType               = $null
                                PIMRecordType               = $null
                                PIMIsCurrentlyActive        = $null
                                PIMIsPermanent              = $null
                                PIMAssignmentType           = $null
                                PIMMemberType               = $null
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $schedule.StartDateTime
                                EndDateTime                 = $schedule.EndDateTime
                            })
                        }
                    }
                    catch {
                        Write-Warning "Could not retrieve directory roles for group $($group.Id): $_"
                    }
                }

                # --- PIM DATA ---
                if ($IncludePIMData -and $isPIMEnabled) {
                    try {
                        $pimData = Get-PIMGroup -GroupId $group.Id -IncludeGroupDetails:$false -AccessType 'all'

                        # Eligibility Schedules
                        foreach ($schedule in $pimData.Eligibility.Schedules) {
                            $principal = Get-PrincipalInfo -PrincipalId $schedule.PrincipalId
                            $isPermanent = ($schedule.ScheduleInfo.Expiration.Type -eq 'noExpiration') -or ($null -eq $schedule.ScheduleInfo.Expiration.EndDateTime)

                            if ($schedule.AccessId -eq 'member') { $pimEligibleMembers++ }
                            elseif ($schedule.AccessId -eq 'owner') { $pimEligibleOwners++ }

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'PIMAccess'
                                PrincipalId                 = $schedule.PrincipalId
                                PrincipalDisplayName        = $principal.DisplayName
                                PrincipalUPN                = $principal.UserPrincipalName
                                PrincipalType               = $principal.Type
                                RelationType                = $null
                                MembershipType              = $null
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $null
                                DirectoryRoleDisplayName    = $null
                                DirectoryRoleAssignmentType = $null
                                DirectoryRoleStatus         = $null
                                PIMAccessType               = $schedule.AccessId
                                PIMRecordType               = 'EligibilitySchedule'
                                PIMIsCurrentlyActive        = $false
                                PIMIsPermanent              = $isPermanent
                                PIMAssignmentType           = $null
                                PIMMemberType               = $schedule.MemberType
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $schedule.ScheduleInfo.StartDateTime
                                EndDateTime                 = $schedule.ScheduleInfo.Expiration.EndDateTime
                            })

                            # Expand group members if requested
                            if ($ExpandGroupMembers -and $principal.Type -eq 'Group') {
                                $groupMembers = Get-GroupTransitiveMembers -GroupId $schedule.PrincipalId -GroupDisplayName $principal.DisplayName

                                foreach ($member in $groupMembers) {
                                    $detailData.Add([PSCustomObject]@{
                                        GroupId                     = $group.Id
                                        GroupDisplayName            = $group.DisplayName
                                        GroupType                   = $groupType
                                        IsAssignableToRole          = $isRoleAssignable
                                        IsPIMEnabled                = $isPIMEnabled
                                        RecordCategory              = 'PIMAccess'
                                        PrincipalId                 = $schedule.PrincipalId
                                        PrincipalDisplayName        = $principal.DisplayName
                                        PrincipalUPN                = $null
                                        PrincipalType               = $principal.Type
                                        RelationType                = $null
                                        MembershipType              = $null
                                        InheritedFromGroupId        = $null
                                        InheritedFromGroupName      = $null
                                        DirectoryRoleId             = $null
                                        DirectoryRoleDisplayName    = $null
                                        DirectoryRoleAssignmentType = $null
                                        DirectoryRoleStatus         = $null
                                        PIMAccessType               = $schedule.AccessId
                                        PIMRecordType               = 'EligibilitySchedule'
                                        PIMIsCurrentlyActive        = $false
                                        PIMIsPermanent              = $isPermanent
                                        PIMAssignmentType           = $null
                                        PIMMemberType               = 'inherited (group)'
                                        TransitiveMemberId          = $member.Id
                                        TransitiveMemberDisplayName = $member.DisplayName
                                        TransitiveMemberUPN         = $member.UserPrincipalName
                                        TransitiveMemberType        = $member.Type
                                        StartDateTime               = $schedule.ScheduleInfo.StartDateTime
                                        EndDateTime                 = $schedule.ScheduleInfo.Expiration.EndDateTime
                                    })
                                }
                            }
                        }

                        # Assignment Schedules
                        foreach ($schedule in $pimData.Assignment.Schedules) {
                            $principal = Get-PrincipalInfo -PrincipalId $schedule.PrincipalId
                            $isPermanent = ($schedule.ScheduleInfo.Expiration.Type -eq 'noExpiration') -or ($null -eq $schedule.ScheduleInfo.Expiration.EndDateTime)

                            if ($schedule.AccessId -eq 'member') { $pimAssignedMembers++ }
                            elseif ($schedule.AccessId -eq 'owner') { $pimAssignedOwners++ }

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'PIMAccess'
                                PrincipalId                 = $schedule.PrincipalId
                                PrincipalDisplayName        = $principal.DisplayName
                                PrincipalUPN                = $principal.UserPrincipalName
                                PrincipalType               = $principal.Type
                                RelationType                = $null
                                MembershipType              = $null
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $null
                                DirectoryRoleDisplayName    = $null
                                DirectoryRoleAssignmentType = $null
                                DirectoryRoleStatus         = $null
                                PIMAccessType               = $schedule.AccessId
                                PIMRecordType               = 'AssignmentSchedule'
                                PIMIsCurrentlyActive        = $false
                                PIMIsPermanent              = $isPermanent
                                PIMAssignmentType           = $schedule.AssignmentType
                                PIMMemberType               = $schedule.MemberType
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $schedule.ScheduleInfo.StartDateTime
                                EndDateTime                 = $schedule.ScheduleInfo.Expiration.EndDateTime
                            })

                            # Expand group members if requested
                            if ($ExpandGroupMembers -and $principal.Type -eq 'Group') {
                                $groupMembers = Get-GroupTransitiveMembers -GroupId $schedule.PrincipalId -GroupDisplayName $principal.DisplayName

                                foreach ($member in $groupMembers) {
                                    $detailData.Add([PSCustomObject]@{
                                        GroupId                     = $group.Id
                                        GroupDisplayName            = $group.DisplayName
                                        GroupType                   = $groupType
                                        IsAssignableToRole          = $isRoleAssignable
                                        IsPIMEnabled                = $isPIMEnabled
                                        RecordCategory              = 'PIMAccess'
                                        PrincipalId                 = $schedule.PrincipalId
                                        PrincipalDisplayName        = $principal.DisplayName
                                        PrincipalUPN                = $null
                                        PrincipalType               = $principal.Type
                                        RelationType                = $null
                                        MembershipType              = $null
                                        InheritedFromGroupId        = $null
                                        InheritedFromGroupName      = $null
                                        DirectoryRoleId             = $null
                                        DirectoryRoleDisplayName    = $null
                                        DirectoryRoleAssignmentType = $null
                                        DirectoryRoleStatus         = $null
                                        PIMAccessType               = $schedule.AccessId
                                        PIMRecordType               = 'AssignmentSchedule'
                                        PIMIsCurrentlyActive        = $false
                                        PIMIsPermanent              = $isPermanent
                                        PIMAssignmentType           = $schedule.AssignmentType
                                        PIMMemberType               = 'inherited (group)'
                                        TransitiveMemberId          = $member.Id
                                        TransitiveMemberDisplayName = $member.DisplayName
                                        TransitiveMemberUPN         = $member.UserPrincipalName
                                        TransitiveMemberType        = $member.Type
                                        StartDateTime               = $schedule.ScheduleInfo.StartDateTime
                                        EndDateTime                 = $schedule.ScheduleInfo.Expiration.EndDateTime
                                    })
                                }
                            }
                        }

                        # Eligibility Instances (currently active)
                        foreach ($instance in $pimData.Eligibility.Instances) {
                            $principal = Get-PrincipalInfo -PrincipalId $instance.PrincipalId
                            $isPermanent = $null -eq $instance.EndDateTime

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'PIMAccess'
                                PrincipalId                 = $instance.PrincipalId
                                PrincipalDisplayName        = $principal.DisplayName
                                PrincipalUPN                = $principal.UserPrincipalName
                                PrincipalType               = $principal.Type
                                RelationType                = $null
                                MembershipType              = $null
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $null
                                DirectoryRoleDisplayName    = $null
                                DirectoryRoleAssignmentType = $null
                                DirectoryRoleStatus         = $null
                                PIMAccessType               = $instance.AccessId
                                PIMRecordType               = 'EligibilityInstance'
                                PIMIsCurrentlyActive        = $true
                                PIMIsPermanent              = $isPermanent
                                PIMAssignmentType           = $null
                                PIMMemberType               = $instance.MemberType
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $instance.StartDateTime
                                EndDateTime                 = $instance.EndDateTime
                            })

                            # Expand group members if requested
                            if ($ExpandGroupMembers -and $principal.Type -eq 'Group') {
                                $groupMembers = Get-GroupTransitiveMembers -GroupId $instance.PrincipalId -GroupDisplayName $principal.DisplayName

                                foreach ($member in $groupMembers) {
                                    $detailData.Add([PSCustomObject]@{
                                        GroupId                     = $group.Id
                                        GroupDisplayName            = $group.DisplayName
                                        GroupType                   = $groupType
                                        IsAssignableToRole          = $isRoleAssignable
                                        IsPIMEnabled                = $isPIMEnabled
                                        RecordCategory              = 'PIMAccess'
                                        PrincipalId                 = $instance.PrincipalId
                                        PrincipalDisplayName        = $principal.DisplayName
                                        PrincipalUPN                = $null
                                        PrincipalType               = $principal.Type
                                        RelationType                = $null
                                        MembershipType              = $null
                                        InheritedFromGroupId        = $null
                                        InheritedFromGroupName      = $null
                                        DirectoryRoleId             = $null
                                        DirectoryRoleDisplayName    = $null
                                        DirectoryRoleAssignmentType = $null
                                        DirectoryRoleStatus         = $null
                                        PIMAccessType               = $instance.AccessId
                                        PIMRecordType               = 'EligibilityInstance'
                                        PIMIsCurrentlyActive        = $true
                                        PIMIsPermanent              = $isPermanent
                                        PIMAssignmentType           = $null
                                        PIMMemberType               = 'inherited (group)'
                                        TransitiveMemberId          = $member.Id
                                        TransitiveMemberDisplayName = $member.DisplayName
                                        TransitiveMemberUPN         = $member.UserPrincipalName
                                        TransitiveMemberType        = $member.Type
                                        StartDateTime               = $instance.StartDateTime
                                        EndDateTime                 = $instance.EndDateTime
                                    })
                                }
                            }
                        }

                        # Assignment Instances (currently active)
                        foreach ($instance in $pimData.Assignment.Instances) {
                            $principal = Get-PrincipalInfo -PrincipalId $instance.PrincipalId
                            $isPermanent = $null -eq $instance.EndDateTime

                            $detailData.Add([PSCustomObject]@{
                                GroupId                     = $group.Id
                                GroupDisplayName            = $group.DisplayName
                                GroupType                   = $groupType
                                IsAssignableToRole          = $isRoleAssignable
                                IsPIMEnabled                = $isPIMEnabled
                                RecordCategory              = 'PIMAccess'
                                PrincipalId                 = $instance.PrincipalId
                                PrincipalDisplayName        = $principal.DisplayName
                                PrincipalUPN                = $principal.UserPrincipalName
                                PrincipalType               = $principal.Type
                                RelationType                = $null
                                MembershipType              = $null
                                InheritedFromGroupId        = $null
                                InheritedFromGroupName      = $null
                                DirectoryRoleId             = $null
                                DirectoryRoleDisplayName    = $null
                                DirectoryRoleAssignmentType = $null
                                DirectoryRoleStatus         = $null
                                PIMAccessType               = $instance.AccessId
                                PIMRecordType               = 'AssignmentInstance'
                                PIMIsCurrentlyActive        = $true
                                PIMIsPermanent              = $isPermanent
                                PIMAssignmentType           = $instance.AssignmentType
                                PIMMemberType               = $instance.MemberType
                                TransitiveMemberId          = $null
                                TransitiveMemberDisplayName = $null
                                TransitiveMemberUPN         = $null
                                TransitiveMemberType        = $null
                                StartDateTime               = $instance.StartDateTime
                                EndDateTime                 = $instance.EndDateTime
                            })

                            # Expand group members if requested
                            if ($ExpandGroupMembers -and $principal.Type -eq 'Group') {
                                $groupMembers = Get-GroupTransitiveMembers -GroupId $instance.PrincipalId -GroupDisplayName $principal.DisplayName

                                foreach ($member in $groupMembers) {
                                    $detailData.Add([PSCustomObject]@{
                                        GroupId                     = $group.Id
                                        GroupDisplayName            = $group.DisplayName
                                        GroupType                   = $groupType
                                        IsAssignableToRole          = $isRoleAssignable
                                        IsPIMEnabled                = $isPIMEnabled
                                        RecordCategory              = 'PIMAccess'
                                        PrincipalId                 = $instance.PrincipalId
                                        PrincipalDisplayName        = $principal.DisplayName
                                        PrincipalUPN                = $null
                                        PrincipalType               = $principal.Type
                                        RelationType                = $null
                                        MembershipType              = $null
                                        InheritedFromGroupId        = $null
                                        InheritedFromGroupName      = $null
                                        DirectoryRoleId             = $null
                                        DirectoryRoleDisplayName    = $null
                                        DirectoryRoleAssignmentType = $null
                                        DirectoryRoleStatus         = $null
                                        PIMAccessType               = $instance.AccessId
                                        PIMRecordType               = 'AssignmentInstance'
                                        PIMIsCurrentlyActive        = $true
                                        PIMIsPermanent              = $isPermanent
                                        PIMAssignmentType           = $instance.AssignmentType
                                        PIMMemberType               = 'inherited (group)'
                                        TransitiveMemberId          = $member.Id
                                        TransitiveMemberDisplayName = $member.DisplayName
                                        TransitiveMemberUPN         = $member.UserPrincipalName
                                        TransitiveMemberType        = $member.Type
                                        StartDateTime               = $instance.StartDateTime
                                        EndDateTime                 = $instance.EndDateTime
                                    })
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Could not retrieve PIM data for group $($group.Id): $_"
                    }
                }

                # Add summary row
                $summaryData.Add([PSCustomObject]@{
                    GroupId              = $group.Id
                    DisplayName          = $group.DisplayName
                    GroupType            = $groupType
                    MembershipType       = $membershipType
                    SecurityEnabled      = $group.SecurityEnabled
                    MailEnabled          = $group.MailEnabled
                    IsAssignableToRole   = $isRoleAssignable
                    IsPIMEnabled         = $isPIMEnabled
                    MemberCount          = $memberCount
                    OwnerCount           = $ownerCount
                    DirectoryRoleCount   = $directoryRoleCount
                    PIMEligible_Members  = $pimEligibleMembers
                    PIMEligible_Owners   = $pimEligibleOwners
                    PIMAssigned_Members  = $pimAssignedMembers
                    PIMAssigned_Owners   = $pimAssignedOwners
                })
            }

            Write-Progress -Activity "Processing Groups" -Completed

            # Export CSVs
            $result = [PSCustomObject]@{
                SummaryReport = $null
                DetailReport  = $null
            }

            if ($summaryData.Count -gt 0) {
                Write-Verbose "Exporting summary report to: $summaryPath"
                $summaryData | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
                $result.SummaryReport = Get-Item -Path $summaryPath
            }

            if ($detailData.Count -gt 0) {
                Write-Verbose "Exporting detail report ($($detailData.Count) records) to: $detailPath"
                $detailData | Export-Csv -Path $detailPath -NoTypeInformation -Encoding UTF8
                $result.DetailReport = Get-Item -Path $detailPath
            }

            if ($summaryData.Count -eq 0 -and $detailData.Count -eq 0) {
                Write-Warning "No data found to export."
            }

            return $result
        }
        catch {
            Write-Error "Failed to generate group security report: $_"
            throw
        }
    }
}

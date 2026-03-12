#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Microsoft.Graph.Groups'; ModuleVersion = '2.0.0' }

<#
.SYNOPSIS
    Bulk-remove Entra ID groups from a CSV of GroupIds.

.DESCRIPTION
    Reads a CSV file containing a GroupId column and deletes each corresponding
    group from Entra ID. All operations are logged via PowerShell transcript.

.PARAMETER InputCsv
    Path to the CSV file. Must contain a 'GroupId' column with group object IDs.

.PARAMETER TranscriptPath
    Path for the transcript log file. Defaults to
    Remove-EntraGroups_<timestamp>.log in the current directory.

.PARAMETER Force
    Skip the confirmation prompt before deletion begins.

.EXAMPLE
    .\Remove-EntraGroups.ps1 -InputCsv 'C:\Data\groups-to-delete.csv'

    Prompts for confirmation, then deletes each group listed in the CSV.

.EXAMPLE
    .\Remove-EntraGroups.ps1 -InputCsv 'C:\Data\groups-to-delete.csv' -Force -Verbose

    Deletes without prompting; verbose output shows per-item progress.

.EXAMPLE
    .\Remove-EntraGroups.ps1 -InputCsv 'C:\Data\groups-to-delete.csv' -WhatIf

    Shows what would be deleted without making any changes.

.OUTPUTS
    None. This script writes results to the console and a transcript log file.

.NOTES
    Requires an active Microsoft Graph session with Group.ReadWrite.All permission.
    Connect first: Connect-MgGraph -Scopes 'Group.ReadWrite.All'

    Warning: Deletion behavior varies by group type.
    - Security groups and Microsoft 365 groups are soft-deleted and recoverable within 30 days.
    - Distribution groups and mail-enabled security groups are permanently deleted immediately
      and CANNOT be restored. Verify your CSV before running without -WhatIf.
    - Role-assignable groups require RoleManagement.ReadWrite.Directory permission in addition
      to Group.ReadWrite.All.
    - Groups synchronized from on-premises AD (onPremisesSyncEnabled = true) cannot be deleted
      via Graph API; deletion must occur in on-premises Active Directory.

    CSV format:
        GroupId
        xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   <-- Group Object ID
        yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
[OutputType([Void])]
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if (-not (Test-Path -Path $PSItem -PathType Leaf)) {
            throw "File not found: $PSItem"
        }
        $true
    })]
    [String]$InputCsv,

    [Parameter()]
    [String]$TranscriptPath,

    [Parameter()]
    [Switch]$DryRun,

    [Parameter()]
    [Switch]$Force
)

# When -Force is specified, suppress all confirmation prompts (including per-item ShouldProcess)
if ($Force) {
    $ConfirmPreference = 'None'
}

# Build transcript path
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $TranscriptPath) {
    $TranscriptPath = Join-Path -Path (Get-Location) -ChildPath "Remove-EntraGroups_$timestamp.log"
}

# Start transcript (bypass WhatIf — logging is observational, not destructive)
$savedWhatIf = $WhatIfPreference
$WhatIfPreference = $false
Start-Transcript -Path $TranscriptPath -Append
$WhatIfPreference = $savedWhatIf
Write-Verbose -Message "Transcript logging to: $TranscriptPath"

try {
    # Import and validate CSV
    Write-Verbose -Message "Importing CSV: $InputCsv"
    $entries = Import-Csv -Path $InputCsv -Encoding UTF8

    if (-not $entries) {
        Write-Warning -Message 'CSV file is empty. Nothing to process.'
        return
    }

    $columnNames = ($entries | Select-Object -First 1).PSObject.Properties.Name
    if ('GroupId' -notin $columnNames) {
        throw "CSV must contain a 'GroupId' column. Found columns: $($columnNames -join ', ')"
    }

    # Filter out blank rows
    $entries = @($entries | Where-Object -FilterScript { -not [String]::IsNullOrWhiteSpace($PSItem.GroupId) })
    $totalCount = $entries.Count
    Write-Host "Found $totalCount group(s) to delete in CSV." -ForegroundColor Cyan

    if ($totalCount -eq 0) {
        Write-Warning -Message 'No valid GroupId values found in CSV.'
        return
    }

    # Confirmation gate (skip when -WhatIf so per-item WhatIf output is shown)
    if (-not $WhatIfPreference -and -not $Force -and -not $PSCmdlet.ShouldProcess(
        "$totalCount group(s)",
        'Delete'
    )) {
        Write-Host 'Operation cancelled by user.' -ForegroundColor Yellow
        return
    }

    # Process deletions
    $successCount = 0
    $failCount = 0
    $skippedCount = 0
    $processedCount = 0

    foreach ($entry in $entries) {
        $processedCount++
        $groupId = $entry.GroupId.Trim()
        $groupDisplayName = $entry.DisplayName.Trim()
        $percentComplete = [Math]::Round(($processedCount / $totalCount) * 100)

        Write-Progress -Activity 'Removing Groups' `
            -Status "[$processedCount/$totalCount] $groupId" `
            -PercentComplete $percentComplete

        # Validate GUID format
        $guidResult = [Guid]::Empty
        if (-not [Guid]::TryParse($groupId, [ref]$guidResult)) {
            Write-Warning -Message "Skipping invalid GroupId (not a GUID): [$groupId] $groupDisplayName"
            $skippedCount++
            continue
        }

        if ($PSCmdlet.ShouldProcess($groupId, 'Remove-MgGroup')) {
            try {
                if (-not $DryRun) {
                    Remove-MgGroup -GroupId $groupId -ErrorAction Stop
                }
                Write-Verbose -Message "Deleted group: [$groupId] $groupDisplayName"
                $successCount++
            }
            catch {
                Write-Warning -Message "Failed to delete group [$groupId] $groupDisplayName : $PSItem"
                $failCount++
            }
        }
    }

    # Summary
    Write-Host ''
    Write-Host '--- Summary ---' -ForegroundColor Cyan
    Write-Host "  Total in CSV:  $totalCount" -ForegroundColor White
    Write-Host "  Deleted:       $successCount" -ForegroundColor Green
    if ($failCount -gt 0) {
        Write-Host "  Failed:        $failCount" -ForegroundColor Red
    }
    if ($skippedCount -gt 0) {
        Write-Host "  Skipped:       $skippedCount" -ForegroundColor Yellow
    }
    Write-Host "  Transcript:    $TranscriptPath" -ForegroundColor White
}
catch {
    Write-Error -Message "Script failed: $PSItem"
    throw
}
finally {
    Write-Progress -Activity 'Removing Groups' -Completed
    $savedWhatIf = $WhatIfPreference
    $WhatIfPreference = $false
    Stop-Transcript
    $WhatIfPreference = $savedWhatIf
}

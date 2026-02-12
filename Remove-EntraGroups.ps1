#Requires -Version 5.1
<#
.SYNOPSIS
    Deletes Entra ID groups from a CSV input file.

.DESCRIPTION
    Reads a CSV file containing GroupId values and deletes each group using
    Microsoft Graph PowerShell SDK. All output is logged via Start-Transcript.

.PARAMETER CsvPath
    Path to the CSV file. Must contain a 'GroupId' column with group object IDs.

.PARAMETER TranscriptPath
    Optional path for the transcript log file. Defaults to
    Remove-EntraGroups_<timestamp>.log in the current directory.

.EXAMPLE
    .\Remove-EntraGroups.ps1 -CsvPath .\groups-to-delete.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$TranscriptPath
)

# Set default transcript path with timestamp
if (-not $TranscriptPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $TranscriptPath = Join-Path $PSScriptRoot "Remove-EntraGroups_$timestamp.log"
}

Start-Transcript -Path $TranscriptPath
Write-Host "Transcript logging to: $TranscriptPath"

try {
    # Validate CSV exists
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return
    }

    # Import and validate CSV
    $groups = Import-Csv -Path $CsvPath
    if (-not $groups) {
        Write-Error "CSV file is empty: $CsvPath"
        return
    }
    if (-not ($groups | Get-Member -Name 'GroupId' -MemberType NoteProperty)) {
        Write-Error "CSV file must contain a 'GroupId' column."
        return
    }

    $groupIds = $groups | Where-Object { $_.GroupId -and $_.GroupId.Trim() -ne '' } | Select-Object -ExpandProperty GroupId
    $totalCount = $groupIds.Count

    if ($totalCount -eq 0) {
        Write-Warning "No valid GroupId values found in CSV."
        return
    }

    Write-Host "`n===== Group Deletion Summary =====" -ForegroundColor Cyan
    Write-Host "CSV File   : $CsvPath"
    Write-Host "Groups     : $totalCount"
    Write-Host "=================================="

    # List all groups to be deleted
    Write-Host "`nGroups to delete:"
    foreach ($id in $groupIds) {
        Write-Host "  - $id"
    }

    # Batch confirmation
    Write-Host ""
    $confirm = Read-Host "Delete $totalCount group(s)? (Y/N)"
    if ($confirm -notin @('Y', 'y')) {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        return
    }

    # Ensure Graph connection with required scope
    Write-Host "`nVerifying Microsoft Graph connection..."
    try {
        $context = Get-MgContext
        if (-not $context) {
            Write-Host "Not connected. Connecting to Microsoft Graph..."
            Connect-MgGraph -Scopes "Group.ReadWrite.All"
        } else {
            Write-Host "Connected as: $($context.Account)"
        }
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        return
    }

    # Delete groups
    $successCount = 0
    $failCount = 0

    Write-Host "`nDeleting groups...`n"
    for ($i = 0; $i -lt $totalCount; $i++) {
        $groupId = $groupIds[$i].Trim()
        $progress = "[$($i + 1)/$totalCount]"

        try {
            Remove-MgGroup -GroupId $groupId -ErrorAction Stop
            Write-Host "$progress Deleted: $groupId" -ForegroundColor Green
            $successCount++
        } catch {
            Write-Host "$progress FAILED:  $groupId - $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
        }
    }

    # Final summary
    Write-Host "`n===== Results =====" -ForegroundColor Cyan
    Write-Host "Total     : $totalCount"
    Write-Host "Succeeded : $successCount" -ForegroundColor Green
    Write-Host "Failed    : $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "==================="

} finally {
    Stop-Transcript
}

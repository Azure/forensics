$ErrorActionPreference = 'Stop'

# Encryption is configured at the host level in the ARM template.
# This script only prepares newly attached RAW data disks inside the guest OS.
$disks = Get-Disk | Where-Object { $_.PartitionStyle -eq "RAW" }

if (-not $disks) {
    Write-Host "No RAW disks found. Skipping disk initialization."
    return
}

foreach ($disk in $disks) {
    Write-Host "Initializing Disk $($disk.Number)..."
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru |
        New-Partition -AssignDriveLetter -UseMaximumSize |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel "DataDisk" -Confirm:$false
    Write-Host "Disk $($disk.Number) initialized and formatted."
}

Write-Host "Disk initialization and formatting complete."
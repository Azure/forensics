
# Get the list of newly added disks
$disks = Get-Disk | Where-Object { $_.PartitionStyle -eq "RAW" }

# Initialize and format each disk
foreach ($disk in $disks) {
    Write-Host "Initializing Disk $($disk.Number)..."
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DataDisk" -Confirm:$false
    Write-Host "Disk $($disk.Number) initialized and formatted."
}

Write-Host "Disk initialization and formatting complete."



param (
    # The name of the Key Vault
    [Parameter(Mandatory = $true)]
    [string]
    $CoCProdKeyvaultName,

    # The name of the Resource Group
    [Parameter(Mandatory = $true)]
    [string]
    $CoCProdRGName,

    # The name of the VM
    [Parameter(Mandatory = $true)]
    [string]
    $CoCProdVMName,

    # The Principal ID of the VM system identity
    [Parameter(Mandatory = $true)]
    [string]
    $VMIdentity 

)

# Get the list of newly added disks
$disks = Get-Disk | Where-Object { $_.PartitionStyle -eq "RAW" }

# Initialize and format each disk
foreach ($disk in $disks) {
    Write-Host "Initializing Disk $($disk.Number)..."
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "DataDisk" -Confirm:$false
    Write-Host "Disk $($disk.Number) initialized and formatted."
}

Write-Host "Disk initialization and formatting complete."

#Required PowerShell module to start the Azure Disk Encryption
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module Az.Accounts -requiredVersion 2.12.1 -Repository PSGallery -Scope AllUsers -Force
Install-Module Az.Resources -requiredVersion 6.6.0 -Repository PSGallery -Scope AllUsers -Force
Install-Module Az.Compute -requiredVersion 5.7.0 -Repository PSGallery -Scope AllUsers -Force
Install-Module Az.KeyVault -requiredVersion 4.9.2 -Repository PSGallery -Scope AllUsers -Force

# Connect to Azure
Connect-AzAccount -Identity

$KeyVault = Get-AzKeyVault -VaultName $CoCProdKeyvaultName -ResourceGroupName $CoCProdRGName
Set-AzVMDiskEncryptionExtension -ResourceGroupName $CoCProdRGName -VMName $CoCProdVMName -DiskEncryptionKeyVaultUrl $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId -Force

#restart the localhost
#Restart-Computer -Force

# Remove the Hybrid Runbook system identity from the Owner role assigned to the storage account
Start-Sleep -s 30
$subscriptionID = (Get-AzContext).Subscription.Id
Remove-AzRoleAssignment -PrincipalId $VMIdentity -Scope "/subscriptions/$subscriptionID/resourceGroups/$CoCProdRGName" -RoleDefinitionName "Owner"




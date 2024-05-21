<#
.SYNOPSIS
    Performs a digital evidence capture operation on a target VM.
    This script is the optimized version that runs in parallel jobs.

.DESCRIPTION
    This is sample code, please be sure to read
    https://docs.microsoft.com/azure/architecture/example-scenario/forensics/ to get
    all the requirements in place and adapt the code to your environment by replacing
    the placeholders and adding the required code blocks before using it. Key outputs
    are in the script for debug reasons, remove the output after the initial tests to
    improve the security of your script.
    
    This is designed to be run from a Windows Hybrid Runbook Worker in response to a
    digital evidence capture request for a target VM. It will create disk snapshots
    for all disks (OS and Data Disks), copying them to immutable SOC storage, takes
    the hash of all disks if specified in the CalculateHash parameter, and stores them
    in the SOC Key Vault.

    The hash calculation may require a long time to complete, depending on the algorithm 
    chosen and on the size of the disks. The script will run in parallel jobs (one job 
    for each disk) to speed up the process. The most performant algorithm is SKEIN because
    it reads the disk in chunks of 1MB and merges all the hashes calculated for each chunk.

    This script depends on Az.Accounts, Az.Compute, Az.Storage, and Az.KeyVault being 
    imported in your Azure Automation account and in the Hybrid Runbook Worker.
    See: https://docs.microsoft.com/en-us/azure/automation/az-modules

.EXAMPLE
    Copy-VmDigitalEvidence -SubscriptionId ffeeddcc-bbaa-9988-7766-554433221100 -ResourceGroupName rg-finance-vms -VirtualMachineName vm-workstation-001

.LINK
    https://docs.microsoft.com/azure/architecture/example-scenario/forensics/
#>

param (
    # The ID of subscription in which the target Virtual Machine is stored
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,

    # The Resource Group containing the Virtual Machine
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,

    # The name of the target Virtual Machine
    [Parameter(Mandatory = $true)]
    [string]
    $VirtualMachineName,

    # Hash Calculation (Optional. Allowed Values:TRUE/FALSE Default = TRUE)
    [Parameter(Mandatory = $false)]
    [string]
    $CalculateHash = "TRUE",

    # Hash Algorithm (Optional. Allowed Values:MD5/SHA256/SKEIN/KECCAK/SHA3 Default = MD5)
    [Parameter(Mandatory = $false)]
    [ValidateSet("MD5", "SHA256", "SKEIN", "KECCAK", "SHA3")]
    [string]
    $HashAlgorithm = "MD5"
)

#$ErrorActionPreference = 'Stop'

######################################### CoC Constants ###################################################
# Update the following Automation Account Variable with the values related to your environment

$destSubId  = Get-AutomationVariable -Name 'destSubId'  # The subscription containing the storage account being copied to (ex. 00112233-4455-6677-8899-aabbccddeeff)
$destRGName = Get-AutomationVariable -Name 'destRGName' # The name of the resource group containing the storage account being copied to 
$destSAblob = Get-AutomationVariable -Name 'destSAblob' # The name of the storage account for BLOB
$destSAfile = Get-AutomationVariable -Name 'destSAfile' # The name of the storage account for FILE
$destKV     = Get-AutomationVariable -Name 'destKV'     # The name of the keyvault to store a copy of the BEK in the dest subscription

# Please do not change the following constants
$destTempShare = 'hash'                               # The temporary file share mounted on the hybrid worker
$destSAContainer = 'immutable'                        # The name of the container within the storage account
$targetWindowsDir = "Z:"                              # The mapping path to the share that will contain the disk and its hash. By default, the scripts assume you mounted the Azure file share on drive Z.
$snapshotPrefix = (Get-Date).ToString('yyyyMMddHHmm') # The prefix of the snapshot to be created

############################################################################################################
Write-Output "SubscriptionId: $SubscriptionId"
Write-Output "ResourceGroupName: $ResourceGroupName"
Write-Output "VirtualMachineName: $VirtualMachineName"


#############################################################################################
# Please verify that your Hybrid Runbook Worker has the following modules installed

    # Uninstall-Module Az.Accounts -Force
    # Uninstall-Module Az.Resources -Force
    # Uninstall-Module Az.Compute -Force
    # Uninstall-Module Az.Storage -Force
    # Uninstall-Module Az.KeyVault -Force    

    # Install-Module Az.Accounts -requiredVersion 2.12.1
    # Install-Module Az.Resources -requiredVersion 6.6.0
    # Install-Module Az.Compute -requiredVersion 5.7.0
    # Install-Module Az.Storage -requiredVersion 5.5.0
    # Install-Module Az.KeyVault -requiredVersion 4.9.2

#############################################################################################

#############################################################################################
# Script Block Section for HASH Algorithm implementation in parallel jobs

$MD5scriptBlock = {
    param($filePath)
    $hash = (Get-FileHash $filePath -Algorithm MD5).Hash
    $result = [PSCustomObject]@{
        Name = $args[0]
        FilePath = $filePath
        Hash = $hash
    }
    return $result
}

$SHA256scriptBlock = {
    param($filePath)
    $hash = (Get-FileHash $filePath -Algorithm SHA256).Hash
    $result = [PSCustomObject]@{
        Name = $args[0]
        FilePath = $filePath
        Hash = $hash
    }
    return $result
}

$SKEINscriptBlock = {
    param($filePath)
    $KVmodulePath = "C:\Program Files\WindowsPowerShell\Modules\Az.KeyVault\4.9.2"
    Add-Type -Path "$KVmodulePath\BouncyCastle.Crypto.dll" # DLL available in the Az.Keyvault PowerShell module folder

    #https://javadoc.io/static/org.bouncycastle/bcprov-jdk14/1.57/org/bouncycastle/crypto/digests/SkeinDigest.html
    $skein = New-Object Org.BouncyCastle.Crypto.Digests.SkeinDigest(512, 512)
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $bufferSize = 512KB
    $buffer = New-Object byte[] $bufferSize
 
    while (($bytesRead = $fileStream.Read($buffer, 0, $bufferSize)) -gt 0) {
        $skein.BlockUpdate($buffer, 0, $bytesRead)
    }
 
    $fileStream.Close()
 
    $hash = New-Object byte[] $skein.GetDigestSize()
    $skein.DoFinal($hash, 0)
 
    $hashString = [System.BitConverter]::ToString($hash).Replace('-', '')
    
    $result = [PSCustomObject]@{
        FilePath = $filePath
        Hash = $hashString
    }
    return $result
}

$KECCAKscriptBlock = {
    param($filePath)
    $KVmodulePath = "C:\Program Files\WindowsPowerShell\Modules\Az.KeyVault\4.9.2"
    Add-Type -Path "$KVmodulePath\BouncyCastle.Crypto.dll" # DLL available in the Az.Keyvault PowerShell module folder

    # https://javadoc.io/static/org.bouncycastle/bcprov-jdk14/1.57/org/bouncycastle/crypto/digests/SHA3Digest.html
    $keccak = New-Object Org.BouncyCastle.Crypto.Digests.KeccakDigest(512)
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $bufferSize = 1MB
    $buffer = New-Object byte[] $bufferSize
 
    while (($bytesRead = $fileStream.Read($buffer, 0, $bufferSize)) -gt 0) {
        $keccak.BlockUpdate($buffer, 0, $bytesRead)
    }
 
    $fileStream.Close()
 
    $hash = New-Object byte[] $keccak.GetDigestSize()
    $keccak.DoFinal($hash, 0)
 
    $hashString = [System.BitConverter]::ToString($hash).Replace('-', '')
    
    $result = [PSCustomObject]@{
        FilePath = $filePath
        Hash = $hashString
    }
    return $result
}

# End Script Block Section
#############################################################################################

##############################################
# Main script section

$swGlobal = [Diagnostics.Stopwatch]::StartNew()

################################## Hybrid Worker Check ######################################
$bios= Get-WmiObject -class Win32_BIOS
if ($bios) {   
    Write-Output "Running on Hybrid Worker"


    ################################## Login session ############################################
    # Connect to Azure (via Automation Account Managed Identity)
    # The following roles must be granted to the Azure AD identity of the Azure Automation account:
    #  - "Contributor" on the Resource Group of target Virtual Machine. This provides snapshot rights on Virtual Machine disks
    #  - "Storage Account Contributor" on the immutable SOC Storage Account
    #  - "Key Vault Secrets Officer" on the SOC Key Vault
    #  - "Key Vault Crypto Officer" on the SOC Key Vault (for future implementation of KEK option)
    #  - "Key Vault Secrets User" on the Key Vault used by target Virtual Machine
    

    Write-Output "Logging in to Azure..."
    Connect-AzAccount -Identity
    Set-AzContext -Subscription $SubscriptionId
    ################################## Mounting fileshare #######################################

    If (!(Test-Path $targetWindowsDir)) {
       $connectTestResult = Test-NetConnection -ComputerName "$destSAfile.file.core.windows.net" -Port 445
       if ($connectTestResult.TcpTestSucceeded) {
           $storageAccount = Get-AzStorageAccount -ResourceGroupName $destRGName -Name $destSAfile
           $keys = $storageAccount | Get-AzStorageAccountKey
           $destSAKey =  $keys[0].value
           # Save the password so the drive will persist on reboot
           cmd.exe /C "cmdkey /add:`"$destSAfile.file.core.windows.net`" /user:`"localhost\$destSAfile`" /pass:`"$destSAKey`""
           # Mount the drive
           New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$destSAfile.file.core.windows.net\hash" -Persist
       } else {
           Write-Error -Message "Unable to reach the Azure storage account via port 445. Check to make sure your organization or ISP is not blocking port 445, or use Azure P2S VPN, Azure S2S VPN, or Express Route to tunnel SMB traffic over a different port."
       }
    }

    ################################## Get VM and Disks #########################################

    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VirtualMachineName

    $disks = @()  # Array to hold both OS and Data Disks

    # Add OS Disk to the Disks array
    $osDisk = $vm.StorageProfile.OsDisk
    $disks += $osDisk

    # Add Data Disks to the Disks array
    $disks += $vm.StorageProfile.DataDisks

    ############################# Snapshot the Disks ############################################
    Write-Output "#################################"
    Write-Output "Snapshot the OS and Data Disks"
    Write-Output "#################################"

    $snapshots = @()  # Array to hold snapshots

    foreach ($disk in $disks) {
        $diskResource = Get-AzDisk -ResourceGroupName $ResourceGroupName -DiskName $disk.Name
        $snapshot = New-AzSnapshotConfig -SourceUri $diskResource.Id -CreateOption Copy -Location $vm.Location
        $snapshotName = $snapshotPrefix + "-" + $disk.Name.Replace("_","-")
        $snapshots += [PSCustomObject]@{
            Disk = $disk
            BEKurl = $diskResource.EncryptionSettingsCollection.EncryptionSettings.DiskEncryptionKey.SecretUrl
            Snapshot = $snapshot
            SnapshotName = $snapshotName
        }
        New-AzSnapshot -ResourceGroupName $ResourceGroupName -Snapshot $snapshot -SnapshotName $snapshotName
    }

    ################################ Copy Snapshots to Storage Account ##################################
    Write-Output "########################################################################"
    Write-Output "Copy the snapshots from source Resource Group to the storage account"
    Write-Output "########################################################################"

    Set-AzContext -Subscription $destSubId
    $targetStorageContextBlob = (Get-AzStorageAccount -ResourceGroupName $destRGName -Name $destSAblob).Context
    $targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $destRGName -Name $destSAfile).Context

    foreach ($snapshot in $snapshots) {
        Set-AzContext -Subscription $SubscriptionId
        $snapSasUrl = Grant-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $snapshot.SnapshotName -DurationInSecond 86400 -Access Read
        Set-AzContext -Subscription $destSubId
        # Start the job to copy the snapshot from source to the storage account
        Write-Output "########################################################################"
        Write-Output "Start Copying the snapshot to blob container"
        Write-output "Snapshot: $($snapshot.SnapshotName).vhd"
        Write-Output "########################################################################"
        Start-AzStorageBlobCopy -AbsoluteUri $snapSasUrl.AccessSAS -DestContainer $destSAContainer -DestContext $targetStorageContextBlob -DestBlob "$($snapshot.SnapshotName).vhd" -Force

        # If you need to calculate the hash, start the job to copy the snapshot to the fileshare
        if ($CalculateHash.ToUpper() -eq "TRUE") {
            Write-Output "########################################################################"
            Write-Output "Start Copying the snapshot to Fileshare"
            Write-output "Snapshot: $($snapshot.SnapshotName)"
            Write-Output "########################################################################"
            Start-AzStorageFileCopy -AbsoluteUri $snapSasUrl.AccessSAS -DestShareName $destTempShare -DestContext $targetStorageContextFile -DestFilePath $($snapshot.SnapshotName) -Force
        }

        # Copy the disk BEK to the SOC Key Vault
        $BEKurl = $snapshot.BEKurl
        if ($BEKurl) {
            Set-AzContext -Subscription $SubscriptionId
            $sourcekv = $BEKurl.Split("/")
            $BEK = Get-AzKeyVaultSecret -VaultName $sourcekv[2].split(".")[0] -Name $sourcekv[4] -Version $sourcekv[5]
            Write-Output "#################################################################"
            Write-Output "Disk Encryption Secret URL: $BEKurl"
            Write-Output "Key value: $($BEK.SecretValue)"
            Write-Output "#################################################################"
            Set-AzContext -Subscription $destSubId
            Set-AzKeyVaultSecret -VaultName $destKV -Name $snapshot.SnapshotName -SecretValue $BEK.SecretValue -ContentType "BEK" -Tag $BEK.Tags
        }
        else {
            Write-Output "Disk not encrypted"
        }
    }

    $snapshotList = $snapshots.SnapshotName

    #############################
    # HASH SECTION
    #############################

    ############################# Calculate the hash of the OS and Data disk snapshots ##############################

    if ($CalculateHash.ToUpper() -eq "TRUE") {
        $completedSnapshots = @()
        # Adding OS and Data snapshots to the list of completed snapshots to parallelize the hash calculation
        
        Write-Output "################################################################################"
        Write-Output "Waiting for all the copies of the snapshots to the fileshare to be completed"
        Write-Output "################################################################################"
        foreach ($snapshot in $snapshotList) {           
            $sw = [Diagnostics.Stopwatch]::StartNew()
            Get-AzStorageFileCopyState -Context $targetStorageContextFile -ShareName $destTempShare -FilePath $snapshot -WaitForComplete
            $sw.Stop()
            Write-Output "Elapsed time: $($sw.Elapsed.TotalMinutes)  minutes"           

            $completedSnapshots += $snapshot
        }

        # Adding parallel jobs for HASH calculation
        Write-Output "################################################################################"
        Write-Output "Starting to calculate the HASH for all the snapshots copied to the fileshare"
        Write-Output "################################################################################"
        $results = $null
        $jobs = @()

        foreach ($snapshot in $completedSnapshots) {
            $filePath = "$targetWindowsDir\$snapshot"
            switch ($HashAlgorithm.toUpper()) {
                "MD5" {
                    # MD5 hash algorithm selected
                    Write-Output "Starting MD5 hash job for $filePath..."
                    $jobs += Start-Job -ScriptBlock $MD5scriptBlock -ArgumentList $filePath
                }
                "SHA256" {
                    # SHA256 hash algorithm selected
                    Write-Output "Starting SHA256 hash job for $filePath..."
                    $jobs += Start-Job -ScriptBlock $SHA256scriptBlock -ArgumentList $filePath
                }
                "SKEIN" {
                    # Skein hash algorithm selected
                    Write-Output "Starting Skein hash job for $filePath..."
                    $jobs += Start-Job -ScriptBlock $SKEINscriptBlock -ArgumentList $filePath
                }
                {"KECCAK","SHA3" -contains $_} {
                    # KECCAK hash algorithm selected
                    Write-Output "Starting Keccak hash job for $filePath..."
                    $jobs += Start-Job -ScriptBlock $KECCAKscriptBlock -ArgumentList $filePath
                }
                default {
                    Write-Host "Invalid algorithm"
                }
            }
        }

        $sw = [Diagnostics.Stopwatch]::StartNew()
        Write-Output "##############################################################"
        Write-output "Waiting the hash jobs for all the snapshots to be completed"
        Write-Output "##############################################################"
        $results = Receive-Job -Job $jobs -Wait
        Remove-Job -Job $jobs

        # For aglorithms that require BouncyCastle.Crypto.dll, the 'results' array contains data to be ignored at its odd indexes
        $evenIndicesArray = @()
        if ($HashAlgorithm.ToUpper() -ne "MD5" -and  $HashAlgorithm.ToUpper() -ne "SHA256")  {
            for ($i = 1; $i -lt $results.Length; $i += 2) {
                $evenIndicesArray += $results[$i]
            }
            $results = $evenIndicesArray
        }

        foreach ($result in $results) {
                Write-Output "$($result.FilePath): $($result.Hash)"
                $snapshot = Split-Path $result.filePath -Leaf
                $dhash = $result.Hash.ToString()
                Write-Output "#################################################"
                Write-Output "Data disk - Put hash value in the Key Vault"
                Write-Output "#################################################"
                $Secret = ConvertTo-SecureString -String $dhash -AsPlainText -Force
                Set-AzKeyVaultSecret -VaultName $destKV -Name "$snapshot-hash-$($HashAlgorithm.toUpper())" -SecretValue $Secret -ContentType "text/plain"
                $targetStorageContextFile = (Get-AzStorageAccount -ResourceGroupName $destRGName -Name $destSAfile).Context
                Remove-AzStorageFile -ShareName $destTempShare -Path $snapshot -Context $targetStorageContextFile
        }

        $sw.Stop()
        Write-Output "Elapsed time: $($sw.Elapsed.TotalMinutes)  minutes" 

    }
    else {
        $dhash = "Not Calculated"
    }



    #############################
    # FINAL SECTION
    #############################
    Write-Output "##############################################################"
    Write-Output "Waiting for all the copies to blob to be completed"
    Write-Output "##############################################################"
    $sw = [Diagnostics.Stopwatch]::StartNew()

    Write-output $snapshotList

    foreach ($snapshot in $snapshotList) {
        Get-AzStorageBlobCopyState -Blob "$snapshot.vhd" -Container $destSAContainer -Context $targetStorageContextBlob -WaitForComplete
    }
    $sw.Stop()
    Write-Output "Elapsed time: $($sw.Elapsed.TotalMinutes)  minutes"
    Set-AzContext -Subscription $SubscriptionId


    #############################
    # CLEANUP SECTION
    #############################
    Write-Output "########################################"
    Write-Output "Waiting deletion of all source snapshots"
    Write-Output "########################################"

    $sw = [Diagnostics.Stopwatch]::StartNew()

    foreach ($snapshot in $snapshotList) {
        Revoke-AzSnapshotAccess -ResourceGroupName $ResourceGroupName -SnapshotName $snapshot
        Remove-AzSnapshot -ResourceGroupName $ResourceGroupName -SnapshotName $snapshot -Force
    }
    $sw.Stop()

    Write-Output "Elapsed time:  $($sw.Elapsed.TotalMinutes)  minutes"

    Write-Output "Cleanup Temp share from the VM"
    # Remove the temporary share on the hybrid worker
    Remove-PSDrive -Name Z -Force

    #################################
    # FINAL STATUS
    #################################

    # Output the job elapsed time
    $swGlobal.Stop()
    Write-Output "########################################################################"
    Write-Output "Operation completed."
    Write-Output "Elapsed time for the entire operation: $($swGlobal.Elapsed.TotalMinutes) minutes"
    Write-Output ""
    Write-Output "NOTE: $snapshotPrefix is the timestamp prefix used for:  "
    Write-Output "  - the digital evidences stored in the immutable blob container of the SOC Storage Account ($destSAblob)" 
    Write-Output "  - the secrets (hash and BEK) stored in the SOC Key Vault ($destKV)"
    Write-Output "########################################################################"

}
else {
    Write-Output "Running on Azure"
    Write-Error "This script must be run from an Azure Automation Hybrid Worker"
    Write-Output "You can run this script on a local machine only to test the hashing operation"
    Write-Output "or for debugging purposes."
    Write-Output "To install a Hybrid Worker please read:"
    Write-Output "https://docs.microsoft.com/azure/automation/automation-hybrid-runbook-worker#install-the-hybrid-runbook-worker"
}

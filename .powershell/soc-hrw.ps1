
param (
    # The resource ID of the storage account
    [Parameter(Mandatory = $true)]
    [string]
    $StorageAccountResourceID,

    # The Principal ID of the HRW system identity
    [Parameter(Mandatory = $true)]
    [string]
    $HRWIdentity,

    # The Principal ID of the HRW system identity
    [Parameter(Mandatory = $true)]
    [string]
    $regionCode

)

Write-Host $StorageAccountResourceID
Write-Output $StorageAccountResourceID

# Required powershell module for the Hybrid Runbook Worker
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

    Install-Module Az.Accounts -requiredVersion 2.12.1 -Repository PSGallery -Scope AllUsers -Force
    Install-Module Az.Resources -requiredVersion 6.6.0 -Repository PSGallery -Scope AllUsers -Force
    Install-Module Az.Compute -requiredVersion 5.7.0 -Repository PSGallery -Scope AllUsers -Force
    Install-Module Az.Storage -requiredVersion 5.5.0 -Repository PSGallery -Scope AllUsers -Force
    Install-Module Az.KeyVault -requiredVersion 4.9.2 -Repository PSGallery -Scope AllUsers -Force

    Uninstall-Module Az.Accounts -Force
    Install-Module Az.Accounts -requiredVersion 2.12.1

# Set LegalHold Access Policy to the immutable container of the Storage Account

Connect-AzAccount -Identity

#---- Codice per Rest API -----------------------------------
function Get-AzCachedAccessToken()
{
    $ErrorActionPreference = 'Stop'
    if(-not (Get-Module Az.Accounts)) {
        Import-Module Az.Accounts
    }
    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    if(-not $azProfile.Accounts.Count) {
        Write-Error "Ensure you have logged in before calling this function."
    }
    $currentAzureContext = Get-AzContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azProfile)
    Write-Debug ("Getting access token for tenant" + $currentAzureContext.Tenant.TenantId)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Tenant.TenantId)
    #$token.AccessToken
    Return $token
}
function Get-AzBearerToken()
{
    $ErrorActionPreference = 'Stop'
    ('Bearer {0}' -f (Get-AzCachedAccessToken))
}
# ----- Inizio Programma ------------
write-host "Get Access Token"
$accesstoken = (Get-AzCachedAccessToken).AccessToken
$header = @{
  "Content-Type"  = "application\json"
  "Authorization" = "Bearer $accesstoken"
}

#---- Fine Codice per Rest API -----------------------------------

$subscriptionID= $StorageAccountResourceID.Split("/")[2]
$resourceGroupName  = $StorageAccountResourceID.Split("/")[4]
$storageAccountName= $StorageAccountResourceID.Split("/")[8]
$containerName = "immutable"

$BodyJson = '{
    "tags": [
    "CoC"
    ]
}' 

$uri = "https://management.azure.com/subscriptions/$subscriptionID/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName/blobServices/default/containers/$containerName/setLegalHold?api-version=2023-05-01"


$setLegalHoldPolicy = Invoke-WebRequest -Uri $Uri -Headers $Header -Method 'POST' -ContentType "application/json" -Body $BodyJson  -UseBasicParsing

Write-Output $setLegalHoldPolicy
Write-Host $setLegalHoldPolicy

# Set the correct time zone based on the location of the HRW

$regionTable = @{
    "eastus" = "Eastern Standard Time"
    "eastus2" = "Eastern Standard Time"
    "southcentralus" = "Central Standard Time"
    "westus2" = "Pacific Standard Time"
    "westus3" = "Pacific Standard Time"
    "australiaeast" = "AUS Eastern Standard Time"
    "southeastasia" = "Singapore Standard Time"
    "northeurope" = "W. Europe Standard Time"
    "swedencentral" = "W. Europe Standard Time"
    "uksouth" = "GMT Standard Time"
    "westeurope" = "W. Europe Standard Time"
    "centralus" = "Central Standard Time"
    "southafricanorth" = "South Africa Standard Time"
    "centralindia" = "India Standard Time"
    "eastasia" = "Tokyo Standard Time"
    "japaneast" = "Tokyo Standard Time"
    "koreacentral" = "Korea Standard Time"
    "canadacentral" = "Central Standard Time"
    "francecentral" = 	"W. Europe Standard Time"
    "germanywestcentral" = 	"W. Europe Standard Time"
    "norwayeast" = 	"W. Europe Standard Time"
    "switzerlandnorth" = 	"W. Europe Standard Time"
    "italynorth" = 	"W. Europe Standard Time"
    "uaenorth" = 	"Arabian Standard Time"
}

$timezoneName = $regionTable[$regionCode]
if ($timezoneName -eq $null) {
    Write-Host ("Region code {0} not found." -f $regionCode)
} else {
    Write-Host ("Setting time zone to {0}." -f $timezoneName)
    Set-TimeZone -Name $timezoneName
}

# Remove the Hybrid Runbook system identity from the Owner role assigned to the storage account
Start-Sleep -s 30
Remove-AzRoleAssignment -PrincipalId $HRWIdentity -Scope "/subscriptions/$subscriptionID/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$storageAccountName" -RoleDefinitionName "Owner"



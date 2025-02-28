param ([Parameter(Mandatory=$true)] $Log, $Type="file", $Output, $DcrImmutableId, $DceURI, $Table)
################
##### Usage
################
# LogGenerator.ps1
#   -Log <String>              - Log file to be forwarded
#   [-Type "file|API"]         - Whether the script should generate sample JSON file or send data via
#                                API call. Data will be written to a file by default.
#   [-Output <String>]         - Path to resulting JSON sample
#   [-DcrImmutableId <string>] - DCR immutable ID
#   [-DceURI]                  - Data collection endpoint URI
#   [-Table]                   - The name of the custom log table, including "_CL" suffix

####
# Information needed to authenticate to Azure Active Directory and obtain a bearer token
####

# Tenant ID in which the Data Collection Endpoint resides
$tenantId = $env:tenantId;

# The Entra ID application ID  (OAuth Client ID)
$appId = $env:appId; 

# The Entra ID application ID  (OAuth Client ID)
$appSecret = $env:appSecret 

$file_data = Get-Content $Log
if ("file" -eq $Type) {
    # If not provided, get output file name
    if ($null -eq $Output) {
        $Output = Read-Host "Enter output file name" 
    };

    # Form file payload
    $payload = @();
    $records_to_generate = [math]::min($file_data.count, 500)
    for ($i=0; $i -lt $records_to_generate; $i++) {
        $log_entry = @{
            Time = Get-Date ([datetime]::UtcNow) -Format O
            Application = "LogGenerator"
            RawData = $file_data[$i]
        }
        $payload += $log_entry
    }
    New-Item -Path $Output -ItemType "file" -Value ($payload | ConvertTo-Json -AsArray) -Force

} else {
    if ($null -eq $DcrImmutableId) {
        $DcrImmutableId = Read-Host "Enter DCR Immutable ID" 
    };

    if ($null -eq $DceURI) {
        $DceURI = Read-Host "Enter data collection endpoint URI" 
    }

    if ($null -eq $Table) {
        $Table = Read-Host "Enter the name of custom log table" 
    }

    $scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
    $body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
    $headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
    $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token

    $body = $file_data;
    Write-Host("Sending this body");
    #Write-Host($body);
    $headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
    $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2023-01-01";
    $uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers;

    Write-Host($uploadResponse)
    Write-Output "---------------------"

}

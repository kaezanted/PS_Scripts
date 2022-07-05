<#
.SYNOPSIS
.\Get-AADUser-Lastlogon.ps1
.DESCRIPTION 
PowerShell script to Export Users list based on last logon days specified at the execution.
.PARAMETER LastLogonDays
The Amount of days where users never logged on. 90 by Default
.PARAMETER $CSVFileName
To rename the CSV File export or Store in a Different location
.EXAMPLE
.\AzureAD_Inactive_Users.ps1 -LastLogonDays 60
.EXAMPLE
.\AzureAD_Inactive_Users.ps1 -LastLogonDays 90 -CSVFileName AzureAD_Last_Logon.csv
.EXAMPLE
.\AzureAD_Inactive_Users.ps1 -LastLogonDays 30 -CSVFileName C:\Temp\Inactive_Users.csv
#>

param(
    [Parameter( Mandatory=$false)]
    [int]$LastLogonDays="90",
    [Parameter( Mandatory=$false)]
    [string]$CSVFileName = "AADUsers_LastLogon.csv"
)

$ApplicationID    = "xxx"
$DirectoryID      = "xxx"
$ClientSecret     = "xxx"

$Body = @{    
Grant_Type    = "client_credentials"
Scope         = "https://graph.microsoft.com/.default"
client_Id     = $ApplicationID
Client_Secret = $ClientSecret
} 

$ConnectGraph = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$DirectoryID/oauth2/v2.0/token" -Method POST -Body $Body
$token = $ConnectGraph.access_token

$Days = (get-date).adddays(-$LastLogonDays)
$GraphDays = $Days.ToString("yyyy-MM-ddTHH:mm:ssZ")

$LoginUrl = "https://graph.microsoft.com/beta/users?filter=signInActivity/lastSignInDateTime le $GraphDays"
$ExpiredUsers = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($token)"} -Uri $LoginUrl -Method Get).value
$ExpiredUsers | FT DisplayName,Mail,id,userType,userPrincipalName,JobTitle,accountEnabled,department,companyName,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSyncEnabled,createdDateTime
$ExpiredUsers | Select-Object DisplayName,Mail,id,userType,userPrincipalName,JobTitle,accountEnabled,department,companyName,onPremisesDistinguishedName,onPremisesDomainName,onPremisesSyncEnabled,createdDateTime | Export-Csv $CSVFileName
$ExpiredUsers.count
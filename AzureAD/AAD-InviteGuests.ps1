<# Script to invite multiple guest users in a Microsoft AAD Tenant based on a CSV file and put them in some defined groups
Autor : Teddy.pokorski@tryade.fr 
Connection to AAD 
CSV Import
Send Invitation / Create the user
Add to groups  
#>
$date = Get-Date -Format "ddMMyyyy_HHmmss"
Start-Transcript -Path "C:\Temp\AAD-InviteGuest-Transcript_$date.txt"

# Setting Group ObjectID for adding guests to them, need to search them before running the script 
$eventsoft = "ObjectId-Eventsoft" #ObjectId "AAD-AAP-Eventsoft-R0"
$matrice = "ObjectId-Matrice" #get-azureadgroup -searchstring "AAD-AAP-Matrice"


# Loading Azure AD PowerShell Module and check if available
$azureADModule = Get-Module -Name "AzureAD" -ListAvailable
If ($null -eq $azureADModule) {
	$azureADModule = Get-Module -Name "AzureADPreview" -ListAvailable
}
If ($null -eq $azureADModule) {
	Write-Host ""
	Write-Host "The Azure AD (Preview) PowerShell Module IS NOT Installed" -ForegroundColor Red
	Write-Host ""
	Write-Host " => The Azure AD (Preview) PowerShell Module Can Be Installed From An Elevated PowerShell Command Prompt By Running Either" -ForegroundColor Red
	Write-Host "    - 'Install-Module AzureAD'" -ForegroundColor Red
	Write-Host "      OR" -ForegroundColor Red
	Write-Host "    - 'Install-Module AzureADPreview'" -ForegroundColor Red
	Write-Host ""
	Write-Host " => Aborting Script..." -ForegroundColor Red
	Write-Host ""

	BREAK
}
If ($azureADModule.count -gt 1) {
	$latestVersion = ($azureADModule | Select-Object version | Sort-Object)[-1]
	$azureADModule  = $azureADModule | Where-Object {$_.version -eq $latestVersion.version}
}
Import-Module $azureADModule


# Connecting To Azure AD Tenant
Write-Host "### Connecting To Azure AD Tenant..." -ForegroundColor Cyan
Write-Host ""
Try {
	Connect-AzureAD -ErrorAction Stop
} Catch {
	Write-Host "Connecting And Authenticating To The Azure AD Tenant Failed..." -ForegroundColor Red
	Write-Host ""
	Write-Host "    - Exception Type......: $($_.Exception.GetType().FullName)" -ForegroundColor Red
	Write-Host "    - Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
	Write-Host "    - Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
	Write-Host ""
	Write-Host " => Aborting Script..." -ForegroundColor Red
	Write-Host ""
	Write-Host ""

	BREAK
}


# Import CSV 
# 3 columns, delimiter ";"
#   Displayname = "Prenom Nom"
#   Guestmail = Adresse mail de l'invité
#   Group = Eventsoft OR Matrice OR 2     ## 2 = Les deux groupes
Write-Host ""
Write-Host "Importing the CSV file"
$CSV = import-csv -path "c:\Temp\CSV-Guests.csv" -Delimiter ";"


foreach ($guest in $CSV) {
# Create the invitation
Write-Host ""
Write-Host "Sending invitation to "$guest.Guestmail" ..."
Write-Host ""

New-AzureADMSInvitation `
    -InvitedUserEmailAddress $guest.Guestmail `
    -InvitedUserDisplayName $guest.displayName `
    -SendInvitationMessage $true `
    -redirecturl "https://myapps.microsoft.com/"

#Add user to groups objectid = groupe / refobjectid = user
Write-Host ""
Write-Host "Adding "$guest.displayname" to "$guest.group" ..."
$user = Get-AzureADUser -SearchString $guest.Guestmail
switch ($guest.group) {
    "Eventsoft" { 
        Add-azureadgroupmember -objectid $eventsoft `
            -refobjectid $user.objectid
            }
    "Matrice" {
        Add-azureadgroupmember -objectid $matrice `
            -refobjectid $user.objectid
            }
    "2" {
        Add-azureadgroupmember -objectid $eventsoft `
            -refobjectid $user.objectid
        Add-azureadgroupmember -objectid $azadgrpid `
            -refobjectid $user.objectid
        }

    Default {
        Write-Output "Aucun groupe pour $guest.displayname "
        }
    }
}
Stop-Transcript
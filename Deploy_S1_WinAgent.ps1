<#Voir la partie CHECK de la présence de l'agent 
 Get-WmiObject -class win32_product |where name -eq "Sentinel agent"
SELECT * FROM win32_product WHERE name = "Sentinel Agent"
#>

# Install SentinelOne via MSI
# --== Configuration ==-- #
###########################
Start-Transcript -Path "\\SRV\SentinelOne\Install_Logs\LOGS_$env:COMPUTERNAME.txt"

$S1_MSI = "\\SRV\SentinelOne\SentinelInstaller_windows_64bit_v21_7_5_1080.msi" # The source of the S1 MSI installer.
$SiteToken = "xxxxx" # Replace this with your site token

$Agent = Get-WmiObject -class win32_product | where name -eq "Sentinel agent"

if ($agent -eq $null) {
    
   Start-Process -FilePath $S1_MSI -ArgumentList "SITE_TOKEN=$($SiteToken)", "/QUIET", "/NORESTART" -Wait -Verbose
   echo "PArtage = $S1_MSI"
   echo "Token = $SiteToken"

   $drive = get-volume
       foreach ($item in $drive) {
          if ($item.DriveLetter -ne $null -and $item.Drivetype -ne "CD-ROM") {
             $letters = ($item.driveletter + ":")
            vssadmin Resize ShadowStorage /For=$letters /On=$letters /MaxSize=10%
       }
  }
}

Stop-Transcript
## Can force restart with "/FORCERESTART"

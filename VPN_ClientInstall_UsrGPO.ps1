# Script Install du client VPN SSL > GPO Utilisateur > execution a l ouverture de session
# Teddy.pokorski@tryade.fr

# Récupération du GUID de l'application
$Product = get-wmiobject Win32_Product | Where-object { $_.Name -match 'Stormshield SSL VPN Client'}
$Guid = $Product.IdentifyingNumber
$Version = $Product.Version
# Filtre des utilisateurs sur qui installer le client
$liste = @("Toto","babidi","boo")
#Liste des users de la machine
$profils = (gci "c:\users\").name

# Fichier log
$outfile = "\\server\VPN$\Log_users.csv"

# Clef Registre
$registrypath = "HKLM:\SOFTWARE\WOW6432Node\Stormshield SSL VPN"

if ( $Version -eq '3.0.1') {

        echo "Client SSL OK"

    } else {
        #Check si les utilisateurs cibles utilisent la machine
        $target = ($liste | ?{$profils -contains $_})

        if (($target =! $null) -and ($target.count -eq 1 )) {
            
            
        # Récupération du nom d'utilisateur
            $username = $target
            Write-Output "regedit"

                # Désinstallation de l'ancien VPN
                msiexec.exe /x $Guid /QN
                # Attente (peut-être à réduire)
                Start-Sleep -Seconds 30
                # Installation du nouveau VPN
                msiexec.exe /package "\\server\VPN$\Stormshield_SSLVPN_Client_3.0.1_win10_fr_x64.msi" /QN
        
                # Inscription des clefs registre
                Set-ItemProperty -Path $registrypath -Name config_dir -Value "C:\Users\$username\AppData\Local\Stormshield\Stormshield SSL VPN Client\config"
                Set-ItemProperty -Path $registrypath -Name log_dir -Value "C:\Users\$username\AppData\Local\Stormshield\Stormshield SSL VPN Client\log"
        
                Add-Content -Path $outfile -Value $username
                Remove-LocalGroupMember administrators -Member ("domain\" + $utilisateur) -Verbose 
        }
        elseif ($target.count -gt 1) {
            $date = get-date
            $Ordinateur = hostname
            Write-Output ("$date" + " | Poste =" + "$Ordinateur" + " | Users = " +[system.String]::Join("+", $liste))
            }
        }
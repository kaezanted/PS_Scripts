#Script ajout utilisateur admin local > GPO Ordinateur
# Teddy.pokorski@tryade.fr

# Récupération du GUID de l'application et de la version 
$Product = get-wmiobject Win32_Product | Where-object { $_.Name -match 'Stormshield SSL VPN Client'}
$Guid = $Product.IdentifyingNumber
$Version = $Product.Version
# Liste des utilisateurs 
$liste = @("Toto","babidi","boo")
#import-csv 
$profiles = (gci "c:\users\").name

# Fichier logs
$outfile = "\\server\VPN$\error_users.txt"

# Cle Registre
$registrypath = "HKLM:\SOFTWARE\WOW6432Node\Stormshield SSL VPN"


#Si la version est bonne : check du groupe administrateur local, si user présent > retrait , sinon rien
#Si la vesion n'est pas bonne : ajout de l'utilisateur dans le groupe administrateur local

$script:admin = ((Get-LocalGroupMember "administrators").name).split("\") | ?{$liste -contains $_}

if ($Version -eq '3.0.1') {

        echo "Client deja OK - Suppression du groupe"
        $utilisateur = $admin
        Remove-LocalGroupMember administrators -Member ("domain\" + $utilisateur) -Verbose 

    } else {

        if ($admin.count -eq 1) {

            Add-localgroupmember "administrateurs" -member ("domain\" + $utilisateur) -Verbose

        }else {
            Write-Output ("$date" + " | Poste =" + "$Ordinateur" + " | Users = " +[system.String]::Join("+", $liste)) >> $outfile
        }
    }
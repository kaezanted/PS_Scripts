#Script qui permet de récupérer / lister les différents logiciels permettant d'avoir un accès distant sur le poste
#Il se base sur une liste de logiciels déclarée dans la variable $soft_name, il faut essayer d'alimenter cette liste 
#lorsque des nouveaux logiciels sont découverts / mis à jour.

#Liste des différents soft de prise de main à distance
#La liste est composée des noms du soft/revendeur pour essayer de balayer plus large
$soft_name = "TermService" , "Windows Remote Desktop Service",
"Remote Administrator Service" , "Remote Administrator Service",
"TeamViewer5" , "Team Viewer V5",
"TeamViewer6" , "Team Viewer V6",
"TeamViewer7" , "Team Viewer V7",
"TeamViewer8" , "Team Viewer V8",
"TeamViewer9" , "Team Viewer V9",
"TeamViewer10" , "Team Viewer V10",
"TeamViewer11" , "Team Viewer V11",
"TeamViewer12" , "Team Viewer V12",
"TeamViewer13" , "Team Viewer V13",
"TeamViewer14" , "Team Viewer V14",
"TeamViewer15" , "Team Viewer V15",
"TeamViewer" , "Team Viewer",
"uvnc_service" , "Ultra VNC",
"vncserver" , "Real VNC",
"tvnserver" , "Tight VNC",
"TigerVNC" , "Tiger VNC",
"AmmyyAdmin" , "Ammyy Admin",
"LMIGuardianSvc" , "LogMeIn Rescue",
"LogMeIn" , "LogMeIn",
"icas" , "iTALC",
"AnyDesk" , "AnyDesk",
"BASupportExpressStandaloneService_Dameware" , "Dameware Remote Everywhere",
"dwmrcs" , "DameWare Mini Remote Control",
"sshd" , "OpenSSH SSH Server",
"DNTUS26" , "DameWare Remote Support 2.6",
"WebexService" , "Cisco WebEx",
"GoToAssist", "GoToAssist Remote Support Customer",
"LANdesk", "LTA", "LDClient",
"BeAnywhere",
"Cendio", "Cendio Thinlinc"

#Récupération des chemins dans le disque C: contenant les potentiels programmes installés
#Peut-être faut il voir pour ajouter une variable récupérant l'ensemble des disques au lieu du C:
$soft_path = ( `
            get-childitem -Path "c:\" | `
            Where name -like "Program*" `
            ).fullname

foreach ($item in $soft_name) {

    foreach ($path in $soft_path) {
        #Check des dossiers d'install dans le disque
        get-childitem -path $path |`
            Where name -like "$item*" |`
            Select name

        #Check des dossiers d'install dans le disque (autre chemin)
        get-childitem -path $path | `
            Where name -like "$item*" |`
            Select name
        }

    #Check des services
    get-service |`
        Where name -like "$item*"

    #Check des soft dans les informations WMI de l'OS
    get-wmiobject -class win32_product |`
        Where vendor -like "$item*" |`
        Select Name, Vendor, Caption

    #Check du registre pour trouver les traces des softs ayant indiqué un chemin de désinstallation
    #Ruche : Local Machine >
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |`
        Where displayname -like "$soft_name*" |`
        Select-Object DisplayName, Publisher |`
        Format-Table -AutoSize

    #Check du registre pour trouver les traces des softs ayant indiqué un chemin de désinstallation dans une autre ruche
    #Ruche Current User >
    Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |`
        Where displayname -like "$soft_name*" |`
        Select-Object DisplayName, Publisher |`
        Format-Table -AutoSize

}


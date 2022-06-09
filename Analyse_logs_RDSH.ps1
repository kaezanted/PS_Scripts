<#
Nouveau script pour rÃ©cupÃ©rer les logs sur les Hotes de session.
De nombreuses amÃ©liorations peuvent Ãªtre faites, le script a ete redige relativement rapidement.
Auteur : Teddy.pokorski@tryade.fr

Sources :
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1
http://woshub.com/rdp-connection-logs-forensics-windows/
#>

<#Algo
    1- Récupération des variables (Liste serveur et date du jour fix à 00h00)

    2- Boucle foreach srv dans la liste
        Recup des logs du session manager avec les ID correspondants aux event des sessions utilisateur

        Creation d un tableau et traitement de chaque event pour faciliter la comprehension dans l output final
    
    3- Recuperation de l'event en XML 
        Generation des colonnes du tableau en fonction des informations qui nous interesse dans l event
            Utilisateur, sessionID, IP, date, ...

    4- Generation du fichier a partir du tableau en trian les event par date 
#>

$Date_log = (get-date -Hour 0 -Minute 0)
$RDSH_list = @("T1" ; "T2" ; "T3" ; "T4" ; "T5" ; "T6" ; "T7" ; "T8")

#Pour chaque Hote de session, nous venons rÃ©cupÃ©rer les logs du session manager RDS
#Chaque eventID correspond Ã  un type d'event particulier
#Nous rÃ©cupÃ©rons uniquement les logs de la journÃ©e en cours

foreach ($server in $RDSH_list)
{
    $Events = Get-WinEvent `
        -computername $server `
        -FilterHashtable @{Logname = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" ; ID = 21,24,25,39,40 ; StartTime = $date_log}

    $ArrayList = New-Object System.Collections.ArrayList
    Foreach ($Event in $Events)
    {
        if ($event.Id -eq "21")
                    {
                        $activity = "21 : Session ouverte"
                    }
        if ($event.Id -eq "24")
                    {
                        $activity = "24 : Session deconnectee (fermee par l utilisateur)"
                    }
        if ($event.id -eq "25")
                    {
                        $activity = "25 : Reconnexion a une session existante"
                    }
        if ($event.id -eq "39")
                    {
                        $activity = "39 : Utilisateur deconnecte"
                    }
        if ($event.id -eq "40")
                    {
                  #Point a traiter a posteriori > code 0 / 5 / 11 a trier > dans la partie XML
                        $activity = "40 : Session deconnectee pour une raison particuliere"
                    }

#Ici nous venons rÃ©cupÃ©rer les informations de l'event et allons gÃ©nÃ©rer les colonnes du fichier CSV de sortie
#Je me base sur la partie XML de l event pour recuperer des infos particulieres qui sont trop compliquees a aller chercher dans le corps du message de l event
        [xml]$Xml = $Event.ToXml()
        $Row = "" | Select Username,SessionID,TimeCreated,IPAddress,id,Reason
        $Row.Username = $Xml.Event.UserData.EventXML.User
        $Row.SessionID = $Xml.Event.UserData.EventXML.SessionID
        if ($Xml.Event.UserData.EventXML.SessionID -eq $null)
            {
                $Row.SessionID = $Xml.Event.UserData.EventXML.Session
            }
        $Row.TimeCreated = $Event.TimeCreated.ToString()
        $Row.IPAddress = $Xml.Event.UserData.EventXML.Address
        $Row.ID = $activity
        switch ($Xml.Event.UserData.EventXML.Reason) 
            {
                $null {$event40 = " "}
                0 {$Event40 = "Erreur ou Fenetre RDP fermee par l utilisateur"}
                5 {$Event40 = "L utilisateur s est reconnecte a une session RDP deja ouverte"}
                11 {$Event40 = "L utilisateur a clique sur deconnecter"}
            }
        $Row.Reason = $Event40
        [void]$ArrayList.Add($Row)
    }

    $Date = (Get-Date -Format "dd-MM-yyyy")
    $filepath = "C:\script\Analyse_Logs_RDSH\" + $server + "_Session du " + $Date + ".csv"

    $ArrayList | Sort TimeCreated | Export-Csv $FilePath -NoTypeInformation -Delimiter ";"

    Write-host "Writing File: $FilePath" -ForegroundColor Cyan
    Write-host "Done!" -ForegroundColor Cyan
}

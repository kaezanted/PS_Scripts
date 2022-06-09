### Script Header ###
###
### Pour l utilisation du script :
### Extraire le dossier sur le poste, 
###     le dossier est constitué du script principal en .rename à renommer en .PS1 si besoin
###     Un fichier CSV cita.csv pour une fonction spéciale
###     Un sous dossier "Questions" contenant les fichiers CSV des questionnaires
###     Du fichier readme.txt
###
### Auteur : Teddy Pokorski
###
### Version 1.0 (10/01/2020), work in progress : 
###     Error import fichier csv popup > rustine, le type d'objet récupéré pour la table n'était pas pris en charge (pwsh version ?)


###algo
<# Start

Fonction selection aleatoire du fichier de question au départ

menu principal avec switch
    Selection du fichier question a importer (fonction import)
    Lancer la partie (fonction play)
    Selection 1 ou 2 joueurs/equipe > par défaut 2 équipes (fonction nmbr)
    Quitter (fonction leave)
    Si pas de choix > fonction lol qui tire au hasard une réplique et > fonction menu

fonction import du fichier question format csv ?
    format question ; réponse
    Popup d'une fenetre de selection de fichier Windows mais erreur lors de l'éxecution
    Import du fichier en CLI manuel a partir d'un gci

fonction play 
    Import du CSV dans une table 
    Etablissement des variables de base (score, tour ...)
    boucle qui tire les questions aléatoirement (get-random sur une ligne) , un count est fait sur le nmbr de ligne dans la table
    modulo du tour 
    Si tour impair > equipe 1 
    Si tour pair > equipe 2

    question $question
    press
    réponse à la question $answer

    read-host y/n
    Si réponse ok : point pour le joueur en cours
    sinon "bouuh"
    read-host pour retirer la question y/n
    Si oui : la question est retirée de la boucle 
    Si non : fonction ASCII, i'll be back et la question reste dans la table'
   
    Affichage des scores, ... 


fonction select du nmbr de joueurs
    A terminer

fonction leave
    Exit

End #>

#################################################################################

mode 250
Write-Host " Bonjour, je vous conseille d'agrandir la fenetre en fullscreen ! Good luck and Have fun ! "
Wait-Event -Timeout 3

[string]$tick = "====================================="
[string]$csv_path = ($PSScriptRoot + "\Questions\")
[int32]$nombre = "2" 

#Fonction selection aléatoire d'un fichier questionnaire au cas où la personne n'en choisit pas
#Il faut donc appeler la fonction au départ et utiliser $select 
function Selection
{
    [int32]$count = (gci $csv_path |select name).count 
    [int32]$random = Get-Random -maximum $count
    $script:rustine = (gci $csv_path | select name | Select -Index $random).name
}



#Import de fichier 
#Probleme avec la fonction popup... work in progress 
function import
{
    Add-Type -AssemblyName System.Windows.Forms
    $popup = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
    InitialDirectory = [Environment]::GetFolderPath("Desktop") 
    Filter = 'CSV (*.csv)|*.csv'
    Title = "Sélectionnez le questionnaire CSV"
    Multiselect = $false
    }
    $null = $popup.ShowDialog()
    $script:Select = $popup.filenames
    $script:rustine = (echo $select) #Rustine degueulasse pour fix mon incident de popup non pris en charge dans l'environnement d execution ps

    ###Si la popup ne fonctionne pas correctement : commenter les lignes au dessus et decommenter celle en dessous

    #gci $csv_path
    #Write-Host $tick
    #$script:select = Read-Host "Selectionnez le fichier en question en entrant son nom exact"

    Menu
}



#Play Coeur du script
#Voir pour intégrer plusieurs fichiers et les ajouter les uns aux autres à la table
function play
{
    Clear-Host
    #import du fichier questionnaire dans une table et remise du score à 0
    [System.Collections.ArrayList]$script:table = import-csv $rustine -Delimiter ";" -Encoding UTF8
    [int32]$script:score1 = "0"
    [int32]$script:score2 = "0"
    [int32]$script:tour = "1"


    $script:score_1 = New-Object -TypeName PSobject -Property @{
                    Equipe = "Equipe 1"
                    Score = $score1
                    }
    $script:score_2 = New-Object -TypeName PSobject -Property @{
                    Equipe = "Equipe 2"
                    Score = $score2
                    }


    Write-Host "###################################################"
    Write-Host "# Le sujet du questionnaire est :" (($rustine.Split("\") | select -Last 1).split(".")[0]) 
    Write-Host "###################################################"
    Wait-Event -Timeout 2

    do
        {
                #On définit le nmbr de lignes dans la table pour le décompte, si une question est supprimée,
                # le fait de placer le count dans la boucle fait que le count diminue en même temps que la suppression
            [int32]$table_count = $table.count 
            if ($table_count -eq "0")
            {
                [int32]$table_random = "0"
            }
            else
            {
                #on génère un nombre random entre 0 et le nombre maximum de ligne dans la table 
                [int32]$table_random = Get-Random -maximum $table_count -ErrorAction SilentlyContinue
            }

            $modul_tour = ($tour %2)
            if ($modul_tour -eq "1")
            {
                Write-Host "Tour de l'équipe 1"
            }
            Else
            {
                Write-Host "Tour de l'équipe 2"
            }
            Wait-event -timeout 2


            #Bloc Affichage de la Question + réponse random
            Clear-Host
            Write-Host $tick
            Write-Host "Question :"
            Write-Host " "
            Write-Host ($table[($table_random)]).Question
            Write-Host " "
            Write-host $tick
            Read-Host "Appuyez sur entrée pour afficher la réponse"

            Write-Host $tick
            Write-Host "Réponse :"
            Write-Host " "
            Write-Host ($table[($table_random)]).Reponse
            Write-Host " "
            Write-host $tick
            Write-Host " "


            #La réponse correcte ? 
            do
                {
                $point = Read-Host "Votre réponse est-elle correcte ? o/n"
                }
            until (($point -eq "o") -or ($point -eq "n"))


            switch ($point)
                {
                    #Réponse juste +1 point
                    o
                    {
                        $modul_tour = ($tour %2)
                        if ($modul_tour -eq "1")
                        {
                            [int32]$script:score1 = ($score1 + "1")
                            Write-Host "=========> Tiens voilà un cookie !"
                            Write-Host " "
                        }
                        Else
                        {
                            [int32]$script:score2 = ($score2 + "1")
                            Write-Host "=========> Tiens voilà un cookie !"
                            Write-Host " "
                        }


                    }

                    #Réponse fausse pas de point
                    n
                    {
                    Write-Host " "
                    Write-Host "Bouuuuuuuuuh ! Shame on you !"
                    }
                }
            
            #Bloc suppression des questions
            do
                {
                Write-Host " "
                $remove = Read-Host "Voulez vous supprimer la question du pool ? o/n"
                }
            until (($remove -eq "o") -or ($remove -eq "n"))

            switch ($remove)
                {
                    #Si oui alors on remove
                    o
                        {
                            $table.Remove(($table[$table_random]))
                        }

                    #Non alors la question peut revenir
                    n
                        {
                            Write-Host -ForegroundColor DarkYellow "                        ______ "
                            Write-Host -ForegroundColor DarkYellow "                     <((((((\\\ "
                            Write-Host -ForegroundColor DarkYellow "                     /      . }\          "
                            Write-Host -ForegroundColor DarkYellow "                     ;--..--._|} "
                            Write-Host -ForegroundColor DarkYellow "  (\                 '--/\--'  ) "
                            Write-Host -ForegroundColor DarkYellow "   \\                | '-'  :'| "
                            Write-Host -ForegroundColor DarkYellow "    \\               . -==- .-| "
                            Write-Host -ForegroundColor DarkYellow "     \\               \.__.'   \--._ "
                            Write-Host -ForegroundColor DarkYellow "     [\\          __.--|       //  _/'--."
                            Write-Host -ForegroundColor DarkYellow "     \ \\       .'-._ ('-----'/ __/      \ "
                            Write-Host -ForegroundColor DarkYellow "      \ \\     /   __>|      | '--.       | "
                            Write-Host -ForegroundColor DarkYellow "       \ \\   |   \   |     /    /       / "
                            Write-Host -ForegroundColor DarkYellow "        \ '\ /     \  |     |  _/       / "
                            Write-Host -ForegroundColor DarkYellow "         \  \       \ |     | /        / "
                            Write-Host -ForegroundColor DarkYellow "          \  \       \       / "
                            Write-Host -ForegroundColor DarkYellow "    "
                            Write-Host -ForegroundColor DarkYellow "      ::::::::::: ::: :::        :::           :::::::::  ::::::::::          :::::::::      :::      ::::::::  :::    :::          ::: "
                            Write-Host -ForegroundColor DarkYellow "         :+:     :+  :+:        :+:           :+:    :+: :+:                 :+:    :+:   :+: :+:   :+:    :+: :+:   :+:           :+:  "
                            Write-Host -ForegroundColor DarkYellow "        +:+         +:+        +:+           +:+    +:+ +:+                 +:+    +:+  +:+   +:+  +:+        +:+  +:+            +:+   "
                            Write-Host -ForegroundColor DarkYellow "       +#+         +#+        +#+           +#++:++#+  +#++:++#            +#++:++#+  +#++:++#++: +#+        +#++:++             +#+    "
                            Write-Host -ForegroundColor DarkYellow "      +#+         +#+        +#+           +#+    +#+ +#+                 +#+    +#+ +#+     +#+ +#+        +#+  +#+            +#+     "
                            Write-Host -ForegroundColor DarkYellow "     #+#         #+#        #+#           #+#    #+# #+#                 #+#    #+# #+#     #+# #+#    #+# #+#   #+#                    "
                            Write-Host -ForegroundColor DarkYellow "###########     ########## ##########    #########  ##########          #########  ###     ###  ########  ###    ###          ###       "

                            Wait-Event -Timeout 3
                        }

                }



                #Affichage du nombre de questions restantes
            Clear-Host
            Write-Host " Il reste $table_count question(s) ..."
            Write-Host " "
            Write-Host "###########################"
            Write-Host "# Score actuel de l'équipe 1 : $score1"
            Write-Host "# Score actuel de l'équipe 2 : $score2"
            Write-Host "###########################"
            Write-Host " "
            [int32]$tour = ($tour + "1")
            Wait-Event -Timeout 2  

        }
    until ($table_count -eq 0)
      


     Write-Host "Le questionnaire est terminé, GG WP !"


     #Bloc affichage des scores et sort dans l'ordre décroissant + gagnant = 1e ligne  

     Clear-Host
     Write-Host "########################"
     Write-Host "# Tableau des Scores : #"
     Write-Host "########################"
     Write-Host "# "$score_1.equipe " : " $score_1.Score
     Write-host "# "$Score_2.Equipe " : " $Score_2.Score
     Write-Host "########################"

     if ($score_1.score -eq $score_2.Score)
     {
        Write-Host "Match nul ... Du coup le formateur gagne des croissants !"
     }
     Elseif($score_1.Score -gt $score_2.Score)
     {
         Write-Host "Le gagnant est : " $score_1.Equipe
         Write-Host $score_2.Equipe ", ça sent les croissants dans le coin ... ?!"
     }
     else
     {
        Write-Host "Le gagnant est : " $score_2.Equipe
        Write-Host "Hey, " $score_1.Equipe ", ça sent les croissants dans le coin ... ?!"
     }

     Wait-event -Timeout 7
     Menu
}



#nmbr changement du nombre d equipe work in progress
function nmbr
{
    
    Menu
}



#Aleatoire
function lol
{
   
    $citation = Import-Csv ($PSScriptRoot + "\cita.csv") -Delimiter ";" -Encoding UTF8
    [int32]$citation_random = Get-Random -maximum ($citation.replique.count) -ErrorAction SilentlyContinue

    Write-Host -ForegroundColor DarkYellow "                     ___________________________________"
    Write-Host -ForegroundColor DarkYellow "                    /                                   "
    Write-Host -ForegroundColor DarkYellow "                   /" ($citation[($citation_random)]).Replique
    Write-Host -ForegroundColor DarkYellow "         .---.    /___________________________________ "
    Write-Host -ForegroundColor DarkYellow "       .'_:___`. //"
    Write-Host -ForegroundColor DarkYellow "       |__ --==|'  "
    Write-Host -ForegroundColor DarkYellow "       [  ]  :[|   "
    Write-Host -ForegroundColor DarkYellow "       |__| I=[|   "
    Write-Host -ForegroundColor DarkYellow "       / / ____|   " 
    Write-Host -ForegroundColor DarkYellow "      |-/.____.'   " 
    Write-Host -ForegroundColor DarkYellow "@snd /___\ /___\   "
    Write-Host -ForegroundColor DarkYellow " "  
    Wait-Event -Timeout 3
   Menu
} 


#Menu
function Menu 
{
    Wait-Event -Timeout 1
    Clear-Host

    Write-host -ForegroundColor Green "  ____   __     __    __   ___   ____  __ __  ____ ____ "
    Write-host -ForegroundColor Green "  || \\ (( \    ||    ||  // \\  || \\ || // ||    || \\"
    Write-host -ForegroundColor Green "  ||_//  \\     \\ /\ // ((   )) ||_// ||<<  ||==  ||_//"
    Write-host -ForegroundColor Green "  ||    \_))     \V/\V/   \\_//  || \\ || \\ ||___ || \\"
    Write-host -ForegroundColor Green " "
    Write-host -ForegroundColor Green "#                                     -.- .- . --.. .- -."


    Write-Host " "    
    Write-host "###########################################################"
    Write-Host "# Menu :                                                  #"
    Write-Host "#-------                                                  #"
    Write-Host "#                                                         #"
    Write-Host "# 1 - Choix d'un fichier questionnaire (Aleatoire sinon)  #"
    Write-Host "# 2 - Lancement de la partie !                            #"
    Write-Host "# 3 - Modification du nombre d equipe, 2 par défaut.      #"
    Write-Host "# 4 - Abandonner lachement et quitter !                   #"
    Write-Host "# 5 - Il n'y a pas de cinquième choix..                   #"
    Write-Host "#                                                         #"                 
    write-host "###########################################################"
    Write-Host " "

    $choix = read-host "Il faut faire un choix camarade ! (1/2/3/4/5)"

    switch ($choix)
    {
        #Choix 1 - Import du fichier 
        1
            {
            Echo "Vous allez choisir un fichier questionnaire."
            import
            }

        #Choix 2 - Lancement de la partie
        2
            {
            Echo "Lancement de la partie !"
            play
            }

        #Choix 3 - Modif du nombre de players (2 par défaut)
        3
            {
            Echo "Modification du nombre de joueur."
            nmbr
            }

        #Choix 4 - Leave
        4
            {
            Clear-Host
            Echo "May the force be with you !"
            Wait-Event 1
            Exit
            }

        #Choix 5 - ??
        5
            {
            Echo "Mais il y a un 5eme élément... [badum tss !]"
            Wait-Event -Timeout 2
            Echo "Il faut que ce soit green OK ? Green green greeeeeeeen ! "
            Wait-Event -Timeout 2
            Menu
            }

        #Easteregg
        Default
            {
            Echo "T'en as trop pris gros !!"
            Wait-Event -Timeout 1 
            lol
            }
    }

}

Selection
Menu
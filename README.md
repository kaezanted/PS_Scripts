### READ ME ###

###	Le but du script est de pouvoir réviser sur un format quizz, par défaut le jeu est pensé pour fonctionner en binôme (ou 2 équipes)
###	Chaque tour, une équipe doit répondre à la question posée, si la réponse est bonne alors vous gagnez un bon point (félicitations)
###	Si la réponse est mauvaise ... vous ne marquez pas de point (boooooo)
###	Enfin vous pouvez décider de garder la question dans le pool si vous voulez pouvoir retomber dessus, ou la retirer.

### Libre à vous de modifier le script, ...
### Auteur : Kaezan
###
### Work on Powershell :
###	6 ok
###	5.1 ok
###	5 ok
###	4 not tested (function import popup ? function import aleatoire ? - $psscriptroot ?)
###	3 ??
###	2 nok

### Pour l utilisation du script :
### Extraire le dossier sur le poste, 
###     le dossier est constitué du script principal en .PS1
###     Un fichier CSV cita.csv pour une fonction spéciale à agrémenter celon votre bon plaisir
###     Un sous dossier contenant les fichiers CSV des questionnaires, libre à vous de les modifier, en ajouter, ... (Désolé pour les possibles erreurs qui s'y glissent)
###
###	Lors du lancement, selectionnez dans le menu la touche 1 pour choisir votre questionnaire
###	Apres ça, vous pouvez lancer votre partie.
###
###	Il est possible qu'une erreur est lieue lors de l'import du fichier via la popup windows, c'est lié à la version de PS du poste
###	si c'est le cas il faut modifier la function import : commenter les lignes superieurs et decommenter les inferieurs
###
###	Les questions sont stockées dans des fichiers CSV avec ";" comme délimiteur.

### Algo
<# Start

Fonction automatique de selection aleatoire du fichier de question au start

menu principal avec switch
    Selection du fichier question a importer (fonction import)
    Lancer la partie (fonction play)
    Selection 1 ou 2 joueurs/equipe > par défaut 2 équipes (fonction nmbr)
    Quitter (fonction leave)
    Si pas de choix > fonction lol qui tire au hasard une réplique et > fonction menu

fonction import du fichier question format csv ?
    format question ; réponse
    Popup d'une fenetre de selection de fichier Windows et utilisation du path
    Si error modif du script >> Import du fichier en CLI manuel a partir d'un gci

fonction play 
    Import du CSV dans une table 
    Etablissement des variables de base (score, tour ...)
    boucle qui tire les questions aléatoirement (get-random sur une ligne) , un count est fait sur le nmbr de ligne dans la table
    modulo du tour 
    Si tour impair > equipe 1 
    Si tour pair > equipe 2
    question $question
    press input
    réponse à la question $answer
    read-host y/n
    Si réponse ok : point pour le joueur en cours
    sinon "bouuh"
    read-host pour retirer la question y/n
    Si oui : la question est retirée de la boucle 
    Si non : fonction ASCII art, i'll be back et la question reste dans la table'
    Affichage des scores, ... 

fonction select du nmbr de joueurs
    A terminer

fonction leave
    Exit
End #>

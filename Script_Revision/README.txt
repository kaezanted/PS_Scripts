### READ ME ###
###
### Libre � vous de modifier le script, ...
###
### Auteur : Kaezan
###
### Work on Powershell :
###	6 ok
###	5.1 ok
###	5 ok
###	4 not tested (function import popup ? function import aleatoire ? - $psscriptroot ?)
###	3 ??
###	2 nok
###
### Pour l utilisation du script :
### Extraire le dossier sur le poste, 
###     le dossier est constitu� du script principal en .rename � renommer en .PS1
###     Un fichier CSV cita.csv pour une fonction sp�ciale � agr�menter celon votre bon plaisir
###     Un sous dossier contenant les fichiers CSV des questionnaires, libre � vous de les modifier, en ajouter, ...
###
###	Lors du lancement, selectionnez dans le menu la touche 1 pour choisir votre questionnaire
###	Apres �a, vous pouvez lancer votre partie.
###
###	Il est possible qu'une erreur est lieue lors de l'import du fichier via la popup windows, c'est li� � la version PS
###	si c'est le cas il faut modifier la function import : commenter les lignes superieurs et decommenter les inferieurs
###
###	Le but du script est de pouvoir r�viser sur un format quizz, par d�faut le jeu est pens� pour fonctionner en bin�me (ou 2 �quipes)
###	Chaque tour, une �quipe doit r�pondre � la question pos�e, si la r�ponse est bonne alors vous gagnez un bon point (f�licitations)
###	Si la r�ponse est mauvaise ... vous ne marquez pas de point (boooooo)
###	Enfin vous pouvez d�cider de garder la question dans le pool si vous voulez pouvoir retomber dessus, ou la retirer.
###
###	Les questions sont stock�es dans des fichiers CSV avec ";" comme d�limiteur.

### Algo
<# Start

Fonction automatique de selection aleatoire du fichier de question au start

menu principal avec switch
    Selection du fichier question a importer (fonction import)
    Lancer la partie (fonction play)
    Selection 1 ou 2 joueurs/equipe > par d�faut 2 �quipes (fonction nmbr)
    Quitter (fonction leave)
    Si pas de choix > fonction lol qui tire au hasard une r�plique et > fonction menu

fonction import du fichier question format csv ?
    format question ; r�ponse
    Popup d'une fenetre de selection de fichier Windows et utilisation du path
    Si error modif du script >> Import du fichier en CLI manuel a partir d'un gci

fonction play 
    Import du CSV dans une table 
    Etablissement des variables de base (score, tour ...)
    boucle qui tire les questions al�atoirement (get-random sur une ligne) , un count est fait sur le nmbr de ligne dans la table
    modulo du tour 
    Si tour impair > equipe 1 
    Si tour pair > equipe 2

    question $question
    press
    r�ponse � la question $answer

    read-host y/n
    Si r�ponse ok : point pour le joueur en cours
    sinon "bouuh"
    read-host pour retirer la question y/n
    Si oui : la question est retir�e de la boucle 
    Si non : fonction ASCII art, i'll be back et la question reste dans la table'
   
    Affichage des scores, ... 


fonction select du nmbr de joueurs
    A terminer

fonction leave
    Exit

End #>

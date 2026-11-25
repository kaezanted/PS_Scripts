<#
.SYNOPSIS
    Socle Almeria de durcissement et de journalisation - postes Windows 11 Pro (25H2, 26H1, 26H2).

.DESCRIPTION
    Script autonome (catalogue embarque), concu pour etre pousse par le RMM RG System en SYSTEM 64 bits.
    Version 0.6.0 - candidat au pilote. Modes :
      Audit      (defaut) etat effectif, autorite (GPO/MDM/Entra/ConfigMgr), ecarts ; cliche d'etat. Aucune ecriture de securite.
      Plan       changements eligibles, sauts, prerequis, redemarrages ; plan horodate et empreinte SHA-256.
      Apply      rejoue les precontroles, exige le plan approuve identique, sauvegarde, ecrit, relit.
      Verify     etat effectif apres application, preuves d'evenements generes localement.
      Rollback   restauration d'une transaction (ou retour a l'origine / a un cliche, par controle).
      Deploy     DEPLOIEMENT INITIAL (sequence de taches MDT) : plan calcule et applique dans la foulee, sans
                 approbation separee. Refuse hors sequence de taches, sur un systeme installe depuis plus de
                 -MaxOsAgeHours, ou si le socle a deja ete applique hors deploiement. A placer en DERNIERE etape.
      Diagnostic n'ecrit RIEN : affiche le contexte d'execution reel (identite, 64 bits, ligne de commande,
                 politiques d'execution, parametres recus) pour valider l'integration RG.
    Machine jointe a un domaine, a Entra ID, inscrite MDM ou geree par ConfigMgr : audit uniquement, sauf
    -LocalException sur les controles sans autorite concurrente.
    Aucune connexion reseau, aucun telechargement, aucun redemarrage, aucun arret de service, aucun gpupdate.

.PARAMETER Mode
    Audit | Plan | Apply | Verify | Rollback | Diagnostic | Deploy (postes, sequence MDT)
.PARAMETER ClientCode
    Libelle client repris dans le rapport (facultatif, sans effet sur le comportement).
.PARAMETER EnableOptions
    Controles de categorie Option a activer, separes par des virgules (jokers acceptes : "ALM-NET-09*").
.PARAMETER DisableControls
    Controles du socle a ne pas appliquer sur cette machine (derogation), separes par des virgules.
.PARAMETER OverrideExisting
    Controles marques "Respect" dont une valeur locale plus faible peut etre remplacee (decision explicite).
.PARAMETER LocalException
    Machine geree : seuls ces controles peuvent etre ecrits localement, et seulement sans autorite concurrente.
.PARAMETER BypassAuthority
    Machine geree (domaine, Entra, MDM, ConfigMgr) : autorise l'ecriture sans -LocalException et ecrit aussi les
    reglages dont l'autorite est inconnue (le script ne sait pas lire ce que pilote un MDM). Les reglages geres par
    une GPO detectee ne sont jamais modifies (la GPO les reecrirait). A utiliser en connaissance de cause ; trace dans
    le rapport. Sans effet sur les refus absolus (controleur de domaine, role serveur sensible).
.PARAMETER AllowOutOfSupportBuild
    Autorise Plan/Apply sur une version hors cycle de support (decision tracee dans le rapport).
.PARAMETER ApproveStoredPlan
    Apply : approuve le dernier plan enregistre si son empreinte est identique au plan recalcule.
.PARAMETER ApprovedPlanHash
    Apply : empreinte (ou 16 premiers caracteres) du plan valide.
.PARAMETER MaxPlanAgeHours
    Age maximal du plan approuve (defaut 168 h).
.PARAMETER MaxOsAgeHours
    Deploy : age maximal du systeme (date d'installation) pour accepter le mode Deploy (defaut 72 h).
.PARAMETER ResumeTransactionId
    Apply : reprise d'une transaction interrompue.
.PARAMETER TransactionId
    Rollback : transaction a annuler.
.PARAMETER ToOrigin
    Rollback : retour a l'etat d'origine (avant toute transaction Almeria) pour les controles -ControlId.
.PARAMETER SnapshotId
    Rollback : retour aux valeurs d'un cliche d'audit pour -ControlId (transition apres retrait d'une GPO).
.PARAMETER ControlId
    Filtre d'identifiants (jokers acceptes, virgules), requis avec -ToOrigin / -SnapshotId.
.PARAMETER GenerateTestEvents
    Verify : genere des evenements de test sans risque (4688, 4698/4699, 4625). Prevenir le SOC.
.PARAMETER MaxDurationSeconds
    Duree maximale (60-3600 s, defaut 300). Arret propre avant la limite. Rester sous le delai RG.
.PARAMETER DiagOutputLines
    Diagnostic : nombre de lignes de remplissage a emettre (test de la capture de sortie RG).
.PARAMETER DiagSleepSeconds
    Diagnostic : attente avant la fin (test du delai RG).
.PARAMETER DiagExitCode
    Diagnostic : code retour a renvoyer (test de la remontee des codes dans RG).

.NOTES
    Codes retour : 0 OK, 1 ecart, 2 saut protege, 3 echec partiel, 4 restauration incomplete, 5 erreur, 6 verrou, 7 delai.
    Cible : Windows PowerShell 5.1 64 bits, SYSTEM ou administrateur local. Fichier ASCII.
    Pour un serveur : Invoke-ServerBaseline.ps1.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Plan', 'Apply', 'Verify', 'Rollback', 'Diagnostic', 'Deploy')][string]$Mode = 'Audit',
    [string]$ClientCode,
    [string[]]$EnableOptions,
    [string[]]$DisableControls,
    [string[]]$OverrideExisting,
    [string[]]$LocalException,
    [switch]$BypassAuthority,
    [switch]$AllowOutOfSupportBuild,
    [switch]$ApproveStoredPlan,
    [string]$ApprovedPlanHash,
    [ValidateRange(1, 2160)][int]$MaxPlanAgeHours = 168,
    [ValidateRange(1, 720)][int]$MaxOsAgeHours = 72,
    [string]$ResumeTransactionId,
    [string]$TransactionId,
    [switch]$ToOrigin,
    [string]$SnapshotId,
    [string[]]$ControlId,
    [switch]$GenerateTestEvents,
    [ValidateRange(60, 3600)][int]$MaxDurationSeconds = 300,
    [ValidateRange(0, 20000)][int]$DiagOutputLines = 0,
    [ValidateRange(0, 3600)][int]$DiagSleepSeconds = 0,
    [ValidateRange(0, 255)][int]$DiagExitCode = 0
)

#region ALM-EMBED - outil 0.6.0, catalogue 0.6.0 (272 controles), assemble le 25/11/2026 10:36. Ne pas modifier a la main.
$script:ALM_CatalogJson = @'
{"CatalogVersion":"0.6.0","Status":"Candidat au pilote - non valide en laboratoire","Profile":"Workstation","Supported":{"Workstation":{"EditionsAccepted":["Professional","ProfessionalWorkstation","ProfessionalEducation","Enterprise","Education"],"Builds":[{"Build":26200,"Version":"25H2"},{"Build":26300,"Version":"26H2"},{"Build":28000,"Version":"26H1"}],"OutOfSupport":[{"Build":26100,"Version":"24H2","EndOfServicingPro":"2026-10-13"}]},"Server":{"EditionsAccepted":["ServerStandard","ServerDatacenter","ServerStandardEval","ServerDatacenterEval"],"Builds":[{"Build":17763,"Version":"2019"},{"Build":20348,"Version":"2022"},{"Build":26100,"Version":"2025"}]}},"Thresholds":{"DiskFreeMinBytes":10737418240,"DiskFreeMinPercent":15,"RetentionWarnDays":{"Workstation":7,"Server":14},"EvidenceLookbackDays":7,"SmbAuditDays":30},"GpoSets":[],"Controls":[{"Id":"ALM-SYS-002","Title":"Autorite de gestion","Domain":"Systeme","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":1,"Mechanism":"Probe","Setting":{"Probe":"Authority"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-SYS-005","Title":"Redemarrage en attente","Domain":"Systeme","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":3,"Mechanism":"Probe","Setting":{"Probe":"PendingReboot"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-SYS-006","Title":"Version, edition et support du systeme","Domain":"Systeme","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":4,"Mechanism":"Probe","Setting":{"Probe":"OsSupport"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-SYS-001","Title":"Synchronisation horaire","Domain":"Systeme","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":5,"Mechanism":"Probe","Setting":{"Probe":"TimeSync"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":["EVT-037"]},{"Id":"ALM-AUD-040","Title":"Forcer les sous-categories d'audit (SCENoApplyLegacyAuditPolicy)","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":10,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"SCENoApplyLegacyAuditPolicy","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-LOG-020","Title":"Retention des journaux et arret sur echec d'audit","Domain":"Journaux","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":15,"Mechanism":"Probe","Setting":{"Probe":"EventLogRetention"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-LOG-021","Title":"ACL du journal Securite","Domain":"Journaux","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":15,"Mechanism":"Probe","Setting":{"Probe":"SecurityLogAcl"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-LOG-023","Title":"Marge disque du volume systeme","Domain":"Journaux","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":15,"Mechanism":"Probe","Setting":{"Probe":"DiskMargin"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-LOG-024","Title":"Retention locale effective","Domain":"Journaux","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":16,"Mechanism":"Probe","Setting":{"Probe":"LogRetention"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-LOG-001","Title":"Taille minimale du journal Security","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":20,"Mechanism":"EventLogSize","Setting":{"LogName":"Security","MinSizeBytes":{"Workstation":201326592,"Server":536870912},"PolicyPath":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security","RoleOverrides":{"RDS":1073741824,"FileServer":1073741824,"HyperV":1073741824}},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"GreaterOrEqual","Events":["EVT-016"]},{"Id":"ALM-LOG-002","Title":"Taille minimale du journal System","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":20,"Mechanism":"EventLogSize","Setting":{"LogName":"System","MinSizeBytes":{"Workstation":33554432,"Server":67108864},"PolicyPath":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System","RoleOverrides":{}},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"GreaterOrEqual","Events":["EVT-014"]},{"Id":"ALM-LOG-003","Title":"Taille minimale du journal Application","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":20,"Mechanism":"EventLogSize","Setting":{"LogName":"Application","MinSizeBytes":{"Workstation":33554432,"Server":67108864},"PolicyPath":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application","RoleOverrides":{}},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"GreaterOrEqual","Events":[]},{"Id":"ALM-LOG-004","Title":"Taille minimale du journal Microsoft-Windows-PowerShell/Operational","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":20,"Mechanism":"EventLogSize","Setting":{"LogName":"Microsoft-Windows-PowerShell/Operational","MinSizeBytes":{"Workstation":134217728,"Server":268435456},"PolicyPath":null,"RoleOverrides":{}},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"GreaterOrEqual","Events":["EVT-027"]},{"Id":"ALM-LOG-005","Title":"Taille minimale du journal Windows PowerShell","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":20,"Mechanism":"EventLogSize","Setting":{"LogName":"Windows PowerShell","MinSizeBytes":{"Workstation":33554432,"Server":33554432},"PolicyPath":null,"RoleOverrides":{}},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"GreaterOrEqual","Events":["EVT-029"]},{"Id":"ALM-LOG-006","Title":"Taille minimale du journal Setup","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":20,"Mechanism":"EventLogSize","Setting":{"LogName":"Setup","MinSizeBytes":{"Workstation":33554432,"Server":33554432},"PolicyPath":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup","RoleOverrides":{}},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"GreaterOrEqual","Events":[]},{"Id":"ALM-LOG-030","Title":"Lecture du journal Windows PowerShell reservee aux administrateurs (lignes de commande 400/403/600)","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":25,"Mechanism":"EventLogAccess","Setting":{"LogName":"Windows PowerShell","RemoveRights":5,"BroadPrincipals":["S-1-1-0","S-1-5-2","S-1-5-3","S-1-5-4","S-1-5-6","S-1-5-7","S-1-5-11","S-1-5-13","S-1-5-14","S-1-5-33","S-1-5-32-545","S-1-5-32-546","S-1-15-2-1","S-1-15-2-2"]},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-LOG-031","Title":"Lecture du canal PowerShell/Operational reservee aux administrateurs (blocs de script 4104)","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":25,"Mechanism":"EventLogAccess","Setting":{"LogName":"Microsoft-Windows-PowerShell/Operational","RemoveRights":5,"BroadPrincipals":["S-1-1-0","S-1-5-2","S-1-5-3","S-1-5-4","S-1-5-6","S-1-5-7","S-1-5-11","S-1-5-13","S-1-5-14","S-1-5-33","S-1-5-32-545","S-1-5-32-546","S-1-15-2-1","S-1-15-2-2"]},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-LOG-032","Title":"Lecture du canal PowerShellCore/Operational reservee aux administrateurs (PowerShell 7)","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":25,"Mechanism":"EventLogAccess","Setting":{"LogName":"PowerShellCore/Operational","RemoveRights":5,"BroadPrincipals":["S-1-1-0","S-1-5-2","S-1-5-3","S-1-5-4","S-1-5-6","S-1-5-7","S-1-5-11","S-1-5-13","S-1-5-14","S-1-5-33","S-1-5-32-545","S-1-5-32-546","S-1-15-2-1","S-1-15-2-2"],"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-LOG-007","Title":"Activer le canal TaskScheduler/Operational","Domain":"Journaux","Decision":{"Workstation":"Option","Server":"Option"},"Order":30,"Mechanism":"EventLogEnable","Setting":{"LogName":"Microsoft-Windows-TaskScheduler/Operational"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"Respect","Events":["EVT-042"]},{"Id":"ALM-DOM-001","Title":"Membre de domaine : chiffrer ou signer le canal securise (toujours)","Domain":"Domaine","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters","Name":"RequireSignOrSeal","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-002","Title":"Membre de domaine : chiffrer le canal securise si possible","Domain":"Domaine","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters","Name":"SealSecureChannel","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SealSecureChannel"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-003","Title":"Membre de domaine : signer le canal securise si possible","Domain":"Domaine","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters","Name":"SignSecureChannel","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SignSecureChannel"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-004","Title":"Membre de domaine : changement du mot de passe du compte ordinateur autorise","Domain":"Domaine","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters","Name":"DisablePasswordChange","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":0,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-005","Title":"Membre de domaine : age maximal du mot de passe ordinateur <= 30 jours","Domain":"Domaine","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters","Name":"MaximumPasswordAge","Type":"DWord","Value":30,"Compare":"LessOrEqual","PolicyKind":"SecurityOption","WindowsDefault":30,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\MaximumPasswordAge"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-006","Title":"Membre de domaine : cle de session forte","Domain":"Domaine","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters","Name":"RequireStrongKey","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireStrongKey"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-007","Title":"Strategies de registre : appliquer aussi en arriere-plan","Domain":"Domaine","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}","Name":"NoBackgroundPolicy","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-008","Title":"Strategies de registre : retraiter meme sans changement","Domain":"Domaine","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}","Name":"NoGPOListChanges","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-009","Title":"Strategies de securite : appliquer aussi en arriere-plan","Domain":"Domaine","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}","Name":"NoBackgroundPolicy","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-010","Title":"Strategies de securite : retraiter meme sans changement","Domain":"Domaine","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}","Name":"NoGPOListChanges","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-011","Title":"Actualisation des strategies en arriere-plan maintenue","Domain":"Domaine","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"DisableBkGndGroupPolicy","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":0},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-DOM-012","Title":"Elevation requise pour changer l'emplacement reseau (utilisateurs du domaine)","Domain":"Domaine","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections","Name":"NC_StdDomainUserSetLocation","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-001","Title":"Pare-feu Domain : journaliser les paquets rejetes","Domain":"Pare-feu","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging","Name":"LogDroppedPackets","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-002","Title":"Pare-feu Domain : journaliser les connexions reussies","Domain":"Pare-feu","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging","Name":"LogSuccessfulConnections","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-003","Title":"Pare-feu Domain : taille du journal >= 16 Mio","Domain":"Pare-feu","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging","Name":"LogFileSize","Type":"DWord","Value":16384,"Compare":"GreaterOrEqual","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-004","Title":"Pare-feu Private : journaliser les paquets rejetes","Domain":"Pare-feu","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging","Name":"LogDroppedPackets","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-005","Title":"Pare-feu Private : journaliser les connexions reussies","Domain":"Pare-feu","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging","Name":"LogSuccessfulConnections","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-006","Title":"Pare-feu Private : taille du journal >= 16 Mio","Domain":"Pare-feu","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging","Name":"LogFileSize","Type":"DWord","Value":16384,"Compare":"GreaterOrEqual","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-007","Title":"Pare-feu Public : journaliser les paquets rejetes","Domain":"Pare-feu","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging","Name":"LogDroppedPackets","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-008","Title":"Pare-feu Public : journaliser les connexions reussies","Domain":"Pare-feu","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging","Name":"LogSuccessfulConnections","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-FW-009","Title":"Pare-feu Public : taille du journal >= 16 Mio","Domain":"Pare-feu","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging","Name":"LogFileSize","Type":"DWord","Value":16384,"Compare":"GreaterOrEqual","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-001","Title":"Desactiver l'execution automatique sur tous les lecteurs","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer","Name":"NoDriveTypeAutoRun","Type":"DWord","Value":255,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":145},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-002","Title":"AutoRun : ne pas executer de commandes","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer","Name":"NoAutorun","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-003","Title":"Interdire AutoPlay pour les peripheriques hors volume","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer","Name":"NoAutoplayfornonVolume","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-004","Title":"UAC : executer les administrateurs en mode d'approbation (EnableLUA)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"EnableLUA","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-HRD-005","Title":"UAC : invite de consentement sur le bureau securise (administrateurs)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"ConsentPromptBehaviorAdmin","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":5,"Accept":[1,2],"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-006","Title":"UAC : refuser automatiquement l'elevation pour les utilisateurs standards","Domain":"Durcissement","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"ConsentPromptBehaviorUser","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":3,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-007","Title":"UAC : mode d'approbation pour le compte Administrateur integre","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"FilterAdministratorToken","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":0,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken"},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-008","Title":"Restrictions UAC distantes pour les comptes locaux (LocalAccountTokenFilterPolicy)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"LocalAccountTokenFilterPolicy","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":0},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-009","Title":"WDigest : pas d'identifiants en clair en memoire","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest","Name":"UseLogonCredential","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":0},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-010","Title":"Protection LSA (RunAsPPL) sans verrou UEFI","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"RunAsPPL","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"Accept":[1,2]},"Applicability":{"Workstation":{"MinBuild":22621},"Server":{"MinBuild":26100}},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-012","Title":"UAC : detecter les installations d'applications","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"EnableInstallerDetection","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableInstallerDetection"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-016","Title":"Installation des pilotes d'impression reservee aux administrateurs","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint","Name":"RestrictDriverInstallationToAdministrators","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-018","Title":"Ne pas stocker de hachage LAN Manager","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"NoLMHash","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-020","Title":"UAC : n'elever UIAccess que depuis des emplacements securises","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"EnableSecureUIAPaths","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableSecureUIAPaths"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-021","Title":"UAC : basculer vers le bureau securise pour l'elevation","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"PromptOnSecureDesktop","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-022","Title":"UAC : virtualiser les echecs d'ecriture","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"EnableVirtualization","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableVirtualization"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-023","Title":"Comptes locaux a mot de passe vide limites a la console","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"LimitBlankPasswordUse","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-024","Title":"Pas d'ouverture de session automatique (AutoAdminLogon)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","Name":"AutoAdminLogon","Type":"String","Value":"0","Compare":"Equal","PolicyKind":"Raw","WindowsDefault":"0"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-HRD-025","Title":"Recherche DLL en mode securise","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager","Name":"SafeDllSearchMode","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":1},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-026","Title":"Protection SEHOP","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel","Name":"DisableExceptionChainValidation","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-027","Title":"Verification du bourrage des certificats Authenticode","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\Wintrust\\Config","Name":"EnableCertPaddingCheck","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-028","Title":"Delai de grace de l'ecran de veille <= 5 s","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","Name":"ScreenSaverGracePeriod","Type":"String","Value":"5","Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-029","Title":"Ne pas enumerer les comptes administrateurs a l'elevation","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI","Name":"EnumerateAdministrators","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-030","Title":"Masquer le bouton d'affichage du mot de passe","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredUI","Name":"DisablePasswordReveal","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-031","Title":"Windows Installer : jamais d'installation avec privileges eleves","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer","Name":"AlwaysInstallElevated","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-032","Title":"Windows Installer : pas de controle utilisateur sur l'installation","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer","Name":"EnableUserControl","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-033","Title":"Pas de reconnexion automatique du dernier utilisateur apres redemarrage","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"DisableAutomaticRestartSignOn","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-034","Title":"Pas de transmission du mot de passe aux fournisseurs MPR","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"EnableMPR","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-035","Title":"Assistance a distance sollicitee desactivee","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"fAllowToGetHelp","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-036","Title":"Offre d'assistance a distance desactivee","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"fAllowUnsolicited","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-037","Title":"Interdire le chargement de SSP/AP personnalises dans LSASS","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"AllowCustomSSPsAPs","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-038","Title":"Pilotes de demarrage : bons, inconnus et mauvais mais critiques (ELAM)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch","Name":"DriverLoadPolicy","Type":"DWord","Value":3,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":3},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-039","Title":"Ne pas desactiver DEP pour l'Explorateur","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer","Name":"NoDataExecutionPrevention","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-040","Title":"Terminer sur corruption du tas (Explorateur)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer","Name":"NoHeapTerminationOnCorruption","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-041","Title":"Protocole shell en mode protege","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer","Name":"PreXPSP2ShellProtocolBehavior","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-042","Title":"Appliquer la Marque du Web aux copies depuis des sources non sures","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer","Name":"DisableMotWOnInsecurePathCopy","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-043","Title":"Empecher la modification des parametres de protection contre les exploits","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection","Name":"DisallowExploitProtectionOverride","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-044","Title":"Commande sudo desactivee","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Sudo","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-045","Title":"Pas de questions de securite pour les comptes locaux","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"NoLocalPasswordResetQuestions","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-046","Title":"Anti-usurpation renforcee de la reconnaissance faciale","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures","Name":"EnhancedAntiSpoofing","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-050","Title":"App Installer : fonctions experimentales desactive(e)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller","Name":"EnableExperimentalFeatures","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-051","Title":"App Installer : contournement du hachage desactive(e)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller","Name":"EnableHashOverride","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-052","Title":"App Installer : contournement de l'analyse des archives locales desactive(e)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller","Name":"EnableLocalArchiveMalwareScanOverride","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-053","Title":"App Installer : contournement de l'epinglage de certificat du Store desactive(e)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller","Name":"EnableBypassCertificatePinningForMicrosoftStore","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-054","Title":"App Installer : protocole ms-appinstaller desactive(e)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppInstaller","Name":"EnableMSAppInstallerProtocol","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-055","Title":"Pas d'installation d'applications empaquetees par les non-administrateurs","Domain":"Durcissement","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Appx","Name":"BlockNonAdminUserInstall","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-056","Title":"Pas de paquets non signes par utilisateur","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Appx","Name":"DisablePerUserUnsignedPackagesByDefault","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-057","Title":"Objets systeme : insensibilite a la casse","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel","Name":"ObCaseInsensitive","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\\ObCaseInsensitive"},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-058","Title":"Objets systeme : renforcer les permissions par defaut","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager","Name":"ProtectionMode","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\ProtectionMode"},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-059","Title":"Seuil d'avertissement du journal Securite (90 %)","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security","Name":"WarningLevel","Type":"DWord","Value":90,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-060","Title":"UAC : Administrator protection (elevation juste-a-temps par compte administrateur isole)","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"TypeOfAdminApprovalMode","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\TypeOfAdminApprovalMode"},"Applicability":{"Workstation":{"MinBuild":26100}},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-HRD-061","Title":"UAC : Administrator protection - demander les identifiants sur le bureau securise","Domain":"Durcissement","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"ConsentPromptBehaviorEnhancedAdmin","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorEnhancedAdmin"},"Applicability":{"Workstation":{"MinBuild":26100}},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-LOG-010","Title":"Journal Application : ecraser les evenements si plein (pas d'arret de journalisation)","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application","Name":"Retention","Type":"String","Value":"0","Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-LOG-011","Title":"Journal Security : ecraser les evenements si plein (pas d'arret de journalisation)","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security","Name":"Retention","Type":"String","Value":"0","Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-LOG-012","Title":"Journal Setup : ecraser les evenements si plein (pas d'arret de journalisation)","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup","Name":"Retention","Type":"String","Value":"0","Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-LOG-013","Title":"Journal System : ecraser les evenements si plein (pas d'arret de journalisation)","Domain":"Journaux","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System","Name":"Retention","Type":"String","Value":"0","Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-001","Title":"SMBv1 serveur desactive","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters","Name":"SMB1","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-002","Title":"Pilote client SMBv1 desactive","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-003","Title":"Serveur SMB : signature exigee","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters","Name":"RequireSecuritySignature","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature"},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-004","Title":"Serveur SMB : signature si le client l'accepte","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters","Name":"EnableSecuritySignature","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableSecuritySignature"},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-005","Title":"Client SMB : signature exigee","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters","Name":"RequireSecuritySignature","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature"},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-006","Title":"Client SMB : signature si le serveur l'accepte","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters","Name":"EnableSecuritySignature","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnableSecuritySignature"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-007","Title":"Pas de mot de passe en clair vers des serveurs SMB tiers","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters","Name":"EnablePlainTextPassword","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":0,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnablePlainTextPassword"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-008","Title":"Connexions invite SMB non securisees interdites","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation","Name":"AllowInsecureGuestAuth","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-009","Title":"Desactiver LLMNR","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient","Name":"EnableMulticast","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-010","Title":"NetBIOS : desactive sur les reseaux publics","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient","Name":"EnableNetbios","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null,"Accept":[0,2]},"Applicability":{"Workstation":{"MinBuild":22621},"Server":{"MinBuild":20348}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-011","Title":"NetBT en mode P-node (pas de diffusion NetBIOS)","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters","Name":"NodeType","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-012","Title":"Desactiver mDNS","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient","Name":"EnableMDNS","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-013","Title":"Niveau d'authentification LAN Manager : NTLMv2 uniquement","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"LmCompatibilityLevel","Type":"DWord","Value":5,"Compare":"GreaterOrEqual","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-014","Title":"Securite minimale de session NTLM (clients) : NTLMv2 + 128 bits","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0","Name":"NTLMMinClientSec","Type":"DWord","Value":537395200,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-015","Title":"Securite minimale de session NTLM (serveurs) : NTLMv2 + 128 bits","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0","Name":"NTLMMinServerSec","Type":"DWord","Value":537395200,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-016","Title":"Audit du NTLM sortant (sans blocage)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0","Name":"RestrictSendingNTLMTraffic","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"Accept":[1,2],"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\RestrictSendingNTLMTraffic"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-017","Title":"Audit du NTLM entrant pour tous les comptes","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0","Name":"AuditReceivingNTLMTraffic","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\AuditReceivingNTLMTraffic"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-018","Title":"Pas d'enumeration anonyme des comptes SAM","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"RestrictAnonymousSAM","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-019","Title":"Pas d'enumeration anonyme des comptes et partages","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"RestrictAnonymous","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":0,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-020","Title":"Tout le monde ne s'applique pas aux anonymes","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"EveryoneIncludesAnonymous","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":0,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-021","Title":"Acces anonyme aux canaux nommes et partages restreint","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters","Name":"RestrictNullSessAccess","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RestrictNullSessAccess"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-022","Title":"Aucun partage accessible anonymement","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters","Name":"NullSessionShares","Type":"MultiString","Value":[],"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\NullSessionShares"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-023","Title":"Aucun canal nomme accessible anonymement","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters","Name":"NullSessionPipes","Type":"MultiString","Value":[],"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\NullSessionPipes"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-024","Title":"Appels distants a la SAM reserves aux administrateurs","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"RestrictRemoteSAM","Type":"String","Value":"O:BAG:BAD:(A;;RC;;;BA)","Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictRemoteSAM"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-025","Title":"Modele de partage classique pour les comptes locaux","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"ForceGuest","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":0,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\ForceGuest"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-026","Title":"LocalSystem utilise l'identite de l'ordinateur pour NTLM","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa","Name":"UseMachineId","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\UseMachineId"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-027","Title":"Pas de session NULL de repli pour LocalSystem","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0","Name":"AllowNullSessionFallback","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\AllowNullSessionFallback"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-028","Title":"Pas d'authentification PKU2U par identite en ligne","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\pku2u","Name":"AllowOnlineID","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\pku2u\\AllowOnlineID","NotIfEntraJoined":true},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-029","Title":"Signature LDAP client : negocier","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP","Name":"LDAPClientIntegrity","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"Accept":[1,2],"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-030","Title":"Chiffrement LDAP client : negocier","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP","Name":"LDAPClientConfidentiality","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"Accept":[1,2],"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LDAP\\LDAPClientConfidentiality"},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-031","Title":"Validation du nom cible SPN du serveur SMB","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters","Name":"SmbServerNameHardeningLevel","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"Accept":[1,2],"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\SmbServerNameHardeningLevel"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-032","Title":"Deconnexion des sessions SMB inactives <= 15 min","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters","Name":"AutoDisconnect","Type":"DWord","Value":15,"Compare":"LessOrEqual","PolicyKind":"SecurityOption","WindowsDefault":15,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\AutoDisconnect"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-033","Title":"Deconnexion SMB a l'expiration des heures de connexion","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters","Name":"EnableForcedLogOff","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":1,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableForcedLogOff"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-034","Title":"CredSSP : forcer les clients a jour (oracle de chiffrement)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters","Name":"AllowEncryptionOracle","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-035","Title":"Delegation d'identifiants non exportables autorisee","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation","Name":"AllowProtectedCreds","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-036","Title":"Routage par la source IPv4 desactive","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters","Name":"DisableIPSourceRouting","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-037","Title":"Routage par la source IPv6 desactive","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters","Name":"DisableIPSourceRouting","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-038","Title":"Redirections ICMP ignorees","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters","Name":"EnableICMPRedirect","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-039","Title":"Ignorer les demandes de liberation de nom NetBIOS","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters","Name":"NoNameReleaseOnDemand","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-040","Title":"Chemins UNC renforces : NETLOGON","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths","Name":"\\\\*\\NETLOGON","Type":"String","Value":"RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1","Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-041","Title":"Chemins UNC renforces : SYSVOL","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths","Name":"\\\\*\\SYSVOL","Type":"String","Value":"RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1","Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-042","Title":"Pont reseau interdit sur le reseau du domaine","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections","Name":"NC_AllowNetBridge_NLA","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-043","Title":"Partage de connexion Internet interdit sur le reseau du domaine","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections","Name":"NC_ShowSharedAccessUI","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-045","Title":"WinRM client : pas d'authentification Basic","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client","Name":"AllowBasic","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-046","Title":"WinRM client : pas de trafic non chiffre","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client","Name":"AllowUnencryptedTraffic","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-047","Title":"WinRM client : pas d'authentification Digest","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client","Name":"AllowDigest","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-048","Title":"WinRM service : pas d'authentification Basic","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service","Name":"AllowBasic","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-049","Title":"WinRM service : pas de trafic non chiffre","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service","Name":"AllowUnencryptedTraffic","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-050","Title":"WinRM service : pas de stockage des identifiants RunAs","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service","Name":"DisableRunAs","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-051","Title":"RDP : authentification au niveau du reseau (NLA) exigee","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"UserAuthentication","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-052","Title":"RDP : communication RPC securisee","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"fEncryptRPCTraffic","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-053","Title":"RDP : couche de securite TLS","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"SecurityLayer","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-054","Title":"RDP : niveau de chiffrement eleve","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"MinEncryptionLevel","Type":"DWord","Value":3,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"Respect","Events":[]},{"Id":"ALM-NET-055","Title":"RDP : toujours demander le mot de passe","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"fPromptForPassword","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-056","Title":"RDP : ne pas enregistrer les mots de passe","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"DisablePasswordSaving","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-057","Title":"RDP : pas de redirection des lecteurs","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"fDisableCdm","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-058","Title":"RDP : supprimer les dossiers temporaires a la fermeture","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"DeleteTempDirsOnExit","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-059","Title":"RDP : dossiers temporaires par session","Domain":"Reseau","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services","Name":"PerSessionTempDir","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-060","Title":"Client SMB : chiffrement exige","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation","Name":"RequireEncryption","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null,"SocleMinBuild":26100},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-061","Title":"Client SMB : version minimale 3.1.1","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation","Name":"MinSmb2Dialect","Type":"DWord","Value":785,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null,"SocleMinBuild":26100},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-062","Title":"Serveur SMB : version minimale 3.1.1","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer","Name":"MinSmb2Dialect","Type":"DWord","Value":785,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null,"SocleMinBuild":26100},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-063","Title":"SMB serveur : audit des clients sans chiffrement","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer","Name":"AuditClientDoesNotSupportEncryption","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-064","Title":"SMB serveur : audit des clients sans signature","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer","Name":"AuditClientDoesNotSupportSigning","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-065","Title":"SMB serveur : audit des connexions invite","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer","Name":"AuditInsecureGuestLogon","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-066","Title":"SMB serveur : limiteur de tentatives d'authentification","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer","Name":"EnableAuthRateLimiter","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-067","Title":"SMB serveur : delai apres echec >= 2000 ms","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanServer","Name":"InvalidAuthenticationDelayTimeInMs","Type":"DWord","Value":2000,"Compare":"GreaterOrEqual","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-068","Title":"SMB client : audit des connexions invite","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation","Name":"AuditInsecureGuestLogon","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-069","Title":"SMB client : audit des serveurs sans chiffrement","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation","Name":"AuditServerDoesNotSupportEncryption","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-070","Title":"SMB client : audit des serveurs sans signature","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation","Name":"AuditServerDoesNotSupportSigning","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-071","Title":"Mailslots distants desactives (navigateur)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Bowser","Name":"EnableMailslots","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-072","Title":"Mailslots distants desactives (fournisseur reseau)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider","Name":"EnableMailslots","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{"Workstation":{"MinBuild":26100},"Server":{"MinBuild":26100}},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-073","Title":"Schannel : SSL 2.0 desactive (serveur)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Server","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-074","Title":"Schannel : SSL 2.0 desactive (client)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 2.0\\Client","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-075","Title":"Schannel : SSL 3.0 desactive (serveur)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Server","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-076","Title":"Schannel : SSL 3.0 desactive (client)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Client","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-077","Title":"Schannel : TLS 1.0 desactive (serveur)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-078","Title":"Schannel : TLS 1.0 desactive (client)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-079","Title":"Schannel : TLS 1.1 desactive (serveur)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-080","Title":"Schannel : TLS 1.1 desactive (client)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Client","Name":"Enabled","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-081","Title":"Spouleur : refuser les connexions clientes distantes (poste)","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers","Name":"RegisterSpoolerRemoteRpcEndPoint","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-082","Title":"Spouleur : Redirection Guard active","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers","Name":"RedirectionGuardPolicy","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-083","Title":"Spouleur : confidentialite RPC au niveau paquet","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print","Name":"RpcAuthnLevelPrivacyEnabled","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":1},"Applicability":{},"Restart":"Redemarrage","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-084","Title":"Point and Print : avertissement et elevation a l'installation","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint","Name":"NoWarningNoElevationOnInstall","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-085","Title":"Point and Print : avertissement et elevation a la mise a jour","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint","Name":"UpdatePromptSettings","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-086","Title":"Fichiers specifiques aux files d'attente limites aux profils de couleur","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers","Name":"CopyFilesPolicy","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-087","Title":"Impression : RPC sortant sur TCP","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC","Name":"RpcUseNamedPipeProtocol","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-088","Title":"Impression : authentification RPC sortante par defaut","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC","Name":"RpcAuthentication","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-089","Title":"Impression : RPC entrant sur TCP","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC","Name":"RpcProtocols","Type":"DWord","Value":5,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-090","Title":"Impression : authentification RPC entrante negociee","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC","Name":"ForceKerberosForRpc","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null,"Accept":[0,1]},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-091","Title":"Impression : port RPC dynamique","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC","Name":"RpcTcpPort","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-092","Title":"Pas de telechargement de pilotes d'impression par HTTP","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers","Name":"DisableWebPnPDownload","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-093","Title":"Pas de telechargement Internet pour les assistants de publication","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer","Name":"NoWebServices","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-094","Title":"Les utilisateurs ne peuvent pas installer de pilotes d'imprimante","Domain":"Reseau","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers","Name":"AddPrinterDrivers","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\AddPrinterDrivers"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-095","Title":"RPC : authentification du client du mappeur de points de terminaison","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc","Name":"EnableAuthEpResolution","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-096","Title":"RPC : clients non authentifies refuses","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc","Name":"RestrictRemoteClients","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-097","Title":"Wi-Fi : pas de connexion automatique aux points d'acces suggeres","Domain":"Reseau","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config","Name":"AutoConnectAllowedOEM","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-098","Title":"Pas de Wi-Fi simultane quand l'Ethernet est connecte","Domain":"Reseau","Decision":{"Workstation":"Option","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy","Name":"fMinimizeConnections","Type":"DWord","Value":3,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-NET-099","Title":"Kerberos : chiffrements AES uniquement","Domain":"Reseau","Decision":{"Workstation":"Exclu","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters","Name":"SupportedEncryptionTypes","Type":"DWord","Value":2147483640,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\SupportedEncryptionTypes"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-PRC-001","Title":"Inclure la ligne de commande dans l'evenement 4688","Domain":"Processus","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit","Name":"ProcessCreationIncludeCmdLine_Enabled","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-PRC-002","Title":"Journalisation des blocs de script PowerShell 5.1","Domain":"Processus","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging","Name":"EnableScriptBlockLogging","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-001","Title":"Service Xbox Accessory Management (XboxGipSvc) desactive","Domain":"Services","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\XboxGipSvc","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-002","Title":"Service Xbox Live Auth Manager (XblAuthManager) desactive","Domain":"Services","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\XblAuthManager","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-003","Title":"Service Xbox Live Game Save (XblGameSave) desactive","Domain":"Services","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\XblGameSave","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-004","Title":"Service Xbox Live Networking (XboxNetApiSvc) desactive","Domain":"Services","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\XboxNetApiSvc","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-005","Title":"Service Localisateur RPC (RpcLocator) desactive","Domain":"Services","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\RpcLocator","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-006","Title":"Service Decouverte SSDP (SSDPSRV) desactive","Domain":"Services","Decision":{"Workstation":"Option","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SSDPSRV","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-007","Title":"Service Hote UPnP (upnphost) desactive","Domain":"Services","Decision":{"Workstation":"Option","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\upnphost","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-008","Title":"Service Point d'acces mobile (icssvc) desactive","Domain":"Services","Decision":{"Workstation":"Option","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\icssvc","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-009","Title":"Service Partage reseau Windows Media Player (WMPNetworkSvc) desactive","Domain":"Services","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WMPNetworkSvc","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-SVC-010","Title":"Service Routage et acces distant (RemoteAccess) desactive","Domain":"Services","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\RemoteAccess","Name":"Start","Type":"DWord","Value":4,"Compare":"Equal","PolicyKind":"Raw","WindowsDefault":null,"OnlyIfKeyExists":true},"Applicability":{},"Restart":"Redemarrage","GpoPart":"None","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-001","Title":"Camera de l'ecran de verrouillage desactivee","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization","Name":"NoLockScreenCamera","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-002","Title":"Diaporama de l'ecran de verrouillage desactive","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization","Name":"NoLockScreenSlideshow","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-003","Title":"Masquer les details du compte a la connexion","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"BlockUserFromShowingAccountDetailsOnSignin","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-004","Title":"Masquer la selection reseau sur l'ecran de connexion","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"DontDisplayNetworkSelectionUI","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-005","Title":"Pas de notifications d'applications sur l'ecran de verrouillage","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"DisableLockScreenAppNotifications","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-006","Title":"Ne pas enumerer les utilisateurs connectes (membre de domaine)","Domain":"Poste","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"DontEnumerateConnectedUsers","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-007","Title":"Ne pas enumerer les utilisateurs locaux (membre de domaine)","Domain":"Poste","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"EnumerateLocalUsers","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-008","Title":"Desactiver la connexion par mot de passe image","Domain":"Poste","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"BlockDomainPicturePassword","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-009","Title":"Desactiver le code PIN de commodite (domaine)","Domain":"Poste","Decision":{"Workstation":"Option","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System","Name":"AllowDomainPINLogon","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-010","Title":"Mot de passe a la sortie de veille (batterie)","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51","Name":"DCSettingIndex","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-011","Title":"Mot de passe a la sortie de veille (secteur)","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51","Name":"ACSettingIndex","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-012","Title":"Verrouiller le poste au retrait de la carte a puce","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","Name":"ScRemoveOption","Type":"String","Value":"1","Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":"0","Accept":["1","2","3"],"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ScRemoveOption"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-013","Title":"Avertissement d'expiration du mot de passe (5 a 14 jours)","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","Name":"PasswordExpiryWarning","Type":"DWord","Value":5,"Compare":"GreaterOrEqual","PolicyKind":"SecurityOption","WindowsDefault":5,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\PasswordExpiryWarning"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-014","Title":"Verrouillage de session apres 20 min d'inactivite","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"InactivityTimeoutSecs","Type":"DWord","Value":1200,"Compare":"LessOrEqual","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-015","Title":"Exiger CTRL+ALT+SUPPR","Domain":"Poste","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"DisableCAD","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-016","Title":"Ne pas afficher le dernier utilisateur connecte","Domain":"Poste","Decision":{"Workstation":"Option","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"DontDisplayLastUserName","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-017","Title":"Arret sans ouverture de session interdit","Domain":"Poste","Decision":{"Workstation":"Exclu","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","Name":"ShutdownWithoutLogon","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":0,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ShutdownWithoutLogon"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-018","Title":"Deverrouillage exigeant l'authentification par un DC","Domain":"Poste","Decision":{"Workstation":"Exclu","Server":"Option"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","Name":"ForceUnlockLogon","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"SecurityOption","WindowsDefault":null,"RsopPath":"MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ForceUnlockLogon"},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-019","Title":"Applications Windows : pas d'activation vocale ecran verrouille","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy","Name":"LetAppsActivateWithVoiceAboveLock","Type":"DWord","Value":2,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-020","Title":"Projection sans fil vers ce PC (Miracast) : code PIN a la premiere association","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Exclu"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Connect","Name":"RequirePinForPairing","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null,"Accept":[1,2]},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-021","Title":"Flux RSS : pas de telechargement des pieces jointes","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds","Name":"DisableEnclosureDownload","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-022","Title":"Flux RSS : pas d'authentification Basic sur HTTP","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds","Name":"AllowBasicAuthInClear","Type":"DWord","Value":0,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-UI-023","Title":"Pas de telechargement des metadonnees de peripheriques depuis Internet","Domain":"Poste","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":50,"Mechanism":"RegistryValue","Setting":{"Path":"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata","Name":"PreventDeviceMetadataFromNetwork","Type":"DWord","Value":1,"Compare":"Equal","PolicyKind":"AdminTemplate","WindowsDefault":null},"Applicability":{},"Restart":"Aucun","GpoPart":"Registry","ExistingValuePolicy":"OverwriteWeaker","Events":[]},{"Id":"ALM-AUD-001","Title":"Audit Validation des informations d'identification","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE923F-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-008"]},{"Id":"ALM-AUD-002","Title":"Audit Gestion des groupes de securite","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9237-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-010"]},{"Id":"ALM-AUD-003","Title":"Audit Gestion des comptes d'utilisateur","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9235-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-009","EVT-006"]},{"Id":"ALM-AUD-004","Title":"Audit Creation de processus","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE922B-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-012"]},{"Id":"ALM-AUD-005","Title":"Audit Ouverture de session","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9215-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-001","EVT-002","EVT-004"]},{"Id":"ALM-AUD-006","Title":"Audit Fermeture de session","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9216-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-003"]},{"Id":"ALM-AUD-007","Title":"Audit Verrouillage du compte","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9217-69AE-11D9-BED3-505054503030}","Success":0,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-007"]},{"Id":"ALM-AUD-008","Title":"Audit Ouverture de session speciale","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE921B-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-005"]},{"Id":"ALM-AUD-009","Title":"Audit Autres evenements d'ouverture/fermeture de session","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE921C-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-021"]},{"Id":"ALM-AUD-010","Title":"Audit Appartenance a un groupe","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9249-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-044"]},{"Id":"ALM-AUD-011","Title":"Audit Modification de la strategie d'audit","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE922F-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-011"]},{"Id":"ALM-AUD-012","Title":"Audit Modification de la strategie d'authentification","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9230-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-011"]},{"Id":"ALM-AUD-013","Title":"Audit Modification de la strategie d'autorisation","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9231-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-041"]},{"Id":"ALM-AUD-014","Title":"Audit Modification de strategie de niveau regle MPSSVC","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9232-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-022"]},{"Id":"ALM-AUD-015","Title":"Audit Autres evenements de modification de strategie","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9234-69AE-11D9-BED3-505054503030}","Success":0,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":[]},{"Id":"ALM-AUD-016","Title":"Audit Utilisation de privileges sensibles","Domain":"Audit","Decision":{"Workstation":"Option","Server":"Option"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9228-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-023"]},{"Id":"ALM-AUD-017","Title":"Audit Modification de l'etat de la securite","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9210-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-019","EVT-039"]},{"Id":"ALM-AUD-018","Title":"Audit Extension du systeme de securite","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9211-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-013"]},{"Id":"ALM-AUD-019","Title":"Audit Integrite du systeme","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9212-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-045"]},{"Id":"ALM-AUD-020","Title":"Audit Autres evenements systeme","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9214-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-038"]},{"Id":"ALM-AUD-021","Title":"Audit Autres evenements d'acces aux objets","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9227-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-020"]},{"Id":"ALM-AUD-022","Title":"Audit Activite PNP","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9248-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-024"]},{"Id":"ALM-AUD-023","Title":"Audit Stockage amovible","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9245-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-025"]},{"Id":"ALM-AUD-024","Title":"Audit Partage de fichiers","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9224-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-026"]},{"Id":"ALM-AUD-025","Title":"Audit Partage de fichiers detaille","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9244-69AE-11D9-BED3-505054503030}","Success":0,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":[]},{"Id":"ALM-AUD-026","Title":"Audit Connexion de la plateforme de filtrage","Domain":"Audit","Decision":{"Workstation":"Exclu","Server":"Exclu"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9226-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":[]},{"Id":"ALM-AUD-027","Title":"Audit Fin du processus","Domain":"Audit","Decision":{"Workstation":"Exclu","Server":"Exclu"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE922C-69AE-11D9-BED3-505054503030}","Success":1,"Failure":0},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":[]},{"Id":"ALM-AUD-028","Title":"Audit Service d'authentification Kerberos","Domain":"Audit","Decision":{"Workstation":"Exclu","Server":"Exclu"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9242-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":["EVT-048"]},{"Id":"ALM-AUD-030","Title":"Audit Gestion des groupes d'applications","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9239-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":[]},{"Id":"ALM-AUD-031","Title":"Audit Pilote IPsec","Domain":"Audit","Decision":{"Workstation":"Socle","Server":"Socle"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9213-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":[]},{"Id":"ALM-AUD-034","Title":"Audit Operations de ticket Kerberos","Domain":"Audit","Decision":{"Workstation":"Exclu","Server":"Exclu"},"Order":100,"Mechanism":"AuditSubcategory","Setting":{"Guid":"{0CCE9240-69AE-11D9-BED3-505054503030}","Success":1,"Failure":1},"Applicability":{},"Restart":"Aucun","GpoPart":"AdvancedAudit","ExistingValuePolicy":"Union","Events":[]},{"Id":"ALM-ACC-001","Title":"Strategie de verrouillage et de mots de passe locaux","Domain":"Durcissement","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"AccountPolicy"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-HRD-011","Title":"VBS / HVCI / Credential Guard : etat","Domain":"Durcissement","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"DeviceGuard"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-HRD-014","Title":"LAPS : etat","Domain":"Durcissement","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"Laps"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-HRD-015","Title":"Comptes locaux sensibles","Domain":"Durcissement","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"LocalAccounts"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-NET-100","Title":"SMBv1 : fonctionnalite installee","Domain":"Reseau","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"Smb1"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-NET-101","Title":"RDP : etat","Domain":"Reseau","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"Rdp"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":["EVT-032"]},{"Id":"ALM-PRC-005","Title":"PowerShell 7 : presence et journalisation","Domain":"Processus","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"PowerShell7"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":["EVT-030"]},{"Id":"ALM-PRC-006","Title":"Moteur Windows PowerShell 2.0","Domain":"Processus","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"PowerShellV2"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":["EVT-029"]},{"Id":"ALM-PRT-001","Title":"Antivirus : produit pilote et Defender","Domain":"Protection","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"Antivirus"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":["EVT-031"]},{"Id":"ALM-PRT-002","Title":"Pare-feu : etat des profils","Domain":"Protection","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"Firewall"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":["EVT-038"]},{"Id":"ALM-SVC-020","Title":"Services exposes installes (IIS, FTP, SSH, Telnet simple...)","Domain":"Services","Decision":{"Workstation":"Audit","Server":"Audit"},"Order":900,"Mechanism":"Probe","Setting":{"Probe":"ServicesExposed"},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]},{"Id":"ALM-PRC-007","Title":"Sysmon","Domain":"Processus","Decision":{"Workstation":"Option","Server":"Option"},"Order":990,"Mechanism":"Manual","Setting":{},"Applicability":{},"Restart":"Aucun","GpoPart":"None","ExistingValuePolicy":"","Events":[]}],"Events":[{"Id":"EVT-001","Signal":"Ouverture de session reussie (type 2/3/7/10/11)","EventIds":[4624],"Channel":"Security","ControlIds":["ALM-AUD-005"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-002","Signal":"Echec d'ouverture de session","EventIds":[4625],"Channel":"Security","ControlIds":["ALM-AUD-005"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-003","Signal":"Fermeture de session","EventIds":[4634,4647],"Channel":"Security","ControlIds":["ALM-AUD-006"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-004","Signal":"Ouverture avec identifiants explicites","EventIds":[4648],"Channel":"Security","ControlIds":["ALM-AUD-005"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-005","Signal":"Session avec privileges speciaux","EventIds":[4672],"Channel":"Security","ControlIds":["ALM-AUD-008"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-006","Signal":"Compte local verrouille","EventIds":[4740],"Channel":"Security","ControlIds":["ALM-AUD-003"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-007","Signal":"Tentative sur compte verrouille","EventIds":[4625],"Channel":"Security","ControlIds":["ALM-AUD-007"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-008","Signal":"Validation NTLM d'un compte local","EventIds":[4776],"Channel":"Security","ControlIds":["ALM-AUD-001"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-009","Signal":"Cycle de vie des comptes locaux","EventIds":[4720,4722,4723,4724,4725,4726,4738,4781],"Channel":"Security","ControlIds":["ALM-AUD-003"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-010","Signal":"Modification de groupes locaux","EventIds":[4731,4732,4733,4734,4735,4799],"Channel":"Security","ControlIds":["ALM-AUD-002"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-011","Signal":"Modification de la strategie d'audit / d'authentification","EventIds":[4719,4706,4713],"Channel":"Security","ControlIds":["ALM-AUD-011","ALM-AUD-012"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-012","Signal":"Creation de processus (+ ligne de commande si ALM-PRC-001)","EventIds":[4688],"Channel":"Security","ControlIds":["ALM-AUD-004","ALM-PRC-001"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-013","Signal":"Service installe (Securite)","EventIds":[4697],"Channel":"Security","ControlIds":["ALM-AUD-018"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-014","Signal":"Service installe (Systeme)","EventIds":[7045],"Channel":"System","ControlIds":["ALM-LOG-002"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-015","Signal":"Type de demarrage de service modifie","EventIds":[7040],"Channel":"System","ControlIds":["ALM-LOG-002"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-016","Signal":"Journal Securite efface","EventIds":[1102],"Channel":"Security","ControlIds":["ALM-LOG-001"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-017","Signal":"Autre journal efface","EventIds":[104],"Channel":"System","ControlIds":["ALM-LOG-002"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-018","Signal":"Arret du service de journalisation","EventIds":[1100],"Channel":"Security","ControlIds":["ALM-LOG-001"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-019","Signal":"Heure systeme modifiee","EventIds":[4616],"Channel":"Security","ControlIds":["ALM-AUD-017"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-020","Signal":"Taches planifiees creees/modifiees/supprimees","EventIds":[4698,4699,4700,4701,4702],"Channel":"Security","ControlIds":["ALM-AUD-021"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-021","Signal":"Reconnexion/deconnexion RDP, verrouillage","EventIds":[4778,4779,4800,4801],"Channel":"Security","ControlIds":["ALM-AUD-009"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-022","Signal":"Regles de pare-feu modifiees","EventIds":[4946,4947,4948,4950],"Channel":"Security","ControlIds":["ALM-AUD-014"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-023","Signal":"Usage de privileges sensibles","EventIds":[4673,4674],"Channel":"Security","ControlIds":["ALM-AUD-016"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-024","Signal":"Peripherique externe connecte","EventIds":[6416],"Channel":"Security","ControlIds":["ALM-AUD-022"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-025","Signal":"Acces fichier sur stockage amovible","EventIds":[4663],"Channel":"Security","ControlIds":["ALM-AUD-023"],"Profiles":["PA","PM"]},{"Id":"EVT-027","Signal":"Bloc de script PowerShell 5.1","EventIds":[4104],"Channel":"Microsoft-Windows-PowerShell/Operational","ControlIds":["ALM-PRC-002","ALM-LOG-004"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-028","Signal":"Journalisation de module PowerShell","EventIds":[4103],"Channel":"Microsoft-Windows-PowerShell/Operational","ControlIds":["ALM-LOG-002"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-029","Signal":"Demarrage du moteur Windows PowerShell (version)","EventIds":[400,403,600],"Channel":"Windows PowerShell","ControlIds":["ALM-PRC-006","ALM-LOG-005"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-030","Signal":"Bloc de script PowerShell 7","EventIds":[4104],"Channel":"PowerShellCore/Operational","ControlIds":["ALM-PRC-005"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-031","Signal":"Defender : detection, protection desactivee, configuration modifiee","EventIds":[1116,1117,5001,5007,5013],"Channel":"Microsoft-Windows-Windows Defender/Operational","ControlIds":["ALM-PRT-001"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-032","Signal":"Sessions Bureau a distance","EventIds":[21,22,23,24,25,1149],"Channel":"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational ; Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational","ControlIds":["ALM-NET-009"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-033","Signal":"Usage NTLM (audit)","EventIds":[8001,8002,4020,4021,4024],"Channel":"Microsoft-Windows-NTLM/Operational","ControlIds":["ALM-NET-016","ALM-NET-017"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-036","Signal":"LSA : module non charge en mode protege (audit/blocage)","EventIds":[3065,3066,3033,3063],"Channel":"Microsoft-Windows-CodeIntegrity/Operational","ControlIds":["ALM-HRD-010"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-037","Signal":"Synchronisation horaire","EventIds":[35,37,129,134],"Channel":"System","ControlIds":["ALM-SYS-001"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-038","Signal":"Pare-feu : service et profils","EventIds":[5024,5025,2003],"Channel":"Security ; Microsoft-Windows-Windows Firewall With Advanced Security/Firewall","ControlIds":["ALM-AUD-020","ALM-PRT-002"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-039","Signal":"Demarrage/arret du systeme","EventIds":[4608,4609,6005,6006,6008],"Channel":"Security ; System","ControlIds":["ALM-AUD-017"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-041","Signal":"Attribution de droits utilisateur","EventIds":[4704,4705,4670],"Channel":"Security","ControlIds":["ALM-AUD-013"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-042","Signal":"Historique Planificateur de taches","EventIds":[106,140,141,200,201],"Channel":"Microsoft-Windows-TaskScheduler/Operational","ControlIds":["ALM-LOG-007"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-043","Signal":"Sessions WinRM","EventIds":[91,6],"Channel":"Microsoft-Windows-WinRM/Operational","ControlIds":["ALM-NET-010"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-044","Signal":"Appartenance aux groupes a l'ouverture de session","EventIds":[4627],"Channel":"Security","ControlIds":["ALM-AUD-010"],"Profiles":["PA","PM","SA","SM"]},{"Id":"EVT-045","Signal":"Integrite du code / du sous-systeme de securite","EventIds":[5038,6281,4612],"Channel":"Security","ControlIds":["ALM-AUD-019"],"Profiles":["PA","PM","SA","SM"]}]}
'@
$script:AlmRepoRoot = $null
# ---- 01-Core.ps1
#region ALM Core - constantes, sortie, utilitaires (ASCII uniquement, Windows PowerShell 5.1)
Set-StrictMode -Version 2.0

$script:AlmToolVersion = '0.6.0'
$script:AlmExit = @{
    OK                     = 0   # succes, aucun ecart sur les controles actifs
    ECART                  = 1   # ecart(s) / conflit(s) constates ou plan contenant des changements
    SAUT_PROTEGE           = 2   # refus volontaire (DC, autorite inconnue, cible non validee, plan non approuve, 32 bits...)
    ECHEC_PARTIEL          = 3   # application partielle : au moins un controle en echec
    RESTAURATION_INCOMPLETE = 4  # rollback avec derives ou echecs
    ERREUR                 = 5   # erreur fatale / precondition technique
    VERROU                 = 6   # autre execution en cours
    DELAI                  = 7   # limite de duree atteinte, transaction interrompue proprement
}
$script:AlmMessages = New-Object System.Collections.Generic.List[object]
$script:AlmStart = Get-Date
$script:AlmDeadline = $null
$script:AlmRoot = $null
$script:AlmRunLog = $null
$script:AlmCatalog = $null
$script:AlmCatalogHash = $null
$script:AlmConfigHash = $null
$script:AlmSummaryLines = @()
$script:AlmConfig = $null
$script:AlmCtx = $null
$script:AlmDisk = $null
$script:AlmIdentity = $null
$script:AlmOs = $null
$script:AlmProfile = ''
$script:AlmRoles = $null
$script:AlmWrite = $null
$script:AlmSkipReport = $false
$script:AlmDeployment = $null
$script:AlmExitCode = 5
$script:AlmAuditCache = $null
$script:AlmPlannedLogGrowth = [long]0
$script:AlmBroadSidNames = @{ 'S-1-1-0' = 'Tout le monde'; 'S-1-5-2' = 'Reseau'; 'S-1-5-3' = 'Batch'; 'S-1-5-4' = 'Interactif'; 'S-1-5-6' = 'Service'; 'S-1-5-7' = 'Anonyme'; 'S-1-5-11' = 'Utilisateurs authentifies'; 'S-1-5-13' = 'Utilisateurs Terminal Server'; 'S-1-5-14' = 'Ouverture interactive distante'; 'S-1-5-33' = 'Ecriture restreinte'; 'S-1-5-32-545' = 'Utilisateurs'; 'S-1-5-32-546' = 'Invites'; 'S-1-15-2-1' = 'Applications empaquetees'; 'S-1-15-2-2' = 'Applications empaquetees restreintes' }

function Write-AlmMessage {
    param([ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO', [Parameter(Mandatory)][string]$Text, [string]$ControlId = '')
    $m = [pscustomobject]@{ Time = (Get-Date).ToString('o'); Level = $Level; ControlId = $ControlId; Text = $Text }
    $script:AlmMessages.Add($m)
    if ($script:AlmRunLog) {
        try { Add-Content -LiteralPath $script:AlmRunLog -Value ('{0} [{1}] {2} {3}' -f $m.Time, $Level, $ControlId, $Text) -Encoding UTF8 } catch { }
    }
}

function ConvertTo-AlmAscii {
    # Sortie RG : ASCII strict (accents retires) pour eviter tout probleme de page de code.
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $n = $Text.Normalize([Text.NormalizationForm]::FormD)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $n.ToCharArray()) {
        $cat = [Globalization.CharUnicodeInfo]::GetUnicodeCategory($ch)
        if ($cat -eq [Globalization.UnicodeCategory]::NonSpacingMark) { continue }
        $c = [int]$ch
        if ($c -lt 128) { [void]$sb.Append($ch) }
        elseif (@(0x2018, 0x2019, 0x201A, 0x2032) -contains $c) { [void]$sb.Append("'") }
        elseif (@(0x00AB, 0x00BB, 0x201C, 0x201D, 0x201E) -contains $c) { [void]$sb.Append('"') }
        elseif (@(0x00A0, 0x202F, 0x2009) -contains $c) { [void]$sb.Append(' ') }
        elseif (@(0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2212) -contains $c) { [void]$sb.Append('-') }
        elseif ($c -eq 0x2026) { [void]$sb.Append('...') }
        elseif ($c -eq 0x0153) { [void]$sb.Append('oe') }
        else { [void]$sb.Append('?') }
    }
    return $sb.ToString()
}

function ConvertTo-AlmCanonicalObject {
    # Tri recursif des cles pour un hachage stable.
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in ($InputObject.Keys | ForEach-Object { [string]$_ } | Sort-Object)) { $o[$k] = ConvertTo-AlmCanonicalObject $InputObject[$k] }
        return $o
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($p in ($InputObject.PSObject.Properties | Sort-Object Name)) { $o[$p.Name] = ConvertTo-AlmCanonicalObject $p.Value }
        return $o
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = @()
        foreach ($i in $InputObject) { $list += , (ConvertTo-AlmCanonicalObject $i) }
        return , $list
    }
    return [string]$InputObject
}

function Get-AlmSha256String {
    param([Parameter(Mandatory)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Get-AlmObjectHash {
    param($InputObject)
    $json = ConvertTo-Json -InputObject (ConvertTo-AlmCanonicalObject $InputObject) -Depth 30 -Compress
    return (Get-AlmSha256String -Text $json)
}

function Invoke-AlmNative {
    # Execute un binaire natif, capture stdout/stderr et code retour, avec delai maximal.
    param([Parameter(Mandatory)][string]$FilePath, [string]$Arguments = '', [int]$TimeoutSeconds = 120)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = $null
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
        $outTask = $p.StandardOutput.ReadToEndAsync()
        $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            try { $p.Kill() } catch { }
            return [pscustomobject]@{ ExitCode = -1; StdOut = ''; StdErr = 'Delai depasse'; TimedOut = $true }
        }
        $p.WaitForExit()
        return [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $outTask.Result; StdErr = $errTask.Result; TimedOut = $false }
    } catch {
        return [pscustomobject]@{ ExitCode = -2; StdOut = ''; StdErr = $_.Exception.Message; TimedOut = $false }
    } finally { if ($p) { $p.Dispose() } }
}

function Test-AlmTimeLeft {
    param([int]$MarginSeconds = 20)
    if ($null -eq $script:AlmDeadline) { return $true }
    return ((Get-Date).AddSeconds($MarginSeconds) -lt $script:AlmDeadline)
}

function Set-AlmRestrictedAcl {
    # SYSTEM et Administrateurs (par SID) uniquement, heritage coupe.
    param([Parameter(Mandatory)][string]$Path)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Initialize-AlmStore {
    param([string]$Name = 'Baseline')
    $root = Join-Path $env:ProgramData ('Almeria\' + $Name)
    $created = -not (Test-Path -LiteralPath $root)
    foreach ($d in @($root, "$root\Transactions", "$root\State", "$root\Reports", "$root\Plans", "$root\Snapshots", "$root\Logs", "$root\Tmp")) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    # Proprietaire attendu : SYSTEM ou Administrateurs (protection contre un dossier pre-cree par un utilisateur standard)
    $cur = Get-Acl -LiteralPath $root
    $owner = $cur.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (@('S-1-5-18', 'S-1-5-32-544') -notcontains $owner) {
        try { $cur.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))); Set-Acl -LiteralPath $root -AclObject $cur -ErrorAction Stop }
        catch { throw "Proprietaire inattendu du magasin $root ($owner) et reprise impossible : verification manuelle requise" }
    }
    # ACL appliquee a la racine a chaque execution (corrige une derive eventuelle) ; echec = arret
    try { Set-AlmRestrictedAcl -Path $root } catch { throw ('ACL du magasin non appliquee : ' + $_.Exception.Message) }
    $script:AlmRoot = $root
    $script:AlmRunLog = Join-Path "$root\Logs" ((Get-Date).ToString('yyyyMMdd') + '.log')
    if ($created) { Write-AlmMessage -Text "Magasin cree : $root" }
    return $root
}

function Enter-AlmLock {
    param([string]$Name = 'Global\Almeria.Baseline.Local')
    $script:AlmMutex = New-Object System.Threading.Mutex($false, $Name)
    $script:AlmLockAbandoned = $false
    try { $got = $script:AlmMutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $got = $true; $script:AlmLockAbandoned = $true }
    if ($script:AlmLockAbandoned) { Write-AlmMessage -Level WARN -Text 'Verrou abandonne par une execution precedente interrompue : diagnostic des transactions requis.' }
    return $got
}

function Exit-AlmLock {
    if ($script:AlmMutex) { try { $script:AlmMutex.ReleaseMutex() } catch { }; $script:AlmMutex.Dispose(); $script:AlmMutex = $null }
}

function Write-AlmJournal {
    # Journal transactionnel append-only, ecriture traversante (resiste a une coupure de l'agent).
    param([Parameter(Mandatory)][string]$TxDir, [Parameter(Mandatory)][hashtable]$Record)
    $Record['Time'] = (Get-Date).ToString('o')
    $line = (ConvertTo-Json -InputObject $Record -Depth 20 -Compress) + "`n"
    $bytes = [Text.Encoding]::UTF8.GetBytes($line)
    $path = Join-Path $TxDir 'journal.jsonl'
    $fs = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read, 4096, [System.IO.FileOptions]::WriteThrough)
    try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
}

function Read-AlmJournal {
    param([Parameter(Mandatory)][string]$TxDir)
    $path = Join-Path $TxDir 'journal.jsonl'
    $records = @()
    if (-not (Test-Path -LiteralPath $path)) { return $records }
    foreach ($l in (Get-Content -LiteralPath $path -Encoding UTF8)) {
        if ([string]::IsNullOrWhiteSpace($l)) { continue }
        try { $records += , ($l | ConvertFrom-Json) } catch { Write-AlmMessage -Level WARN -Text "Ligne de journal illisible ignoree (ecriture interrompue) dans $path" }
    }
    return $records
}

function Get-AlmTransactions {
    param([string]$Root = $script:AlmRoot)
    $list = @()
    foreach ($d in (Get-ChildItem -LiteralPath "$Root\Transactions" -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $j = Read-AlmJournal -TxDir $d.FullName
        $begin = @($j | Where-Object { $_.Type -eq 'BEGIN' }) | Select-Object -First 1
        $end = @($j | Where-Object { $_.Type -eq 'END' }) | Select-Object -Last 1
        $status = 'Inconnue'
        if ($end) { $status = $end.Status } elseif ($begin) { $status = 'Interrompue' }
        $list += [pscustomobject]@{ Id = $d.Name; Dir = $d.FullName; Kind = $(if ($begin) { $begin.Kind } else { '' }); Status = $status; Records = $j; Begin = $begin }
    }
    return $list
}

function Read-AlmJsonFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Write-AlmJsonFile {
    param([Parameter(Mandatory)][string]$Path, $InputObject)
    $json = ConvertTo-Json -InputObject $InputObject -Depth 30
    $tmp = "$Path.tmp"
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Get-AlmProp {
    # Lecture tolerante d'une propriete (StrictMode) sur PSCustomObject ou hashtable.
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $Default } }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    return $p.Value
}

function Test-AlmIdMatch {
    # Correspondance d'identifiant de controle avec jokers (ALM-AUD-*).
    param([string]$Id, $Patterns)
    foreach ($p in @($Patterns)) { if ($p -and ($Id -like [string]$p)) { return $true } }
    return $false
}
#endregion
# ---- 02-Context.ps1
#region ALM Context - systeme, identite, autorite de gestion, roles
function Get-AlmOsInfo {
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    [pscustomobject]@{
        Build            = [int](Get-AlmProp $cv 'CurrentBuildNumber' 0)
        Ubr              = [int](Get-AlmProp $cv 'UBR' 0)
        EditionId        = [string](Get-AlmProp $cv 'EditionID' '')
        InstallationType = [string](Get-AlmProp $cv 'InstallationType' '')
        DisplayVersion   = [string](Get-AlmProp $cv 'DisplayVersion' '')
        ProductName      = [string](Get-AlmProp $cv 'ProductName' '')
        Is64BitOs        = [Environment]::Is64BitOperatingSystem
        Is64BitProcess   = [Environment]::Is64BitProcess
        ProcessorArch    = $env:PROCESSOR_ARCHITECTURE
        PsVersion        = $PSVersionTable.PSVersion.ToString()
        Culture          = (Get-Culture).Name
        UiCulture        = (Get-UICulture).Name
        UserSid          = $id.User.Value
        UserName         = $id.Name
        IsSystem         = ($id.User.Value -eq 'S-1-5-18')
        IsAdmin          = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Interactive      = [Environment]::UserInteractive
        LastBoot         = $(try { (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { $null })
    }
}

function Get-AlmMachineIdentity {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $guid = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction Stop).MachineGuid
    $machineSid = ''
    try {
        $u = Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | Select-Object -First 1
        if ($u) { $machineSid = ($u.SID -replace '-\d+$', '') }
    } catch { }
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        MachineGuid  = [string]$guid
        MachineSid   = $machineSid
        PartOfDomain = [bool]$cs.PartOfDomain
        Domain       = [string]$cs.Domain
        DomainRole   = [int]$cs.DomainRole
    }
}

function Test-AlmSameMachine {
    param($Saved, $Current)
    $reasons = @()
    if ((Get-AlmProp $Saved 'MachineGuid') -ne $Current.MachineGuid) { $reasons += 'MachineGuid different' }
    if ((Get-AlmProp $Saved 'ComputerName') -ne $Current.ComputerName) { $reasons += 'Nom d''hote different' }
    if ((Get-AlmProp $Saved 'MachineSid') -and ((Get-AlmProp $Saved 'MachineSid') -ne $Current.MachineSid)) { $reasons += 'SID machine different' }
    if ((Get-AlmProp $Saved 'Domain') -ne $Current.Domain) { $reasons += 'Domaine/groupe de travail different' }
    return $reasons
}

function Read-AlmRegistryPol {
    # Analyse d'un fichier Registry.pol (format PReg v1). Retourne des entrees {Key, ValueName, Type, Delete}.
    param([Parameter(Mandatory)][string]$Path)
    $entries = @()
    if (-not (Test-Path -LiteralPath $Path)) { return $entries }
    $b = [IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 8) { return $entries }
    if ([BitConverter]::ToUInt32($b, 0) -ne 0x67655250 -or [BitConverter]::ToUInt32($b, 4) -ne 1) { throw "Format Registry.pol inattendu : $Path" }
    $pos = 8
    $readStr = {
        param([int]$start)
        $i = $start
        while ($i + 1 -lt $b.Length -and -not ($b[$i] -eq 0 -and $b[$i + 1] -eq 0)) { $i += 2 }
        $s = [Text.Encoding]::Unicode.GetString($b, $start, $i - $start)
        return @($s, ($i + 2))
    }
    while ($pos + 2 -le $b.Length) {
        if ([BitConverter]::ToUInt16($b, $pos) -ne 0x5B) { throw "Registry.pol corrompu (position $pos)" }
        $pos += 2
        $r = & $readStr $pos; $key = $r[0]; $pos = $r[1] + 2           # ';'
        $r = & $readStr $pos; $val = $r[0]; $pos = $r[1] + 2           # ';'
        $type = [BitConverter]::ToUInt32($b, $pos); $pos += 4 + 2      # ';'
        $size = [BitConverter]::ToUInt32($b, $pos); $pos += 4 + 2      # ';'
        $pos += $size
        if ([BitConverter]::ToUInt16($b, $pos) -ne 0x5D) { throw "Registry.pol corrompu (fin d'entree $pos)" }
        $pos += 2
        $del = $false; $name = $val
        if ($val -like '`*`*del.*') { $del = $true; $name = $val.Substring(6) }
        elseif ($val -like '`*`*Delete*') { $del = $true }
        $entries += [pscustomobject]@{ Key = $key; ValueName = $name; Type = $type; Delete = $del }
    }
    return $entries
}

function Get-AlmGpResultAudit {
    # Sous-categories d'audit avance fournies par GPO (gpresult /x, identifiants GUID independants de la langue).
    $res = @{ Available = $false; Settings = @{}; Error = '' }
    $tmp = Join-Path "$script:AlmRoot\Tmp" ('gpresult_' + [guid]::NewGuid().ToString('N') + '.xml')
    $r = Invoke-AlmNative -FilePath "$env:SystemRoot\System32\gpresult.exe" -Arguments "/scope computer /x `"$tmp`" /f" -TimeoutSeconds 120
    try {
        if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $tmp)) { $res.Error = "gpresult code $($r.ExitCode) $($r.StdErr)"; return $res }
        [xml]$x = Get-Content -LiteralPath $tmp -Raw
        foreach ($n in $x.SelectNodes("//*[local-name()='AuditSetting']")) {
            $g = $n.SelectSingleNode("*[local-name()='SubcategoryGuid']")
            $v = $n.SelectSingleNode("*[local-name()='SettingValue']")
            $gpo = $n.SelectSingleNode("*[local-name()='GPO']/*[local-name()='Name']")
            if ($g) { $res.Settings[$g.InnerText.ToUpper()] = [pscustomobject]@{ Value = $(if ($v) { [int]$v.InnerText } else { -1 }); Gpo = $(if ($gpo) { $gpo.InnerText } else { '' }) } }
        }
        $res.Available = $true
    } catch { $res.Error = $_.Exception.Message }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    return $res
}

function Get-AlmAuditCsvGuids {
    param([string[]]$Paths)
    $h = @{}
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            foreach ($row in (Import-Csv -LiteralPath $p)) {
                $g = [string](Get-AlmProp $row 'Subcategory GUID' '')
                if ($g) { $h[$g.ToUpper()] = [pscustomobject]@{ Value = [int](Get-AlmProp $row 'Setting Value' -1); Source = $p } }
            }
        } catch { Write-AlmMessage -Level WARN -Text "audit.csv illisible : $p" }
    }
    return $h
}

function Get-AlmManagementContext {
    param([Parameter(Mandatory)]$Identity, [switch]$SkipGpResult)
    $ctx = [ordered]@{
        PartOfDomain = $Identity.PartOfDomain; Domain = $Identity.Domain; DomainRole = $Identity.DomainRole
        IsDomainController = $false; EntraJoined = $false; MdmEnrolled = $false; MdmProviders = @(); ConfigMgr = $false
        GpoList = @(); RsopAvailable = $false; RsopError = ''; RsopRegistry = @{}; RsopSecurity = @{}
        LocalPol = @{}; LocalPolError = ''; GpResultAvailable = $false; GpResultError = ''; GpoAudit = @{}; AuditCsv = @{}
        ManagedExternally = $false; ContextComplete = $true; Notes = @()
    }
    # Controleur de domaine (DC ou RODC)
    if ($Identity.DomainRole -ge 4) { $ctx.IsDomainController = $true }
    if (Get-Service -Name 'NTDS' -ErrorAction SilentlyContinue) { $ctx.IsDomainController = $true }
    if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters') {
        $dsa = Get-AlmProp (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue) 'DSA Database file'
        if ($dsa) { $ctx.IsDomainController = $true }
    }
    # Entra ID
    $jk = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
    if ((Test-Path -LiteralPath $jk) -and @(Get-ChildItem -LiteralPath $jk -ErrorAction SilentlyContinue).Count -gt 0) { $ctx.EntraJoined = $true }
    # MDM
    foreach ($e in (Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty -LiteralPath $e.PSPath -ErrorAction SilentlyContinue
        $prov = [string](Get-AlmProp $p 'ProviderID' '')
        $state = Get-AlmProp $p 'EnrollmentState' $null
        if ($prov -and $prov -ne '' -and ($null -eq $state -or [int]$state -eq 1)) {
            if ($prov -eq 'MS DM Server' -or $prov -notlike 'WMI_Bridge*') { $ctx.MdmEnrolled = $true; $ctx.MdmProviders += $prov }
        }
    }
    # ConfigMgr
    if (Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue) { $ctx.ConfigMgr = $true }
    # GPO appliquees (liste)
    foreach ($g in (Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\GPO-List' -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty -LiteralPath $g.PSPath -ErrorAction SilentlyContinue
        $ctx.GpoList += [pscustomobject]@{ DisplayName = [string](Get-AlmProp $p 'DisplayName' ''); GPOName = [string](Get-AlmProp $p 'GPOName' ''); Link = [string](Get-AlmProp $p 'Link' ''); FileSysPath = [string](Get-AlmProp $p 'FileSysPath' '') }
    }
    # RSoP (registre et options de securite gagnantes)
    try {
        foreach ($s in (Get-CimInstance -Namespace 'root\rsop\computer' -ClassName 'RSOP_RegistryPolicySetting' -Filter 'precedence=1' -ErrorAction Stop)) {
            if ($s.registryKey) { $ctx.RsopRegistry[(([string]$s.registryKey) + '\' + ([string]$s.valueName)).ToLower()] = [string]$s.GPOID }
        }
        try {
            foreach ($s in (Get-CimInstance -Namespace 'root\rsop\computer' -ClassName 'RSOP_RegistryValue' -Filter 'precedence=1' -ErrorAction Stop)) {
                if ($s.Path) { $ctx.RsopSecurity[([string]$s.Path).ToLower()] = [string]$s.GPOID }
            }
        } catch { $ctx.Notes += 'RSOP_RegistryValue indisponible' }
        $ctx.RsopAvailable = $true
    } catch { $ctx.RsopError = $_.Exception.Message }
    # GPO locale
    try {
        foreach ($e in (Read-AlmRegistryPol -Path "$env:SystemRoot\System32\GroupPolicy\Machine\Registry.pol")) { $ctx.LocalPol[($e.Key + '\' + $e.ValueName).ToLower()] = $e }
    } catch { $ctx.LocalPolError = $_.Exception.Message; $ctx.ContextComplete = $false }
    # Audit avance par GPO
    if (-not $SkipGpResult) {
        $gr = Get-AlmGpResultAudit
        $ctx.GpResultAvailable = $gr.Available; $ctx.GpResultError = $gr.Error; $ctx.GpoAudit = $gr.Settings
    }
    $ctx.AuditCsv = Get-AlmAuditCsvGuids -Paths @("$env:SystemRoot\security\audit\audit.csv", "$env:SystemRoot\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv")
    $ctx.ManagedExternally = ($ctx.PartOfDomain -or $ctx.EntraJoined -or $ctx.MdmEnrolled -or $ctx.ConfigMgr)
    if ($ctx.PartOfDomain -and -not ($ctx.RsopAvailable -and $ctx.GpResultAvailable)) { $ctx.ContextComplete = $false; $ctx.Notes += 'Membre de domaine sans RSoP/gpresult complet : autorite des reglages inconnue' }
    return [pscustomobject]$ctx
}

function Get-AlmServerRoles {
    $r = [ordered]@{ Complete = $false; Roles = @(); Sensitive = @(); Error = ''; Shares = 0; SharedPrinters = 0 }
    try {
        Import-Module ServerManager -ErrorAction Stop
        $f = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed } | ForEach-Object { $_.Name })
        $map = @{ 'RDS-RD-Server' = 'RDS'; 'Hyper-V' = 'HyperV'; 'Print-Server' = 'Print'; 'ADCS-Cert-Authority' = 'ADCS'; 'AD-Domain-Services' = 'ADDS-Binaires'; 'Web-Server' = 'IIS'; 'DHCP' = 'DHCP'; 'DNS' = 'DNS'; 'UpdateServices' = 'WSUS'; 'FS-FileServer' = 'FS-FileServer'; 'NPAS' = 'NPS' }
        foreach ($k in $map.Keys) { if ($f -contains $k) { $r.Roles += $map[$k] } }
        $r.Complete = $true
    } catch { $r.Error = 'ServerManager indisponible : ' + $_.Exception.Message }
    try { $r.Shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special }).Count; if ($r.Shares -gt 0) { $r.Roles += 'FileServer' } } catch { $r.Complete = $false; $r.Error += ' ; Get-SmbShare indisponible' }
    try { $r.SharedPrinters = @(Get-Printer -ErrorAction Stop | Where-Object { $_.Shared }).Count; if ($r.SharedPrinters -gt 0) { $r.Roles += 'PrintShared' } } catch { }
    $svc = @(Get-Service -ErrorAction SilentlyContinue)
    if ($svc | Where-Object { $_.Name -like 'Veeam*' }) { $r.Roles += 'Veeam' }
    if ($svc | Where-Object { $_.Name -eq 'ADSync' }) { $r.Roles += 'EntraConnect' }
    if ($svc | Where-Object { $_.Name -eq 'BrokerAgent' -or $_.DisplayName -like 'Citrix*' }) { $r.Roles += 'Citrix' }
    if ($svc | Where-Object { $_.Name -like 'MSSQL*' }) { $r.Roles += 'SQL' }
    if ($svc | Where-Object { $_.DisplayName -like '*AuthPoint*' }) { $r.Roles += 'AuthPoint' }
    foreach ($s in @('ADCS', 'EntraConnect', 'ADDS-Binaires')) { if ($r.Roles -contains $s) { $r.Sensitive += $s } }
    $r.Roles = @($r.Roles | Select-Object -Unique)
    return [pscustomobject]$r
}

function Get-AlmProfileCode {
    param([string]$BaselineProfile, $Identity)
    if ($BaselineProfile -eq 'Workstation') { if ($Identity.PartOfDomain) { return 'PM' } else { return 'PA' } }
    if ($Identity.PartOfDomain) { return 'SM' } else { return 'SA' }
}
#endregion
# ---- 03-State.ps1
#region ALM State - lecture/ecriture des reglages (registre, audit avance, journaux)
function Split-AlmRegPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^HKLM:\\(.+)$') { throw "Chemin registre non pris en charge (HKLM uniquement) : $Path" }
    return $Matches[1]
}

function Get-AlmRegState {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $sub = Split-AlmRegPath $Path
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sub, $false)
    if ($null -eq $k) { return [pscustomobject]@{ KeyExists = $false; Exists = $false; Type = ''; Value = $null } }
    try {
        $v = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -eq $v) { return [pscustomobject]@{ KeyExists = $true; Exists = $false; Type = ''; Value = $null } }
        $kind = $k.GetValueKind($Name).ToString()
        if ($v -is [array]) { $v = @($v) }
        return [pscustomobject]@{ KeyExists = $true; Exists = $true; Type = $kind; Value = $v }
    } finally { $k.Close() }
}

function Set-AlmRegState {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Type, $Value)
    $sub = Split-AlmRegPath $Path
    $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($sub)
    try {
        $kind = [Microsoft.Win32.RegistryValueKind]$Type
        if ($kind -eq [Microsoft.Win32.RegistryValueKind]::DWord) { $Value = [int]$Value }
        elseif ($kind -eq [Microsoft.Win32.RegistryValueKind]::QWord) { $Value = [long]$Value }
        elseif ($kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) { $Value = [string[]]@($Value) }
        $k.SetValue($Name, $Value, $kind)
    } finally { $k.Close() }
}

function Remove-AlmRegValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [switch]$RemoveKeyIfEmpty)
    $sub = Split-AlmRegPath $Path
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sub, $true)
    if ($null -eq $k) { return }
    $empty = $false
    try { $k.DeleteValue($Name, $false); $empty = ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) } finally { $k.Close() }
    if ($RemoveKeyIfEmpty -and $empty) { [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($sub, $false) }
}

function Test-AlmRegValueEqual {
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }
    if ($A -is [array] -or $B -is [array]) { return ((@($A) -join "`n") -ceq (@($B) -join "`n")) }
    return ([string]$A -eq [string]$B)
}

function Get-AlmAuditPolicyAll {
    # Strategie d'audit effective via auditpol /backup (colonne 'Setting Value' numerique : independant de la langue).
    $tmp = Join-Path "$script:AlmRoot\Tmp" ('auditpol_' + [guid]::NewGuid().ToString('N') + '.csv')
    $r = Invoke-AlmNative -FilePath "$env:SystemRoot\System32\auditpol.exe" -Arguments "/backup /file:`"$tmp`"" -TimeoutSeconds 60
    try {
        if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $tmp)) { throw "auditpol /backup en echec (code $($r.ExitCode)) $($r.StdErr) $($r.StdOut)" }
        $h = @{}
        foreach ($row in (Import-Csv -LiteralPath $tmp)) {
            $g = [string](Get-AlmProp $row 'Subcategory GUID' '')
            if ($g) { $h[$g.ToUpper()] = [int](Get-AlmProp $row 'Setting Value' 0) }
        }
        if ($h.Count -lt 20) { throw "auditpol /backup : contenu inattendu ($($h.Count) sous-categories)" }
        return $h
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

function Set-AlmAuditSubcategory {
    param([Parameter(Mandatory)][string]$Guid, [Parameter(Mandatory)][int]$SettingValue)
    $s = $(if ($SettingValue -band 1) { 'enable' } else { 'disable' })
    $f = $(if ($SettingValue -band 2) { 'enable' } else { 'disable' })
    $r = Invoke-AlmNative -FilePath "$env:SystemRoot\System32\auditpol.exe" -Arguments "/set /subcategory:$Guid /success:$s /failure:$f" -TimeoutSeconds 60
    if ($r.ExitCode -ne 0) { throw "auditpol /set $Guid en echec (code $($r.ExitCode)) $($r.StdErr) $($r.StdOut)" }
}

function ConvertTo-AlmAuditText {
    param([int]$Value)
    switch ($Value) { 0 { 'Aucun' } 1 { 'Succes' } 2 { 'Echec' } 3 { 'Succes+Echec' } default { "Inconnu($Value)" } }
}

function Get-AlmEventLogState {
    param([Parameter(Mandatory)][string]$LogName)
    try {
        $l = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        return [pscustomobject]@{ Exists = $true; MaxSizeBytes = [long]$l.MaximumSizeInBytes; FileSize = [long]$l.FileSize; IsEnabled = [bool]$l.IsEnabled; LogMode = [string]$l.LogMode; RecordCount = $l.RecordCount; Sddl = [string]$l.SecurityDescriptor; LogFilePath = [string]$l.LogFilePath }
    } catch { return [pscustomobject]@{ Exists = $false; MaxSizeBytes = 0; FileSize = 0; IsEnabled = $false; LogMode = ''; RecordCount = 0; Sddl = ''; LogFilePath = '' } }
}

function Get-AlmNormalizedSddl {
    param([string]$Sddl)
    if (-not $Sddl) { return '' }
    return (New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)).GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
}

function ConvertTo-AlmRestrictedSddl {
    # Retire les droits $RemoveMask (lecture 0x1, effacement 0x4) aux principaux larges ; conserve l'ecriture (0x2) et tous les autres ACE.
    param([string]$Sddl, [string[]]$BroadSids, [int]$RemoveMask = 5)
    if (-not $Sddl) { return '' }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    $acl = $sd.DiscretionaryAcl
    for ($i = $acl.Count - 1; $i -ge 0; $i--) {
        $ace = $acl[$i]
        if ($ace -isnot [System.Security.AccessControl.CommonAce] -or $ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
        if ($BroadSids -notcontains $ace.SecurityIdentifier.Value) { continue }
        $m = $ace.AccessMask -band (-bnot $RemoveMask)
        if ($m -eq 0) { $acl.RemoveAce($i) } elseif ($m -ne $ace.AccessMask) { $ace.AccessMask = $m }
    }
    return $sd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
}

function Get-AlmSddlBroadReaders {
    param([string]$Sddl, [string[]]$BroadSids)
    $out = @()
    if (-not $Sddl) { return $out }
    foreach ($ace in (New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)).DiscretionaryAcl) {
        if ($ace -is [System.Security.AccessControl.CommonAce] -and $ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and ($ace.AccessMask -band 1) -and ($BroadSids -contains $ace.SecurityIdentifier.Value)) {
            $sid = $ace.SecurityIdentifier.Value
            $out += $(if ($script:AlmBroadSidNames.ContainsKey($sid)) { $script:AlmBroadSidNames[$sid] } else { $sid })
        }
    }
    return $out
}

function Set-AlmEventLogAccess {
    # Equivalent de : wevtutil sl <canal> /ca:<SDDL> (effet immediat, persistant, sans redemarrage du service).
    param([Parameter(Mandatory)][string]$LogName, [Parameter(Mandatory)][string]$Sddl)
    $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($LogName)
    try { $cfg.SecurityDescriptor = $Sddl; $cfg.SaveChanges() } finally { $cfg.Dispose() }
}

function Set-AlmEventLogConfig {
    param([Parameter(Mandatory)][string]$LogName, [long]$MaxSizeBytes = 0, $Enabled = $null)
    $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($LogName)
    try {
        if ($MaxSizeBytes -gt 0) { $cfg.MaximumSizeInBytes = $MaxSizeBytes }
        if ($null -ne $Enabled) { $cfg.IsEnabled = [bool]$Enabled }
        $cfg.SaveChanges()
    } finally { $cfg.Dispose() }
}
#endregion
# ---- 04-Probes.ps1
#region ALM Probes - constats en lecture seule
function New-AlmProbeResult { param([string]$Status, [string]$Current, [string]$Detail = '') [pscustomobject]@{ Status = $Status; Current = $Current; Detail = $Detail } }

function Test-AlmSddlReadableByUsers {
    # Retourne la liste des SID non privilegies ayant le droit de lecture (0x1) dans le SDDL d'un canal.
    param([string]$Sddl)
    $risky = $script:AlmBroadSidNames
    $found = @()
    if (-not $Sddl) { return $found }
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -is [System.Security.AccessControl.CommonAce] -and $ace.AceQualifier -eq 'AccessAllowed' -and ($ace.AccessMask -band 1)) {
            $sid = $ace.SecurityIdentifier.Value
            if ($risky.ContainsKey($sid)) { $found += "$sid ($($risky[$sid]))" }
        }
    }
    return $found
}

function Get-AlmOldestEventAge {
    param([string]$LogName)
    try {
        $e = Get-WinEvent -LogName $LogName -MaxEvents 1 -Oldest -ErrorAction Stop
        return [math]::Round(((Get-Date) - $e.TimeCreated).TotalDays, 1)
    } catch { return $null }
}

function Invoke-AlmProbe {
    param([Parameter(Mandatory)][string]$Name, $Control)
    $os = $script:AlmOs; $ctx = $script:AlmCtx; $prof = $script:AlmProfile
    try {
        switch ($Name) {
            'None' { return (New-AlmProbeResult 'Exclu' 'Non automatise') }
            'OsSupport' {
                $sup = $script:AlmCatalog.Supported.$prof
                $cur = "$($os.ProductName) $($os.EditionId) $($os.DisplayVersion) build $($os.Build).$($os.Ubr) $($os.InstallationType) $($os.ProcessorArch)"
                $okEd = @($sup.EditionsAccepted) -contains $os.EditionId
                $okBuild = @($sup.Builds | Where-Object { $_.Build -eq $os.Build }).Count -gt 0
                $oos = @((Get-AlmProp $sup 'OutOfSupport' @()) | Where-Object { $_.Build -eq $os.Build })
                if (-not $okEd) { return (New-AlmProbeResult 'Ecart' $cur "Edition non prise en charge par ce script ($($os.EditionId))") }
                if ($oos.Count -gt 0) { return (New-AlmProbeResult 'Ecart' $cur ("Version hors service (fin : " + $oos[0].EndOfServicingPro + ")")) }
                if (-not $okBuild) { return (New-AlmProbeResult 'Ecart' $cur 'Build non reference dans le catalogue') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'Authority' {
                $d = "Domaine=$($ctx.PartOfDomain) ($($ctx.Domain)) Entra=$($ctx.EntraJoined) MDM=$($ctx.MdmEnrolled) ConfigMgr=$($ctx.ConfigMgr) GPO=$(@($ctx.GpoList).Count) RSoP=$($ctx.RsopAvailable) gpresult=$($ctx.GpResultAvailable)"
                return (New-AlmProbeResult 'Constat' $d (@($ctx.Notes) -join ' ; '))
            }
            'DomainController' { if ($ctx.IsDomainController) { return (New-AlmProbeResult 'Ecart' 'Controleur de domaine detecte' 'Refus') } else { return (New-AlmProbeResult 'Conforme' 'Pas un DC') } }
            'ServerRoles' {
                $r = $script:AlmRoles
                if ($null -eq $r) { return (New-AlmProbeResult 'NonApplicable' '-') }
                $st = 'Constat'; if (-not $r.Complete) { $st = 'NonVerifiable' }
                return (New-AlmProbeResult $st ('Roles : ' + (@($r.Roles) -join ', ')) ("Sensibles : " + (@($r.Sensitive) -join ', ') + " " + $r.Error))
            }
            'PendingReboot' {
                $p = @()
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $p += 'CBS' }
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $p += 'WindowsUpdate' }
                if (Get-AlmProp (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue) 'PendingFileRenameOperations') { $p += 'PendingFileRename' }
                if ($p.Count -gt 0) { return (New-AlmProbeResult 'Ecart' ('Redemarrage en attente : ' + ($p -join ', '))) }
                return (New-AlmProbeResult 'Conforme' 'Aucun redemarrage en attente')
            }
            'TimeSync' {
                $tp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop
                $svc = Get-Service W32Time -ErrorAction SilentlyContinue
                $type = [string](Get-AlmProp $tp 'Type' ''); $ntp = [string](Get-AlmProp $tp 'NtpServer' '')
                $cur = "Type=$type NtpServer=$ntp Service=$(if ($svc) { $svc.Status } else { 'absent' })"
                if (-not $svc -or $svc.Status -ne 'Running' -or $type -eq 'NoSync') { return (New-AlmProbeResult 'Ecart' $cur 'Synchronisation non active (source NTP non modifiee par le script)') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'EventLogRetention' {
                $bad = @()
                foreach ($ln in @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')) {
                    $s = Get-AlmEventLogState $ln
                    if ($s.Exists -and $s.LogMode -ne 'Circular') { $bad += "$ln=$($s.LogMode)" }
                }
                $caf = Get-AlmProp (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue) 'CrashOnAuditFail' 0
                if ([int]$caf -ne 0) { $bad += "CrashOnAuditFail=$caf" }
                if ($bad.Count -gt 0) { return (New-AlmProbeResult 'Ecart' ($bad -join ' ; ') 'Retention non circulaire ou arret sur echec d''audit : decision client a confirmer, aucune modification automatique') }
                return (New-AlmProbeResult 'Conforme' 'Retention circulaire, CrashOnAuditFail inactif')
            }
            'SecurityLogAcl' {
                $s = Get-AlmEventLogState 'Security'
                $r = @(Test-AlmSddlReadableByUsers $s.Sddl)
                $readers = @()
                try { $readers = @(Get-LocalGroupMember -SID 'S-1-5-32-573' -ErrorAction Stop | ForEach-Object { $_.Name }) } catch { }
                $cur = 'Lecteurs non privilegies : ' + $(if ($r.Count) { $r -join ', ' } else { 'aucun' }) + ' ; Lecteurs des journaux : ' + $(if ($readers.Count) { $readers -join ', ' } else { 'vide' })
                if ($r.Count -gt 0) { return (New-AlmProbeResult 'Ecart' $cur 'Journal Securite lisible par des non-administrateurs') }
                return (New-AlmProbeResult 'Conforme' $cur 'Verifier que les membres de Lecteurs des journaux sont legitimes (collecteur)')
            }
            'DiskMargin' {
                $d = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $env:SystemDrive + "'") -ErrorAction Stop
                $script:AlmDisk = [pscustomobject]@{ Free = [long]$d.FreeSpace; Size = [long]$d.Size }
                $pct = [math]::Round(100 * $d.FreeSpace / $d.Size, 1)
                $cur = "Libre $([math]::Round($d.FreeSpace / 1GB, 1)) Gio ($pct %)"
                $t = $script:AlmCatalog.Thresholds
                if ($d.FreeSpace -lt [long]$t.DiskFreeMinBytes -or $pct -lt [double]$t.DiskFreeMinPercent) { return (New-AlmProbeResult 'Ecart' $cur 'Marge insuffisante : agrandissement des journaux suspendu') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'LogRetention' {
                $warn = [int]$script:AlmCatalog.Thresholds.RetentionWarnDays.$prof
                $parts = @(); $low = @()
                foreach ($ln in @('Security', 'System', 'Microsoft-Windows-PowerShell/Operational')) {
                    $age = Get-AlmOldestEventAge $ln
                    $parts += "$ln=$age j"
                    if ($null -ne $age -and $age -lt $warn) { $low += $ln }
                }
                if ($low.Count -gt 0) { return (New-AlmProbeResult 'Ecart' ($parts -join ' ; ') ("Retention < $warn j : " + ($low -join ', ') + ' (peut etre normal juste apres installation)')) }
                return (New-AlmProbeResult 'Conforme' ($parts -join ' ; '))
            }
            'Collector' {
                $known = @('winlogbeat', 'nxlog', 'graylog-sidecar', 'collector-sidecar', 'filebeat', 'elastic-agent')
                $found = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $known -contains $_.Name.ToLower() } | ForEach-Object { "$($_.Name)=$($_.Status)" })
                $wef = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -ErrorAction SilentlyContinue
                if ($wef) { $found += 'WEF (abonnement par strategie)' }
                if ($found.Count -eq 0) { return (New-AlmProbeResult 'Ecart' 'Aucun collecteur detecte' 'Journalisation locale uniquement : aucune supervision SOC de ces evenements') }
                return (New-AlmProbeResult 'Constat' ($found -join ' ; ') 'Presence d''agent : la reception cote collecteur reste a prouver')
            }
            'PowerShell7' {
                $paths = @("$env:ProgramFiles\PowerShell\7\pwsh.exe", "$env:ProgramFiles\PowerShell\7-preview\pwsh.exe")
                $p = @($paths | Where-Object { Test-Path -LiteralPath $_ })
                if ($p.Count -eq 0) { return (New-AlmProbeResult 'Conforme' 'PowerShell 7 absent') }
                $ch = Get-AlmEventLogState 'PowerShellCore/Operational'
                $pol = Get-AlmRegState 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging' 'EnableScriptBlockLogging'
                $inh = Get-AlmRegState 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging' 'UseWindowsPowerShellPolicySetting'
                $cur = "pwsh present ; canal PowerShellCore/Operational=$($ch.Exists) ; ScriptBlockLogging=$($pol.Value) ; UseWindowsPowerShellPolicySetting=$($inh.Value)"
                if (-not $ch.Exists) { return (New-AlmProbeResult 'Ecart' $cur 'Fournisseur non enregistre : executer $PSHOME\RegisterManifest.ps1 (action manuelle)') }
                return (New-AlmProbeResult 'Constat' $cur)
            }
            'PowerShellV2' {
                $state = 'inconnu'
                try {
                    if ($os.InstallationType -eq 'Client') { $f = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop; $state = [string]$f.State }
                    else { Import-Module ServerManager -ErrorAction Stop; $f = Get-WindowsFeature -Name 'PowerShell-V2' -ErrorAction Stop; $state = $(if ($f.Installed) { 'Enabled' } else { 'Disabled' }) }
                } catch { $state = 'absent ou non interrogeable' }
                if ($state -eq 'Enabled') { return (New-AlmProbeResult 'Ecart' "Moteur 2.0 : $state" 'Suppression = option manuelle apres verification des dependances') }
                return (New-AlmProbeResult 'Conforme' "Moteur 2.0 : $state")
            }
            'DeviceGuard' {
                $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
                $cur = "VBS=$($dg.VirtualizationBasedSecurityStatus) Services=$(@($dg.SecurityServicesRunning) -join ',') (1=CredentialGuard 2=HVCI)"
                return (New-AlmProbeResult 'Constat' $cur 'Activation hors socle (Pro : Credential Guard non supporte)')
            }
            'Laps' {
                $w = Get-Item 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction SilentlyContinue
                $w2 = Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS' -ErrorAction SilentlyContinue
                $l = Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue
                $cur = "Windows LAPS strategie=$([bool]($w -or $w2)) ; LAPS historique=$([bool]$l)"
                if (-not ($w -or $w2 -or $l)) { return (New-AlmProbeResult 'Ecart' $cur 'Aucune gestion du mot de passe administrateur local detectee') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'LocalAccounts' {
                if ($ctx.IsDomainController) { return (New-AlmProbeResult 'NonApplicable' 'DC') }
                $u = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
                $adm = $u | Where-Object { $_.SID -like '*-500' } | Select-Object -First 1
                $gst = $u | Where-Object { $_.SID -like '*-501' } | Select-Object -First 1
                $n = 'n/a'; try { $n = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop).Count } catch { }
                $cur = "Admin RID500 actif=$(if ($adm) { -not $adm.Disabled } else { 'n/a' }) ; Invite actif=$(if ($gst) { -not $gst.Disabled } else { 'n/a' }) ; membres Administrateurs=$n"
                if ($gst -and -not $gst.Disabled) { return (New-AlmProbeResult 'Ecart' $cur 'Compte Invite actif') }
                return (New-AlmProbeResult 'Constat' $cur)
            }
            'Spooler' {
                $s = Get-Service Spooler -ErrorAction SilentlyContinue
                $roles = @(); if ($script:AlmRoles) { $roles = @($script:AlmRoles.Roles) }
                $need = ($roles -contains 'RDS') -or ($roles -contains 'Print') -or ($roles -contains 'PrintShared') -or ($roles -contains 'Citrix')
                $cur = "Spooler=$(if ($s) { "$($s.Status)/$($s.StartType)" } else { 'absent' }) ; role necessitant l'impression=$need"
                if ($s -and $s.Status -eq 'Running' -and -not $need) { return (New-AlmProbeResult 'Ecart' $cur 'Desactivation = option apres verification (impression d''application, PDF, sauvegarde)') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'Antivirus' {
                $prod = @()
                if ($os.InstallationType -eq 'Client') {
                    try { $prod = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { "$($_.displayName) (etat $($_.productState))" }) } catch { }
                }
                $svc = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'PandaAether*' -or $_.Name -like 'PSANHost*' -or $_.DisplayName -like '*WatchGuard*' -or $_.DisplayName -like '*Panda*' } | ForEach-Object { "$($_.DisplayName)=$($_.Status)" })
                $md = 'n/a'
                try { $m = Get-MpComputerStatus -ErrorAction Stop; $md = "Defender AMRunningMode=$(Get-AlmProp $m 'AMRunningMode' '?') RTP=$($m.RealTimeProtectionEnabled)" } catch { $md = 'Defender non interrogeable' }
                $cur = "SecurityCenter2: $($prod -join ' | ') ; Services EPDR: $($svc -join ' | ') ; $md"
                if ($prod.Count -eq 0 -and $svc.Count -eq 0 -and $md -notmatch 'RTP=True') { return (New-AlmProbeResult 'Ecart' $cur 'Aucune protection active identifiee : verifier (aucune activation automatique)') }
                if ($os.InstallationType -like 'Server*' -and $svc.Count -gt 0 -and $md -match 'RTP=True') { return (New-AlmProbeResult 'Ecart' $cur 'Serveur : Defender reste actif a cote d''EPDR (non desactive automatiquement sur Windows Server ; coexistence non supportee par WatchGuard) : desactivation manuelle documentee') }
                return (New-AlmProbeResult 'Constat' $cur 'Aucune modification de Defender, ASR ou exclusions par le socle')
            }
            'Firewall' {
                $p = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
                $cur = ($p | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ' ; '
                $fwp = @(); if ($os.InstallationType -eq 'Client') { try { $fwp = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop | ForEach-Object { $_.displayName }) } catch { } }
                if ($fwp.Count) { $cur += ' ; pare-feu tiers : ' + ($fwp -join ', ') }
                if (@($p | Where-Object { -not $_.Enabled -or [string]$_.Enabled -eq 'False' }).Count -gt 0) {
                    if ($fwp.Count) { return (New-AlmProbeResult 'Constat' $cur 'Pare-feu Windows desactive au profit d''un pare-feu tiers (EPDR)') }
                    return (New-AlmProbeResult 'Ecart' $cur 'Profil desactive sans pare-feu tiers identifie : activation manuelle apres test des acces (RMM, sauvegarde, metier)') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'Smb1' {
                $srv = 'n/a'; try { $srv = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }
                $feat = 'n/a'
                try { if ($os.InstallationType -eq 'Client') { $feat = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State } else { Import-Module ServerManager -ErrorAction Stop; $feat = (Get-WindowsFeature FS-SMB1 -ErrorAction Stop).Installed } } catch { }
                $cur = "Serveur SMB1=$srv ; fonctionnalite=$feat"
                if ([string]$srv -eq 'True' -or [string]$feat -eq 'Enabled' -or [string]$feat -eq 'True') { return (New-AlmProbeResult 'Ecart' $cur 'Inventorier NAS/multifonctions avant suppression (option)') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'SmbSigning' {
                $s = Get-SmbServerConfiguration -ErrorAction Stop; $c = Get-SmbClientConfiguration -ErrorAction Stop
                $cur = "Serveur Require=$($s.RequireSecuritySignature) ; Client Require=$($c.RequireSecuritySignature)"
                if (-not $s.RequireSecuritySignature -or -not $c.RequireSecuritySignature) { return (New-AlmProbeResult 'Ecart' $cur 'Signature non exigee (normal en entree sur Server 2019/2022/2025 non DC) : option apres tests') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'SmbGuest' {
                $a = Get-AlmRegState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'AllowInsecureGuestAuth'
                $b = Get-AlmRegState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth'
                $cur = "Parametre=$($a.Value) ; Strategie=$($b.Value)"
                if (($a.Exists -and [int]$a.Value -eq 1) -or ($b.Exists -and [int]$b.Value -eq 1)) { return (New-AlmProbeResult 'Ecart' $cur 'Acces invite SMB autorise (dependance NAS probable)') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'Rdp' {
                $d = Get-AlmRegState 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
                $n = Get-AlmRegState 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
                $np = Get-AlmRegState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'UserAuthentication'
                $enabled = ($d.Exists -and [int]$d.Value -eq 0)
                $nla = ($np.Exists -and [int]$np.Value -eq 1) -or (-not $np.Exists -and $n.Exists -and [int]$n.Value -eq 1)
                $cur = "RDP actif=$enabled ; NLA=$nla"
                if ($enabled -and -not $nla) { return (New-AlmProbeResult 'Ecart' $cur 'RDP sans NLA : correction = option (tester clients legers et passerelles)') }
                return (New-AlmProbeResult 'Conforme' $cur)
            }
            'WinRM' {
                $s = Get-Service WinRM -ErrorAction SilentlyContinue
                $b = Get-AlmRegState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic'
                $u = Get-AlmRegState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic'
                $cur = "WinRM=$(if ($s) { "$($s.Status)/$($s.StartType)" } else { 'absent' }) ; AllowBasic(strategie)=$($b.Value) ; AllowUnencrypted(strategie)=$($u.Value)"
                if (($b.Exists -and [int]$b.Value -eq 1) -or ($u.Exists -and [int]$u.Value -eq 1)) { return (New-AlmProbeResult 'Ecart' $cur 'Authentification Basic ou trafic non chiffre autorise') }
                return (New-AlmProbeResult 'Constat' $cur)
            }
            'AccountPolicy' {
                $tmp = Join-Path "$script:AlmRoot\Tmp" ('secedit_' + [guid]::NewGuid().ToString('N') + '.inf')
                $r = Invoke-AlmNative "$env:SystemRoot\System32\secedit.exe" "/export /cfg `"$tmp`" /areas SECURITYPOLICY /quiet" 60
                try {
                    if (-not (Test-Path -LiteralPath $tmp)) { return (New-AlmProbeResult 'NonVerifiable' "secedit /export code $($r.ExitCode)") }
                    $h = @{}; $sec = ''
                    foreach ($l in (Get-Content -LiteralPath $tmp)) { if ($l -match '^\[(.+)\]') { $sec = $Matches[1] } elseif ($sec -eq 'System Access' -and $l -match '^\s*(\w+)\s*=\s*(.+)$') { $h[$Matches[1]] = $Matches[2].Trim() } }
                    $cur = "Seuil verrouillage=$($h['LockoutBadCount']) ; duree=$($h['LockoutDuration']) min ; reinitialisation=$($h['ResetLockoutCount']) min ; longueur min=$($h['MinimumPasswordLength']) ; complexite=$($h['PasswordComplexity'])"
                    if (-not $h['LockoutBadCount'] -or [int]$h['LockoutBadCount'] -eq 0) { return (New-AlmProbeResult 'Ecart' $cur 'Aucun verrouillage des comptes locaux (CIS L1 : 5 tentatives max, 15 min) : risque de force brute RDP/SMB ; modification hors socle') }
                    return (New-AlmProbeResult 'Constat' $cur 'Comptes locaux uniquement (comptes de domaine : strategie du domaine)')
                } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            }
            'ServicesExposed' {
                $names = @('Browser', 'IISADMIN', 'irmon', 'FTPSVC', 'sshd', 'simptcp', 'sacsvr', 'WMSvc', 'W3SVC', 'TlntSvr', 'SNMP')
                $found = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.Name } | ForEach-Object { "$($_.Name)=$($_.Status)/$($_.StartType)" })
                if (@($found | Where-Object { $_ -match 'Running' }).Count) { return (New-AlmProbeResult 'Ecart' ($found -join ' ; ') 'Service reseau optionnel actif : verifier l''usage (desactivation manuelle)') }
                return (New-AlmProbeResult 'Conforme' $(if ($found.Count) { $found -join ' ; ' } else { 'Aucun installe' }))
            }
            default { return (New-AlmProbeResult 'NonVerifiable' "Sonde inconnue : $Name") }
        }
    } catch {
        return (New-AlmProbeResult 'NonVerifiable' 'Erreur de lecture' $_.Exception.Message)
    }
}
#endregion
# ---- 05-Engine.ps1
#region ALM Engine - evaluation, autorite, plan, application, retour arriere, preuves
$script:AlmEval = [ordered]@{}
$script:AlmOwned = @{}
$script:AlmOrigins = @{}

function Get-AlmControl { param([string]$Id) @($script:AlmCatalog.Controls | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1 }

function Test-AlmScopeMatch {
    param($Scope)
    if ($null -eq $Scope) { return $false }
    foreach ($s in @($Scope)) { if ($env:COMPUTERNAME -like [string]$s) { return $true } }
    return $false
}

function Get-AlmDerogation {
    param([string]$Id)
    foreach ($d in @(Get-AlmProp $script:AlmConfig 'Derogations' @())) {
        if ((Test-AlmIdMatch -Id $Id -Patterns (Get-AlmProp $d 'ControlId')) -and (Test-AlmScopeMatch (Get-AlmProp $d 'Scope' '*'))) {
            $exp = $false
            $rev = Get-AlmProp $d 'Review' ''
            if ($rev) { try { $exp = ([datetime]::ParseExact([string]$rev, 'yyyy-MM-dd', $null) -lt (Get-Date).Date) } catch { $exp = $true } }
            return [pscustomobject]@{ Entry = $d; Expired = $exp }
        }
    }
    return $null
}

function Get-AlmEffectiveCategory {
    param($Control)
    $dec = [string](Get-AlmProp $Control.Decision $script:AlmProfile 'NA')
    $smb = Get-AlmProp $Control.Setting 'SocleMinBuild' $null
    if ($dec -eq 'Socle' -and $smb -and $script:AlmOs -and [int]$script:AlmOs.Build -lt [int]$smb) { $dec = 'Option' }
    if ($dec -eq 'Option' -and (Test-AlmIdMatch -Id $Control.Id -Patterns (Get-AlmProp $script:AlmConfig 'EnableOptions' @()))) { $dec = 'OptionActivee' }
    if ($dec -eq 'Socle' -or $dec -eq 'OptionActivee') {
        $der = Get-AlmDerogation -Id $Control.Id
        if ($der) { if ($der.Expired) { return 'DerogationExpiree' } else { return 'Derogation' } }
    }
    return $dec
}

function Get-AlmTargetValue {
    param($Control)
    $s = $Control.Setting
    switch ($Control.Mechanism) {
        'RegistryValue' { return $s.Value }
        'AuditSubcategory' { return ([int]([bool]$s.Success) * 1 + [int]([bool]$s.Failure) * 2) }
        'EventLogEnable' { return $true }
        'EventLogSize' {
            $t = [long](Get-AlmProp $s.MinSizeBytes $script:AlmProfile 0)
            if ($script:AlmRoles) {
                foreach ($p in (Get-AlmProp $s 'RoleOverrides' (New-Object psobject)).PSObject.Properties) { if (@($script:AlmRoles.Roles) -contains $p.Name -and [long]$p.Value -gt $t) { $t = [long]$p.Value } }
            }
            $ov = Get-AlmProp (Get-AlmProp (Get-AlmProp $script:AlmConfig 'LogSizeOverrides') $s.LogName) $script:AlmProfile $null
            if ($ov) { $t = [long]$ov }
            return $t
        }
    }
    return $null
}

function Get-AlmRawState {
    param($Control)
    $s = $Control.Setting
    switch ($Control.Mechanism) {
        'RegistryValue' { $r = Get-AlmRegState -Path $s.Path -Name $s.Name; return [pscustomobject]@{ KeyExists = $r.KeyExists; Exists = $r.Exists; Type = $r.Type; Value = $r.Value } }
        'AuditSubcategory' {
            if ($null -eq $script:AlmAuditCache) { $script:AlmAuditCache = Get-AlmAuditPolicyAll }
            $g = ([string]$s.Guid).ToUpper()
            if (-not $script:AlmAuditCache.ContainsKey($g)) { throw "Sous-categorie absente de auditpol : $g" }
            return [pscustomobject]@{ Value = [int]$script:AlmAuditCache[$g] }
        }
        'EventLogSize' { $l = Get-AlmEventLogState $s.LogName; if (-not $l.Exists) { throw "Canal absent : $($s.LogName)" }; return [pscustomobject]@{ MaxSizeBytes = $l.MaxSizeBytes; FileSize = $l.FileSize } }
        'EventLogEnable' { $l = Get-AlmEventLogState $s.LogName; if (-not $l.Exists) { throw "Canal absent : $($s.LogName)" }; return [pscustomobject]@{ IsEnabled = $l.IsEnabled } }
        'EventLogAccess' {
            $l = Get-AlmEventLogState $s.LogName
            if (-not $l.Exists) { if (Get-AlmProp $s 'OnlyIfKeyExists' $false) { return [pscustomobject]@{ KeyExists = $false; Sddl = '' } }; throw "Canal absent : $($s.LogName)" }
            return [pscustomobject]@{ KeyExists = $true; Sddl = (Get-AlmNormalizedSddl $l.Sddl) }
        }
    }
    throw "Mecanisme sans etat : $($Control.Mechanism)"
}

function Set-AlmRawState {
    param($Control, $Desired)
    $s = $Control.Setting
    switch ($Control.Mechanism) {
        'RegistryValue' {
            if ($Desired.Exists) { Set-AlmRegState -Path $s.Path -Name $s.Name -Type $(if ($Desired.Type) { $Desired.Type } else { $s.Type }) -Value $Desired.Value }
            else { Remove-AlmRegValue -Path $s.Path -Name $s.Name -RemoveKeyIfEmpty:(-not (Get-AlmProp $Desired 'KeyExists' $true)) }
        }
        'AuditSubcategory' { Set-AlmAuditSubcategory -Guid $s.Guid -SettingValue ([int]$Desired.Value); $script:AlmAuditCache = $null }
        'EventLogSize' { Set-AlmEventLogConfig -LogName $s.LogName -MaxSizeBytes ([long]$Desired.MaxSizeBytes) }
        'EventLogEnable' { Set-AlmEventLogConfig -LogName $s.LogName -Enabled ([bool]$Desired.IsEnabled) }
        'EventLogAccess' { if (-not [string]$Desired.Sddl) { throw 'SDDL cible vide : refus' }; Set-AlmEventLogAccess -LogName $s.LogName -Sddl ([string]$Desired.Sddl) }
    }
}

function Test-AlmRawEqual {
    param($Control, $A, $B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    switch ($Control.Mechanism) {
        'RegistryValue' { if ([bool]$A.Exists -ne [bool]$B.Exists) { return $false }; if (-not $A.Exists) { return $true }; return (Test-AlmRegValueEqual $A.Value $B.Value) }
        'AuditSubcategory' { return ([int]$A.Value -eq [int]$B.Value) }
        'EventLogSize' { return ([long]$A.MaxSizeBytes -eq [long]$B.MaxSizeBytes) }
        'EventLogEnable' { return ([bool]$A.IsEnabled -eq [bool]$B.IsEnabled) }
        'EventLogAccess' { return ((Get-AlmNormalizedSddl ([string]$A.Sddl)) -eq (Get-AlmNormalizedSddl ([string]$B.Sddl))) }
    }
    return $false
}

function Format-AlmRaw {
    param($Control, $Raw)
    if ($null -eq $Raw) { return '-' }
    switch ($Control.Mechanism) {
        'RegistryValue' { if ($Raw.Exists) { return "$($Raw.Value) ($($Raw.Type))" } else { return 'absent' } }
        'AuditSubcategory' { return (ConvertTo-AlmAuditText $Raw.Value) }
        'EventLogSize' { return ('{0} Mio' -f [math]::Round([long]$Raw.MaxSizeBytes / 1MB, 1)) }
        'EventLogEnable' { return $(if ($Raw.IsEnabled) { 'active' } else { 'inactif' }) }
        'EventLogAccess' {
            if (-not (Get-AlmProp $Raw 'KeyExists' $true)) { return 'canal absent' }
            $rd = @(Get-AlmSddlBroadReaders ([string]$Raw.Sddl) @($Control.Setting.BroadPrincipals))
            return $(if ($rd.Count) { 'Lecture non privilegiee : ' + ($rd -join ', ') } else { 'Lecture reservee (administrateurs, SYSTEM, Lecteurs des journaux)' })
        }
    }
    return [string]$Raw
}

function New-AlmDesiredRaw {
    param($Control, $Target)
    switch ($Control.Mechanism) {
        'RegistryValue' { return [pscustomobject]@{ KeyExists = $true; Exists = $true; Type = $Control.Setting.Type; Value = $Target } }
        'AuditSubcategory' { return [pscustomobject]@{ Value = [int]$Target } }
        'EventLogSize' { return [pscustomobject]@{ MaxSizeBytes = [long]$Target; FileSize = 0 } }
        'EventLogEnable' { return [pscustomobject]@{ IsEnabled = [bool]$Target } }
        'EventLogAccess' { return [pscustomobject]@{ KeyExists = $true; Sddl = [string]$Target } }
    }
}

function Get-AlmControlAuthority {
    param($Control)
    $ctx = $script:AlmCtx; $s = $Control.Setting
    $gpoLabel = {
        param($gpoId)
        if ($gpoId -eq 'LocalGPO' -or $gpoId -eq 'Local Group Policy') { return 'GPO-Locale' }
        return 'GPO-Domaine'
    }
    switch ($Control.Mechanism) {
        'RegistryValue' {
            $rel = (Split-AlmRegPath $s.Path) + '\' + $s.Name
            if ($s.PolicyKind -eq 'SecurityOption' -and (Get-AlmProp $s 'RsopPath')) {
                $k = ([string]$s.RsopPath).ToLower()
                if ($ctx.RsopSecurity.ContainsKey($k)) { return [pscustomobject]@{ Authority = (& $gpoLabel $ctx.RsopSecurity[$k]); Detail = "RSoP GPO $($ctx.RsopSecurity[$k])" } }
            }
            if ($ctx.RsopRegistry.ContainsKey($rel.ToLower())) { return [pscustomobject]@{ Authority = (& $gpoLabel $ctx.RsopRegistry[$rel.ToLower()]); Detail = "RSoP GPO $($ctx.RsopRegistry[$rel.ToLower()])" } }
            if ($ctx.LocalPol.ContainsKey($rel.ToLower())) { return [pscustomobject]@{ Authority = 'GPO-Locale'; Detail = 'Registry.pol local' } }
            if ($ctx.MdmEnrolled -or $ctx.ConfigMgr) { return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'MDM/ConfigMgr : correspondance CSP non verifiee' } }
            if ($ctx.PartOfDomain -and -not $ctx.RsopAvailable -and -not $script:AlmDeployment) { return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'Membre de domaine sans RSoP' } }
            if ($script:AlmOwned.ContainsKey($Control.Id)) { return [pscustomobject]@{ Authority = 'AlmeriaLocal'; Detail = 'Ecrit par une transaction Almeria' } }
            return [pscustomobject]@{ Authority = 'Aucune'; Detail = '' }
        }
        'AuditSubcategory' {
            $g = ([string]$s.Guid).ToUpper()
            if ($ctx.GpoAudit.ContainsKey($g)) { return [pscustomobject]@{ Authority = 'GPO'; Detail = "gpresult : $($ctx.GpoAudit[$g].Gpo)" } }
            if ($ctx.AuditCsv.ContainsKey($g)) { return [pscustomobject]@{ Authority = 'GPO'; Detail = "audit.csv : $($ctx.AuditCsv[$g].Source)" } }
            if ($ctx.MdmEnrolled -or $ctx.ConfigMgr) { return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'MDM/ConfigMgr' } }
            if ($ctx.PartOfDomain -and -not $ctx.GpResultAvailable -and -not $script:AlmDeployment) { return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'gpresult indisponible sur un membre' } }
            if ($script:AlmOwned.ContainsKey($Control.Id)) { return [pscustomobject]@{ Authority = 'AlmeriaLocal'; Detail = '' } }
            return [pscustomobject]@{ Authority = 'Aucune'; Detail = '' }
        }
        { $_ -eq 'EventLogSize' -or $_ -eq 'EventLogEnable' } {
            $pp = Get-AlmProp $s 'PolicyPath'
            if ($pp) {
                $rel = ((Split-AlmRegPath $pp) + '\MaxSize').ToLower()
                if ($ctx.RsopRegistry.ContainsKey($rel)) { return [pscustomobject]@{ Authority = (& $gpoLabel $ctx.RsopRegistry[$rel]); Detail = 'Strategie EventLog' } }
                if ($ctx.LocalPol.ContainsKey($rel)) { return [pscustomobject]@{ Authority = 'GPO-Locale'; Detail = 'Registry.pol local' } }
                if ((Get-AlmRegState -Path $pp -Name 'MaxSize').Exists) { return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'Valeur de strategie presente, source inconnue' } }
            }
            if ($ctx.MdmEnrolled -or $ctx.ConfigMgr) { return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'MDM/ConfigMgr' } }
            if ($script:AlmOwned.ContainsKey($Control.Id)) { return [pscustomobject]@{ Authority = 'AlmeriaLocal'; Detail = '' } }
            return [pscustomobject]@{ Authority = 'Aucune'; Detail = '' }
        }
        'EventLogAccess' {
            $paths = @(('software\microsoft\windows\currentversion\winevt\channels\' + ([string]$s.LogName).ToLower() + '\channelaccess'), ('system\currentcontrolset\services\eventlog\' + ([string]$s.LogName).ToLower() + '\customsd'))
            foreach ($rel in $paths) {
                if ($ctx.RsopRegistry.ContainsKey($rel)) { return [pscustomobject]@{ Authority = (& $gpoLabel $ctx.RsopRegistry[$rel]); Detail = 'ACL du canal definie par strategie' } }
                if ($ctx.LocalPol.ContainsKey($rel)) { return [pscustomobject]@{ Authority = 'GPO-Locale'; Detail = 'Registry.pol local' } }
            }
            if ($ctx.MdmEnrolled -or $ctx.ConfigMgr) { return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'MDM/ConfigMgr' } }
            if ($ctx.PartOfDomain -and -not $ctx.RsopAvailable -and -not $script:AlmDeployment) { return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'Membre de domaine sans RSoP' } }
            if ($script:AlmOwned.ContainsKey($Control.Id)) { return [pscustomobject]@{ Authority = 'AlmeriaLocal'; Detail = '' } }
            return [pscustomobject]@{ Authority = 'Aucune'; Detail = '' }
        }
    }
    return [pscustomobject]@{ Authority = 'Inconnue'; Detail = 'Mecanisme non gere' }
}

function Test-AlmCompliant {
    param($Control, $Raw, $Target)
    $s = $Control.Setting
    switch ($Control.Mechanism) {
        'RegistryValue' {
            $v = $null; $exists = $Raw.Exists
            if ($exists) { $v = $Raw.Value } elseif ($null -ne (Get-AlmProp $s 'WindowsDefault')) { $v = $s.WindowsDefault; $exists = $true }
            if (-not $exists) { return $false }
            $acc = Get-AlmProp $s 'Accept' $null
            if ($null -ne $acc) { foreach ($a in @($acc)) { if (Test-AlmRegValueEqual $v $a) { return $true } } }
            if ($s.Compare -eq 'GreaterOrEqual') { try { return ([long]$v -ge [long]$Target) } catch { return $false } }
            if ($s.Compare -eq 'LessOrEqual') { try { return ([long]$v -le [long]$Target -and [long]$v -gt 0) } catch { return $false } }
            return (Test-AlmRegValueEqual $v $Target)
        }
        'AuditSubcategory' { return (([int]$Raw.Value -band [int]$Target) -eq [int]$Target) }
        'EventLogSize' { return ([long]$Raw.MaxSizeBytes -ge [long]$Target) }
        'EventLogEnable' { return [bool]$Raw.IsEnabled }
        'EventLogAccess' { return ((Get-AlmNormalizedSddl ([string]$Raw.Sddl)) -eq [string]$Target) }
    }
    return $false
}

function Get-AlmControlCompliantSince {
    # Depuis quand le controle (valeur de registre) est-il en place ? Ecriture Almeria, sinon plus ancien cliche d'une serie continue conforme.
    param([string]$Id)
    $c = Get-AlmControl $Id
    if (-not $c) { return $null }
    $own = $script:AlmOwned[$Id]
    if ($own) { try { return [datetime](Get-AlmProp $own 'Time') } catch { } }
    $since = $null
    foreach ($f in @(Get-ChildItem -LiteralPath "$script:AlmRoot\Snapshots" -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $snap = Read-AlmJsonFile $f.FullName
        $st = Get-AlmProp (Get-AlmProp $snap 'States') $Id $null
        $ok = ($st -and (Get-AlmProp $st 'Exists' $false) -and (Test-AlmRegValueEqual (Get-AlmProp $st 'Value') $c.Setting.Value))
        if ($ok) { if (-not $since) { $since = [datetime](Get-AlmProp $snap 'Time') } } else { $since = $null }
    }
    return $since
}

function Get-AlmNonMicrosoftLsaPackages {
    $known = @('', 'msv1_0', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'negotiate', 'livessp', 'msoidssp', 'credssp')
    $out = @()
    foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig')) {
        foreach ($n in @('Security Packages', 'Authentication Packages')) {
            $v = Get-AlmRegState $k $n
            if (-not $v.Exists) { continue }
            foreach ($p in @($v.Value)) { $x = ([string]$p).Trim().Trim('"').ToLower(); if ($known -notcontains $x -and $out -notcontains $x) { $out += $x } }
        }
    }
    return $out
}

function Test-AlmPrerequisites {
    # Retourne '' si OK, sinon la raison du saut.
    param($Control, $Raw, $Target)
    $id = $Control.Id
    if ($Control.Mechanism -eq 'AuditSubcategory') {
        $sce = $script:AlmEval['ALM-AUD-040']
        if ($sce -and $sce.Status -eq 'Conflit') { return 'Audit classique prioritaire (SCENoApplyLegacyAuditPolicy explicitement a 0)' }
    }
    if ($Control.Mechanism -eq 'EventLogSize') {
        if ($null -eq $script:AlmDisk) { return 'Marge disque non evaluee (ALM-LOG-011)' }
        $delta = [long]$Target - [long]$Raw.MaxSizeBytes
        $free = [long]$script:AlmDisk.Free - [long]$script:AlmPlannedLogGrowth - $delta
        $t = $script:AlmCatalog.Thresholds
        if ($free -lt [long]$t.DiskFreeMinBytes -or (100.0 * $free / [long]$script:AlmDisk.Size) -lt [double]$t.DiskFreeMinPercent) { return 'Marge disque insuffisante apres agrandissement' }
    }
    switch ($id) {
        'ALM-PRC-001' { $e = $script:AlmEval['ALM-LOG-021']; if (-not $e -or $e.Status -ne 'Conforme') { return 'ACL du journal Securite non conforme ou non verifiee (ALM-LOG-021)' } }
        'ALM-PRC-002' { $e = $script:AlmEval['ALM-LOG-031']; if (-not $e -or -not ($e.Status -eq 'Conforme' -or $e.Action -eq 'Set')) { return 'Canal PowerShell/Operational encore lisible par des non-administrateurs : ALM-LOG-031 doit etre conforme ou applique dans la meme transaction' } }
        'ALM-HRD-010' {
            try { $n = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3065, 3066; StartTime = (Get-Date).AddDays(-30) } -ErrorAction Stop).Count } catch { $n = 0; if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { return 'Journal CodeIntegrity illisible' } }
            if ($n -gt 0) { return "$n evenement(s) 3065/3066 sur 30 jours : modules LSA incompatibles" }
        }
        'ALM-NET-016' { if ([int]$Control.Setting.Value -ne 1) { return 'Garde-fou : seule la valeur 1 (audit) est autorisee' } }
        'ALM-HRD-037' {
            $pk = @(Get-AlmNonMicrosoftLsaPackages)
            if ($pk.Count) { return ('SSP/AP non Microsoft enregistre(s) dans LSA : ' + ($pk -join ', ') + ' (le blocage les empecherait de se charger)') }
        }
        { @('ALM-NET-060', 'ALM-NET-061', 'ALM-NET-062') -contains $_ } {
            if ([int]$script:AlmOs.Build -ge [int](Get-AlmProp $Control.Setting 'SocleMinBuild' 0)) {
                $days = [int](Get-AlmProp $script:AlmCatalog.Thresholds 'SmbAuditDays' 30)
                if ($_ -eq 'ALM-NET-062') { $audits = @('ALM-NET-063', 'ALM-NET-064'); $log = 'Microsoft-Windows-SMBServer/Audit' } else { $audits = @('ALM-NET-069', 'ALM-NET-070'); $log = 'Microsoft-Windows-SMBClient/Audit' }
                foreach ($a in $audits) {
                    $since = Get-AlmControlCompliantSince $a
                    if (-not $since -or ((Get-Date) - $since).TotalDays -lt $days) { return "Audit SMB $a actif depuis moins de $days jours : incompatibilites encore inconnues" }
                }
                $n = 0
                try { $n = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = (Get-Date).AddDays(-$days) } -ErrorAction Stop).Count } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { return "Journal $log illisible" } }
                if ($n -gt 0) { return "$n evenement(s) d'incompatibilite SMB dans $log sur $days jours : appareils a remplacer ou derogation" }
            }
        }
        'ALM-NET-002' {
            $dep = Get-AlmRegState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' 'DependOnService'
            if ($dep.Exists -and (@($dep.Value) -contains 'MRxSmb10')) { return 'LanmanWorkstation depend de MRxSmb10 : desactiver le pilote casserait le client SMB. Desinstaller la fonctionnalite SMB1 (action manuelle documentee)' }
        }
        { @('ALM-LOG-010', 'ALM-LOG-011', 'ALM-LOG-012', 'ALM-LOG-013') -contains $_ } {
            $ln = ([string]$Control.Setting.Path).Split('\')[-1]
            $st = Get-AlmEventLogState $ln
            if ($st.Exists -and $st.LogMode -ne 'Circular') { return "Journal $ln en mode $($st.LogMode) : decision existante conservee" }
        }
    }
    return ''
}

function Measure-AlmControl {
    param($Control)
    $cat = Get-AlmEffectiveCategory $Control
    $r = [ordered]@{ Id = $Control.Id; Title = $Control.Title; Domain = $Control.Domain; Mechanism = $Control.Mechanism; Category = $cat; Applicable = $true
        Authority = ''; AuthorityDetail = ''; Current = ''; CurrentRaw = $null; Target = ''; TargetRaw = $null; Status = ''; Action = 'None'; Reason = ''; Restart = $Control.Restart }
    if ($cat -eq 'NA') { $r.Applicable = $false; $r.Status = 'NonApplicable'; return [pscustomobject]$r }
    $appl = Get-AlmProp (Get-AlmProp $Control 'Applicability') $script:AlmProfile $null
    $minB = Get-AlmProp $appl 'MinBuild' $null
    if ($minB -and $script:AlmOs.Build -lt [int]$minB) { $r.Applicable = $false; $r.Status = 'NonApplicable'; $r.Reason = "Build < $minB"; return [pscustomobject]$r }
    if ($Control.Mechanism -eq 'Probe') {
        $p = Invoke-AlmProbe -Name $Control.Setting.Probe -Control $Control
        $r.Status = $p.Status; $r.Current = $p.Current; $r.Reason = $p.Detail
        if ($cat -eq 'Exclu') { $r.Status = 'Exclu' }
        return [pscustomobject]$r
    }
    if ($Control.Mechanism -eq 'Manual') { $r.Status = $(if ($cat -eq 'Exclu') { 'Exclu' } else { 'NonAutomatise' }); $r.Reason = 'Etape manuelle hors scripts'; return [pscustomobject]$r }
    if ((Get-AlmProp $Control.Setting 'NotIfEntraJoined' $false) -and $script:AlmCtx -and $script:AlmCtx.EntraJoined) { $r.Applicable = $false; $r.Status = 'NonApplicable'; $r.Reason = 'Appareil joint ou hybride Entra ID : PKU2U necessaire'; return [pscustomobject]$r }
    $exr = @(Get-AlmProp $Control.Setting 'ExcludeRoles' @())
    if ($exr.Count -and $script:AlmRoles) {
        $hit = @($exr | Where-Object { @($script:AlmRoles.Roles) -contains $_ })
        if ($hit.Count) { $r.Applicable = $false; $r.Status = 'NonApplicable'; $r.Reason = 'Role detecte : ' + ($hit -join ','); return [pscustomobject]$r }
    }
    try { $raw = Get-AlmRawState $Control } catch { $r.Status = 'NonVerifiable'; $r.Reason = $_.Exception.Message; return [pscustomobject]$r }
    if ((Get-AlmProp $Control.Setting 'OnlyIfKeyExists' $false) -and -not $raw.KeyExists) { $r.Applicable = $false; $r.Status = 'NonApplicable'; $r.Reason = 'Composant non installe'; $r.Current = 'absent'; return [pscustomobject]$r }
    $target = Get-AlmTargetValue $Control
    $r.CurrentRaw = $raw; $r.Current = Format-AlmRaw $Control $raw
    if ($Control.Mechanism -eq 'EventLogAccess') { $target = ConvertTo-AlmRestrictedSddl ([string]$raw.Sddl) @($Control.Setting.BroadPrincipals) ([int](Get-AlmProp $Control.Setting 'RemoveRights' 5)) }
    $desiredValue = $target
    if ($Control.Mechanism -eq 'AuditSubcategory') { $desiredValue = ([int]$raw.Value -bor [int]$target) }
    $r.TargetRaw = New-AlmDesiredRaw $Control $desiredValue
    $r.Target = Format-AlmRaw $Control $r.TargetRaw
    $auth = Get-AlmControlAuthority $Control
    $r.Authority = $auth.Authority; $r.AuthorityDetail = $auth.Detail
    $ok = Test-AlmCompliant $Control $raw $target
    if ($cat -eq 'Exclu') { $r.Status = 'Exclu'; return [pscustomobject]$r }
    if ($ok) { $r.Status = 'Conforme'; return [pscustomobject]$r }
    $r.Status = 'Ecart'
    if ($cat -eq 'Audit') { $r.Reason = 'Constat uniquement (aucune ecriture prevue)'; return [pscustomobject]$r }
    if ($cat -eq 'Option') { $r.Reason = 'Option non activee pour ce client'; return [pscustomobject]$r }
    if ($cat -eq 'Derogation') { $r.Status = 'Derogation'; $r.Reason = 'Derogation client approuvee'; return [pscustomobject]$r }
    if ($cat -eq 'DerogationExpiree') { $r.Action = 'Skip'; $r.Reason = 'Derogation expiree : a revoir (aucune application automatique)'; return [pscustomobject]$r }
    # Socle ou option activee : peut-on ecrire ?
    $bypassUnknown = ($auth.Authority -eq 'Inconnue' -and (Get-AlmProp $script:AlmConfig 'BypassAuthority' $false))
    if ($bypassUnknown) { $r.AuthorityDetail = ([string]$r.AuthorityDetail + ' ; contournee (-BypassAuthority)').Trim(' ;') }
    if (@('Aucune', 'AlmeriaLocal') -notcontains $auth.Authority -and -not $bypassUnknown) {
        $r.Action = 'Skip'
        if ($auth.Authority -eq 'Inconnue') { $r.Reason = 'Autorite inconnue : saut protege' } else { $r.Status = 'Conflit'; $r.Reason = "Gere par $($auth.Authority) : pas d'ecriture locale" + $(if (Get-AlmProp $script:AlmConfig 'BypassAuthority' $false) { ' (non contourne : la strategie reecrirait la valeur)' } else { '' }) }
        return [pscustomobject]$r
    }
    $s = $Control.Setting
    if ($Control.Mechanism -eq 'RegistryValue' -and $raw.Exists) {
        $owned = $script:AlmOwned[$Control.Id]
        $isDefault = ($null -ne (Get-AlmProp $s 'WindowsDefault')) -and (Test-AlmRegValueEqual $raw.Value $s.WindowsDefault)
        $override = $false
        foreach ($o in @(Get-AlmProp $script:AlmConfig 'OverrideExisting' @())) { if ((Test-AlmIdMatch $Control.Id (Get-AlmProp $o 'ControlId')) -and (Test-AlmScopeMatch (Get-AlmProp $o 'Scope' '*')) -and (Get-AlmProp $o 'Approver')) { $override = $true } }
        if ($owned -and -not (Test-AlmRegValueEqual $raw.Value (Get-AlmProp $owned.Value 'Value'))) { $r.Status = 'Conflit'; $r.Action = 'Skip'; $r.Reason = 'Valeur modifiee par un tiers apres application Almeria'; return [pscustomobject]$r }
        if (-not $owned -and -not $isDefault -and -not $override) {
            if ($Control.ExistingValuePolicy -eq 'Respect') { $r.Status = 'Conflit'; $r.Action = 'Skip'; $r.Reason = 'Valeur explicite existante (exception presumee) : non ecrasee sans -OverrideExisting'; return [pscustomobject]$r }
            $r.Reason = 'Valeur explicite plus faible remplacee'
        }
    }
    $pre = Test-AlmPrerequisites $Control $raw $target
    if ($pre) { $r.Action = 'Skip'; $r.Reason = $pre; return [pscustomobject]$r }
    if (-not $script:AlmWrite.Permitted) { $r.Action = 'Skip'; $r.Reason = 'Ecriture non autorisee sur cet hote : ' + (@($script:AlmWrite.Reasons) -join ' ; '); return [pscustomobject]$r }
    if ($script:AlmWrite.ControlFilter -and -not (Test-AlmIdMatch $Control.Id $script:AlmWrite.ControlFilter)) { $r.Action = 'Skip'; $r.Reason = 'Controle hors du perimetre de l''exception approuvee'; return [pscustomobject]$r }
    $r.Action = 'Set'
    if ($Control.Mechanism -eq 'EventLogSize') { $script:AlmPlannedLogGrowth += ([long]$r.TargetRaw.MaxSizeBytes - [long]$raw.MaxSizeBytes) }
    return [pscustomobject]$r
}

function Invoke-AlmEvaluation {
    $script:AlmEval = [ordered]@{}
    $script:AlmAuditCache = $null
    $script:AlmPlannedLogGrowth = [long]0
    foreach ($c in @($script:AlmCatalog.Controls | Sort-Object { [int]$_.Order }, Id)) {
        if (-not (Test-AlmTimeLeft -MarginSeconds 30)) { Write-AlmMessage -Level WARN -Text 'Delai : evaluation incomplete'; break }
        $script:AlmEval[$c.Id] = Measure-AlmControl $c
    }
    return $script:AlmEval
}

function New-AlmPlan {
    $actions = @(); $skips = @(); $restart = @()
    foreach ($e in $script:AlmEval.Values) {
        if ($e.Action -eq 'Set') {
            $before = $e.CurrentRaw
            # La taille courante du fichier evolue en continu : exclue du plan (et donc de son empreinte).
            if ($e.Mechanism -eq 'EventLogSize') { $before = [pscustomobject]@{ MaxSizeBytes = [long]$before.MaxSizeBytes; FileSize = 0 } }
            $actions += [pscustomobject]@{ Id = $e.Id; Mechanism = $e.Mechanism; Before = $before; Desired = $e.TargetRaw; BeforeText = $e.Current; TargetText = $e.Target }
            if ($e.Restart -like 'Redemarrage*') { $restart += $e.Id }
        } elseif ($e.Action -eq 'Skip') { $skips += [pscustomobject]@{ Id = $e.Id; Reason = $e.Reason } }
    }
    $core = [ordered]@{ Profile = $script:AlmProfile; ToolVersion = $script:AlmToolVersion; CatalogVersion = $script:AlmCatalog.CatalogVersion; CatalogHash = $script:AlmCatalogHash; ConfigHash = $script:AlmConfigHash; Machine = $script:AlmIdentity; Actions = $actions }
    $hash = Get-AlmObjectHash $core
    return [pscustomobject]@{ Hash = $hash; CreatedAt = (Get-Date).ToString('o'); Core = $core; Skipped = $skips; RestartRequired = $restart }
}

function Save-AlmLedger {
    Write-AlmJsonFile -Path "$script:AlmRoot\State\owned.json" -InputObject $script:AlmOwned
    Write-AlmJsonFile -Path "$script:AlmRoot\State\origins.json" -InputObject $script:AlmOrigins
}

function Import-AlmLedger {
    $script:AlmOwned = @{}; $script:AlmOrigins = @{}
    $o = Read-AlmJsonFile "$script:AlmRoot\State\owned.json"
    if ($o) { foreach ($p in $o.PSObject.Properties) { $script:AlmOwned[$p.Name] = $p.Value } }
    $g = Read-AlmJsonFile "$script:AlmRoot\State\origins.json"
    if ($g) { foreach ($p in $g.PSObject.Properties) { $script:AlmOrigins[$p.Name] = $p.Value } }
}

function Get-AlmManualRollbackLine {
    param($Control, $Before)
    $s = $Control.Setting
    switch ($Control.Mechanism) {
        'RegistryValue' {
            $k = 'HKLM\' + (Split-AlmRegPath $s.Path)
            if ($Before.Exists) { $t = @{ DWord = 'REG_DWORD'; String = 'REG_SZ'; ExpandString = 'REG_EXPAND_SZ'; QWord = 'REG_QWORD'; MultiString = 'REG_MULTI_SZ' }[[string]$Before.Type]; return "reg add `"$k`" /v $($s.Name) /t $t /d $($Before.Value) /f" }
            return "reg delete `"$k`" /v $($s.Name) /f"
        }
        'AuditSubcategory' { $v = [int]$Before.Value; return "auditpol /set /subcategory:$($s.Guid) /success:$(if ($v -band 1) { 'enable' } else { 'disable' }) /failure:$(if ($v -band 2) { 'enable' } else { 'disable' })" }
        'EventLogSize' { return "wevtutil sl `"$($s.LogName)`" /ms:$($Before.MaxSizeBytes)" }
        'EventLogEnable' { return "wevtutil sl `"$($s.LogName)`" /e:$(([string][bool]$Before.IsEnabled).ToLower())" }
        'EventLogAccess' { return "wevtutil sl `"$($s.LogName)`" /ca:`"$($Before.Sddl)`"" }
    }
}

function Invoke-AlmTransaction {
    # Moteur unique : Apply, reprise, restauration d'origine ou de cliche. Chaque action : {Id, Before(attendu), Desired}.
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)]$Actions, [string]$PlanHash = '', [string]$ResumeTxId = '')
    if ($ResumeTxId) { $txId = $ResumeTxId } else { $txId = (Get-Date).ToString('yyyyMMdd-HHmmss') + '-' + $Kind + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6)) }
    $txDir = Join-Path "$script:AlmRoot\Transactions" $txId
    $done = @{}
    if ($ResumeTxId) {
        foreach ($rec in (Read-AlmJournal $txDir)) { if ($rec.Type -eq 'DONE') { $done[$rec.Id] = $true } }
        Write-AlmJournal $txDir @{ Type = 'RESUME'; By = $script:AlmOs.UserName }
    } else {
        New-Item -ItemType Directory -Path $txDir -Force | Out-Null
        Write-AlmJsonFile -Path "$txDir\actions.json" -InputObject @($Actions)
        Write-AlmJournal $txDir @{ Type = 'BEGIN'; Kind = $Kind; Profile = $script:AlmProfile; Machine = $script:AlmIdentity; PlanHash = $PlanHash; ToolVersion = $script:AlmToolVersion; CatalogVersion = $script:AlmCatalog.CatalogVersion; By = $script:AlmOs.UserName }
    }
    $manual = New-Object System.Collections.Generic.List[string]
    $manual.Add("REM Retour arriere manuel - transaction $txId - $($env:COMPUTERNAME) - a executer en administrateur, dans l'ordre")
    $res = [ordered]@{ TxId = $txId; Dir = $txDir; Done = 0; Failed = 0; Skipped = 0; Interrupted = $false; Items = @() }
    foreach ($a in @($Actions)) {
        if ($done.ContainsKey($a.Id)) { continue }
        if (-not (Test-AlmTimeLeft -MarginSeconds 20)) { $res.Interrupted = $true; Write-AlmJournal $txDir @{ Type = 'STOP'; Reason = 'Delai' }; break }
        $c = Get-AlmControl $a.Id
        try { $now = Get-AlmRawState $c } catch { $res.Failed++; Write-AlmJournal $txDir @{ Type = 'FAIL'; Id = $a.Id; Error = "Lecture : $($_.Exception.Message)" }; continue }
        if (-not (Test-AlmRawEqual $c $now $a.Before)) {
            if (Test-AlmRawEqual $c $now $a.Desired) { Write-AlmJournal $txDir @{ Type = 'DONE'; Id = $a.Id; Before = $a.Before; After = $now; Note = 'Deja dans l''etat cible' }; $res.Done++; continue }
            $res.Skipped++; Write-AlmJournal $txDir @{ Type = 'SKIP'; Id = $a.Id; Reason = 'Etat modifie depuis le plan'; Now = $now }
            $res.Items += [pscustomobject]@{ Id = $a.Id; Result = 'Saut'; Detail = 'Etat modifie depuis le plan' }; continue
        }
        Write-AlmJournal $txDir @{ Type = 'BACKUP'; Id = $a.Id; Before = $now }
        if (-not $script:AlmOrigins.ContainsKey($a.Id)) { $script:AlmOrigins[$a.Id] = [pscustomobject]@{ Before = $now; TxId = $txId; Time = (Get-Date).ToString('o') } }
        Write-AlmJournal $txDir @{ Type = 'INTENT'; Id = $a.Id; Desired = $a.Desired }
        try {
            Set-AlmRawState $c $a.Desired
            $after = Get-AlmRawState $c
            if (-not (Test-AlmRawEqual $c $after $a.Desired)) { throw "Relecture differente de la cible ($(Format-AlmRaw $c $after))" }
            Write-AlmJournal $txDir @{ Type = 'DONE'; Id = $a.Id; Before = $now; After = $after }
            $script:AlmOwned[$a.Id] = [pscustomobject]@{ Value = $after; TxId = $txId; Time = (Get-Date).ToString('o') }
            if ($Kind -ne 'Apply' -and (Test-AlmRawEqual $c $after (Get-AlmProp $script:AlmOrigins[$a.Id] 'Before'))) { $script:AlmOwned.Remove($a.Id); $script:AlmOrigins.Remove($a.Id) }
            $manual.Add((Get-AlmManualRollbackLine $c $now))
            $res.Done++; $res.Items += [pscustomobject]@{ Id = $a.Id; Result = 'Applique'; Detail = "$(Format-AlmRaw $c $now) -> $(Format-AlmRaw $c $after)" }
        } catch {
            $err = $_.Exception.Message
            $restored = $false
            try { Set-AlmRawState $c $now; $restored = Test-AlmRawEqual $c (Get-AlmRawState $c) $now } catch { }
            Write-AlmJournal $txDir @{ Type = 'FAIL'; Id = $a.Id; Error = $err; RestoredBefore = $restored }
            $res.Failed++; $res.Items += [pscustomobject]@{ Id = $a.Id; Result = 'Echec'; Detail = "$err ; etat precedent restaure=$restored" }
        }
        Save-AlmLedger
    }
    [IO.File]::AppendAllText("$txDir\ROLLBACK_MANUEL.txt", (($manual -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
    $status = 'Succes'
    if ($res.Interrupted) { $status = 'Interrompue' } elseif ($res.Failed -gt 0) { $status = 'EchecPartiel' }
    if (-not $res.Interrupted) { Write-AlmJournal $txDir @{ Type = 'END'; Status = $status; Done = $res.Done; Failed = $res.Failed; Skipped = $res.Skipped } }
    $res['Status'] = $status
    return [pscustomobject]$res
}

function Invoke-AlmRollbackTransaction {
    param([Parameter(Mandatory)]$Tx)
    $txDir = $Tx.Dir
    $res = [ordered]@{ TxId = $Tx.Id; Restored = 0; Drift = 0; Deferred = 0; Failed = 0; Items = @() }
    $recs = @($Tx.Records)
    $done = @($recs | Where-Object { $_.Type -eq 'DONE' })
    # Ecritures possiblement realisees mais non journalisees (coupure entre INTENT et DONE)
    foreach ($i in @($recs | Where-Object { $_.Type -eq 'INTENT' })) {
        if (-not (@($done | Where-Object { $_.Id -eq $i.Id }).Count)) {
            $bk = @($recs | Where-Object { $_.Type -eq 'BACKUP' -and $_.Id -eq $i.Id }) | Select-Object -Last 1
            if ($bk) { $done += [pscustomobject]@{ Type = 'DONE'; Id = $i.Id; Before = $bk.Before; After = $i.Desired; Note = 'Intent sans confirmation' } }
        }
    }
    [array]::Reverse($done)
    Write-AlmJournal $txDir @{ Type = 'RB_BEGIN'; By = $script:AlmOs.UserName }
    foreach ($d in $done) {
        $c = Get-AlmControl $d.Id
        try {
            $now = Get-AlmRawState $c
            if (Test-AlmRawEqual $c $now $d.Before) { Write-AlmJournal $txDir @{ Type = 'RB_ALREADY'; Id = $d.Id }; $res.Items += [pscustomobject]@{ Id = $d.Id; Result = 'DejaRestaure' }; continue }
            if (-not (Test-AlmRawEqual $c $now $d.After)) {
                $res.Drift++; Write-AlmJournal $txDir @{ Type = 'RB_DRIFT'; Id = $d.Id; Now = $now }
                $res.Items += [pscustomobject]@{ Id = $d.Id; Result = 'Derive'; Detail = "Valeur actuelle $(Format-AlmRaw $c $now) differente de la valeur ecrite : non ecrasee" }; continue
            }
            if ($c.Mechanism -eq 'EventLogSize' -and [long]$now.FileSize -gt [long]$d.Before.MaxSizeBytes) {
                $res.Deferred++; Write-AlmJournal $txDir @{ Type = 'RB_DEFERRED'; Id = $d.Id }
                $res.Items += [pscustomobject]@{ Id = $d.Id; Result = 'Differe'; Detail = 'Fichier de journal plus grand que la taille d''origine : taille conservee (aucun evenement efface)' }; continue
            }
            Set-AlmRawState $c $d.Before
            $after = Get-AlmRawState $c
            if (Test-AlmRawEqual $c $after $d.Before) {
                $res.Restored++; Write-AlmJournal $txDir @{ Type = 'RB_RESTORED'; Id = $d.Id; After = $after }
                $o = $script:AlmOwned[$d.Id]; if ($o -and $o.TxId -eq $Tx.Id) { $script:AlmOwned.Remove($d.Id) }
                $g = $script:AlmOrigins[$d.Id]; if ($g -and (Test-AlmRawEqual $c $after $g.Before)) { $script:AlmOrigins.Remove($d.Id) }
                $res.Items += [pscustomobject]@{ Id = $d.Id; Result = 'Restaure'; Detail = Format-AlmRaw $c $after }
            } else { throw 'Relecture differente apres restauration' }
        } catch {
            $res.Failed++; Write-AlmJournal $txDir @{ Type = 'RB_FAIL'; Id = $d.Id; Error = $_.Exception.Message }
            $res.Items += [pscustomobject]@{ Id = $d.Id; Result = 'Echec'; Detail = $_.Exception.Message }
        }
        Save-AlmLedger
    }
    $st = 'Annulee'; if ($res.Drift -or $res.Failed -or $res.Deferred) { $st = 'AnnulationIncomplete' }
    Write-AlmJournal $txDir @{ Type = 'RB_END'; Status = $st; Restored = $res.Restored; Drift = $res.Drift; Deferred = $res.Deferred; Failed = $res.Failed }
    $res['Status'] = $st
    return [pscustomobject]$res
}

function Get-AlmEventEvidence {
    param([int]$LookbackDays = 7)
    $code = Get-AlmProfileCode $script:AlmProfile $script:AlmIdentity
    $out = @()
    foreach ($ev in @($script:AlmCatalog.Events)) {
        if (@($ev.Profiles) -notcontains $code) { continue }
        $active = $false
        foreach ($cid in @($ev.ControlIds)) { $e = $script:AlmEval[$cid]; if ($e -and @('Socle', 'OptionActivee', 'Audit') -contains $e.Category) { $active = $true } }
        if (-not $active) { continue }
        $last = $null; $state = 'NonObserve'; $detail = ''
        foreach ($ch in (([string]$ev.Channel) -split '\s*;\s*')) {
            try {
                $x = Get-WinEvent -FilterHashtable @{ LogName = $ch; Id = [int[]]@($ev.EventIds); StartTime = (Get-Date).AddDays(-$LookbackDays) } -MaxEvents 1 -ErrorAction Stop
                if ($x) { $last = $x.TimeCreated; $state = 'ObserveLocalement'; $detail = "$ch Id $($x.Id)"; break }
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $state = 'NonVerifiable'; $detail = $_.Exception.Message }
            }
        }
        $out += [pscustomobject]@{ Id = $ev.Id; Signal = $ev.Signal; Channel = $ev.Channel; EventIds = (@($ev.EventIds) -join ','); State = $state; Last = $(if ($last) { $last.ToString('yyyy-MM-dd HH:mm') } else { '' }); Detail = $detail }
    }
    return $out
}

function Invoke-AlmTestEvents {
    # Generation d'evenements sans risque (sur demande explicite : prevenir le SOC avant usage).
    $log = @()
    try { Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/c', 'exit' -WindowStyle Hidden -Wait; $log += '4688 : cmd.exe /c exit' } catch { $log += "4688 : echec $($_.Exception.Message)" }
    $tn = 'ALM-Baseline-TestEvent'
    $r1 = Invoke-AlmNative "$env:SystemRoot\System32\schtasks.exe" "/Create /TN $tn /TR `"cmd.exe /c exit`" /SC ONCE /ST 23:59 /RU SYSTEM /F" 60
    $r2 = Invoke-AlmNative "$env:SystemRoot\System32\schtasks.exe" "/Delete /TN $tn /F" 60
    $log += "4698/4699 : creation=$($r1.ExitCode) suppression=$($r2.ExitCode)"
    $u = 'almtest' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $p = [guid]::NewGuid().ToString('N')
    $r3 = Invoke-AlmNative "$env:SystemRoot\System32\net.exe" "use \\127.0.0.1\IPC$ /user:.\$u $p" 60
    Invoke-AlmNative "$env:SystemRoot\System32\net.exe" 'use \\127.0.0.1\IPC$ /delete /y' 30 | Out-Null
    $log += "4625/4776 : tentative avec compte inexistant (code $($r3.ExitCode), echec attendu)"
    Start-Sleep -Seconds 5
    return $log
}
#endregion
# ---- 06-Main.ps1
#region ALM Main - orchestration des scripts locaux (poste / serveur)
function Split-AlmList {
    # powershell.exe -File transmet "A,B" comme une seule chaine : decoupage explicite
    param($Value)
    return @(@($Value) | Where-Object { $_ } | ForEach-Object { ([string]$_) -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Import-AlmCatalog {
    $catText = $null
    if (Get-Variable -Name ALM_CatalogJson -Scope Script -ErrorAction SilentlyContinue) { $catText = $script:ALM_CatalogJson }
    if (-not $catText) {
        $p = Join-Path ([string]$script:AlmRepoRoot) 'Catalog.json'
        if (-not (Test-Path -LiteralPath $p)) { throw "Catalogue embarque absent" }
        $catText = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)
    }
    $catText = ($catText -replace "`r`n", "`n").TrimEnd()
    $script:AlmCatalogHash = Get-AlmSha256String $catText
    $script:AlmCatalog = $catText | ConvertFrom-Json
}

function New-AlmConfigFromParameters {
    # Les choix client sont passes en parametres de la commande RG (aucun fichier de configuration).
    param([hashtable]$P)
    $cfg = [ordered]@{
        ClientCode = [string]$P['ClientCode']
        EnableOptions = @(Split-AlmList $P['EnableOptions'])
        Derogations = @(Split-AlmList $P['DisableControls'] | ForEach-Object { [pscustomobject]@{ ControlId = $_; Scope = '*'; Approver = 'parametre -DisableControls' } })
        OverrideExisting = @(Split-AlmList $P['OverrideExisting'] | ForEach-Object { [pscustomobject]@{ ControlId = $_; Scope = '*'; Approver = 'parametre -OverrideExisting' } })
        LocalException = @(Split-AlmList $P['LocalException'])
        ConfirmedRoles = @(Split-AlmList $P['ConfirmedRoles'])
        AllowOutOfSupportBuild = [bool]$P['AllowOutOfSupportBuild']
        BypassAuthority = [bool]$P['BypassAuthority']
        MaxPlanAgeHours = $(if ($P['MaxPlanAgeHours']) { [int]$P['MaxPlanAgeHours'] } else { 168 })
    }
    $script:AlmConfig = [pscustomobject]$cfg
    $script:AlmConfigHash = Get-AlmObjectHash $cfg
}

function Get-AlmWritePermission {
    $reasons = @(); $filter = $null
    $exc = @(Get-AlmProp $script:AlmConfig 'LocalException' @())
    $roles = @(Get-AlmProp $script:AlmConfig 'ConfirmedRoles' @())
    $osp = Invoke-AlmProbe -Name 'OsSupport'
    if ($osp.Status -ne 'Conforme' -and -not (Get-AlmProp $script:AlmConfig 'AllowOutOfSupportBuild' $false)) { $reasons += ('Systeme hors perimetre : ' + $osp.Detail) }
    if ($exc.Count) { $filter = $exc }
    $mgdDeploy = ($script:AlmDeployment -and $script:AlmCtx.PartOfDomain -and -not ($script:AlmCtx.EntraJoined -or $script:AlmCtx.MdmEnrolled -or $script:AlmCtx.ConfigMgr))
    if ($mgdDeploy) { Write-AlmMessage -Text 'Deploiement initial : membre de domaine accepte ; les reglages deja geres par une GPO visible (RSoP) sont respectes, les GPO appliquees ensuite restent prioritaires' }
    $bypass = [bool](Get-AlmProp $script:AlmConfig 'BypassAuthority' $false)
    if ($bypass -and $script:AlmCtx.ManagedExternally) { Write-AlmMessage -Level WARN -Text 'BypassAuthority actif sur une machine geree : les reglages d''autorite inconnue (MDM, ConfigMgr, domaine sans RSoP) seront ecrits ; les reglages geres par une GPO detectee restent intacts (la GPO les reecrirait)' }
    if ($script:AlmCtx.ManagedExternally -and -not $exc.Count -and -not $mgdDeploy -and -not $bypass) { $reasons += 'Machine geree (domaine/Entra/MDM/ConfigMgr) : audit par defaut ; ecriture seulement avec -LocalException "<ID>,..." sur cette machine' }
    if ($script:AlmProfile -eq 'Server') {
        $r = $script:AlmRoles
        if (@($r.Sensitive).Count -gt 0) { $reasons += ('Role sensible detecte (' + (@($r.Sensitive) -join ',') + ') : hors perimetre d''application') }
        if (-not $r.Complete) {
            if ($roles.Count) { Write-AlmMessage -Text ('Roles confirmes par parametre : ' + ($roles -join ',')); $script:AlmRoles.Roles = @(@($r.Roles) + $roles | Select-Object -Unique) }
            else { $reasons += 'Detection des roles incomplete : confirmer les roles avec -ConfirmedRoles' }
        }
    }
    return [pscustomobject]@{ Permitted = ($reasons.Count -eq 0); Reasons = $reasons; ControlFilter = $filter }
}

function Get-AlmActiveIssueCount {
    $n = 0
    foreach ($e in $script:AlmEval.Values) {
        if (@('Exclu', 'Option', 'NA') -contains $e.Category) { continue }
        if (@('Ecart', 'Conflit', 'NonVerifiable') -contains $e.Status -or $e.Category -eq 'DerogationExpiree') { $n++ }
    }
    return $n
}

function Save-AlmSnapshot {
    $states = [ordered]@{}
    foreach ($e in $script:AlmEval.Values) { if ($null -ne $e.CurrentRaw) { $states[$e.Id] = $e.CurrentRaw } }
    $id = (Get-Date).ToString('yyyyMMdd-HHmmss')
    Write-AlmJsonFile -Path "$script:AlmRoot\Snapshots\$id.json" -InputObject ([ordered]@{ Id = $id; Time = (Get-Date).ToString('o'); Profile = $script:AlmProfile; Machine = $script:AlmIdentity; States = $states })
    Get-ChildItem -LiteralPath "$script:AlmRoot\Snapshots" -Filter '*.json' | Sort-Object Name -Descending | Select-Object -Skip 20 | Remove-Item -Force -ErrorAction SilentlyContinue
    return $id
}

function Write-AlmReportAndSummary {
    param([string]$Mode, [int]$Code, $Extra)
    $codeName = ($script:AlmExit.GetEnumerator() | Where-Object { $_.Value -eq $Code } | Select-Object -First 1).Name
    $report = [ordered]@{
        Tool = "Almeria Baseline $script:AlmToolVersion"; Profile = $script:AlmProfile; Mode = $Mode; ExitCode = $Code; ExitName = $codeName
        Start = $script:AlmStart.ToString('o'); End = (Get-Date).ToString('o'); CatalogVersion = (Get-AlmProp $script:AlmCatalog 'CatalogVersion'); CatalogHash = $script:AlmCatalogHash; ConfigHash = $script:AlmConfigHash
        ClientCode = (Get-AlmProp $script:AlmConfig 'ClientCode' ''); Os = $script:AlmOs; Machine = $script:AlmIdentity
        Context = $(if ($script:AlmCtx) { [ordered]@{ PartOfDomain = $script:AlmCtx.PartOfDomain; Domain = $script:AlmCtx.Domain; IsDC = $script:AlmCtx.IsDomainController; Entra = $script:AlmCtx.EntraJoined; Mdm = $script:AlmCtx.MdmEnrolled; ConfigMgr = $script:AlmCtx.ConfigMgr; Gpo = $script:AlmCtx.GpoList; Rsop = $script:AlmCtx.RsopAvailable; GpResult = $script:AlmCtx.GpResultAvailable; Notes = $script:AlmCtx.Notes } } else { $null })
        Roles = $script:AlmRoles; Write = $script:AlmWrite
        Controls = @($script:AlmEval.Values | ForEach-Object { $_ | Select-Object Id, Title, Domain, Mechanism, Category, Applicable, Authority, AuthorityDetail, Current, Target, Status, Action, Reason, Restart, CurrentRaw })
        Extra = $Extra; Messages = $script:AlmMessages
    }
    $file = ''
    if ($script:AlmRoot) {
        $file = Join-Path "$script:AlmRoot\Reports" ((Get-Date).ToString('yyyyMMdd-HHmmss') + "_$($script:AlmProfile)_$Mode.json")
        try {
            Write-AlmJsonFile -Path $file -InputObject $report
            Copy-Item -LiteralPath $file -Destination (Join-Path "$script:AlmRoot\Reports" "latest_$($script:AlmProfile)_$Mode.json") -Force
            Get-ChildItem -LiteralPath "$script:AlmRoot\Reports" -Filter '2*.json' | Sort-Object Name -Descending | Select-Object -Skip 60 | Remove-Item -Force -ErrorAction SilentlyContinue
        } catch { $file = 'ECHEC ecriture rapport : ' + $_.Exception.Message }
    }
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("ALM-BASELINE $script:AlmToolVersion | $($script:AlmProfile) | Mode=$Mode | Code=$Code ($codeName) | Catalogue=$(Get-AlmProp $script:AlmCatalog 'CatalogVersion' '?')")
    if ($script:AlmOs) { $L.Add("Hote=$env:COMPUTERNAME | $($script:AlmOs.EditionId) $($script:AlmOs.DisplayVersion) build $($script:AlmOs.Build).$($script:AlmOs.Ubr) | Identite=$($script:AlmOs.UserName) | 64bits=$($script:AlmOs.Is64BitProcess)") }
    if ($script:AlmCtx) { $L.Add("Autorite: Domaine=$($script:AlmCtx.PartOfDomain) Entra=$($script:AlmCtx.EntraJoined) MDM=$($script:AlmCtx.MdmEnrolled) RSoP=$($script:AlmCtx.RsopAvailable) | Ecriture=$(if ($script:AlmWrite) { $script:AlmWrite.Permitted } else { 'n/a' })") }
    if ($script:AlmEval.Count -gt 0) {
        $vals = @($script:AlmEval.Values)
        $socle = @($vals | Where-Object { @('Socle', 'OptionActivee') -contains $_.Category })
        $grp = $socle | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
        $L.Add("Socle+options actives: $($socle.Count) controles | " + ($grp -join ' '))
        foreach ($st in @('Ecart', 'Conflit', 'NonVerifiable')) {
            $ids = @($vals | Where-Object { $_.Status -eq $st -and @('Exclu', 'Option', 'NA') -notcontains $_.Category } | ForEach-Object { $_.Id })
            if ($ids.Count) { $L.Add("${st}: " + (($ids | Select-Object -First 15) -join ',') + $(if ($ids.Count -gt 15) { " (+$($ids.Count - 15))" } else { '' })) }
        }
        $act = @($vals | Where-Object { $_.Action -eq 'Set' } | ForEach-Object { $_.Id })
        if ($act.Count -and $Mode -ne 'Apply') { $L.Add('Changements possibles: ' + (($act | Select-Object -First 15) -join ',')) }
    }
    $pl = $null; if ($Extra -and $Extra.Contains('Plan')) { $pl = $Extra['Plan'] }
    if ($Extra -and $Extra.Contains('Transaction') -and $Extra['Transaction']) { $tx = $Extra['Transaction']; $L.Add("Transaction: $(Get-AlmProp $tx 'TxId' '?') | statut=$(Get-AlmProp $tx 'Status' '?') | reussis=$(Get-AlmProp $tx 'Done' 0) echecs=$(Get-AlmProp $tx 'Failed' 0) | annulation : -Mode Rollback -TransactionId $(Get-AlmProp $tx 'TxId' '?')") }
    if ($Extra -and $Extra.Contains('SnapshotId') -and $Extra['SnapshotId']) { $L.Add("Cliche: $($Extra['SnapshotId'])") }
    if ($pl) { $L.Add("Plan: empreinte=$($pl.Hash) | changements=$(@(@(Get-AlmProp $pl.Core 'Ops' @()) + @(Get-AlmProp $pl.Core 'Actions' @()) | Where-Object { $_ }).Count) | Apply: -ApprovedPlanHash $($pl.Hash.Substring(0, 16))") }
    if ((Get-AlmProp $script:AlmConfig 'BypassAuthority' $false) -and $script:AlmCtx -and $script:AlmCtx.ManagedExternally) { $L.Add('ATTENTION: -BypassAuthority actif : reglages d''autorite inconnue ecrits malgre MDM/domaine ; reglages GPO detectes non modifies') }
    if ($script:AlmWrite -and -not $script:AlmWrite.Permitted -and @('Plan', 'Apply') -contains $Mode) { $L.Add('Ecriture refusee: ' + (@($script:AlmWrite.Reasons) -join ' ; ')) }
    foreach ($m in @($script:AlmMessages | Where-Object { $_.Level -eq 'ERROR' -or $_.Level -eq 'WARN' } | Select-Object -Last 6)) { $L.Add("$($m.Level): $($m.ControlId) $($m.Text)") }
    $L.Add("Rapport: $file")
    $script:AlmSummaryLines = @($L | ForEach-Object { ConvertTo-AlmAscii $_ })
}

function Test-AlmDeploymentContext {
    # Mode Deploy : reserve a une sequence de taches (MDT) sur un poste fraichement installe, jamais gere auparavant par le socle.
    param([hashtable]$P)
    $r = [ordered]@{ Ok = $false; Reasons = @(); TsLogPath = ''; OsAgeHours = $null; TaskSequence = $false }
    try { $ts = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop; $r.TaskSequence = $true
        foreach ($v in @('LogPath', '_SMSTSLogPath')) { $x = [string]$ts.Value($v); if ($x -and (Test-Path -LiteralPath $x)) { $r.TsLogPath = $x; break } }
    } catch { $r.Reasons += 'Aucune sequence de taches detectee (Microsoft.SMS.TSEnvironment) : le mode Deploy est reserve au deploiement initial MDT' }
    try { $inst = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).InstallDate; $r.OsAgeHours = [math]::Round(((Get-Date) - $inst).TotalHours, 1) } catch { $r.Reasons += 'Date d''installation du systeme illisible' }
    $max = $(if ($P['MaxOsAgeHours']) { [int]$P['MaxOsAgeHours'] } else { 72 })
    if ($null -ne $r.OsAgeHours -and $r.OsAgeHours -gt $max) { $r.Reasons += "Systeme installe depuis $($r.OsAgeHours) h (> $max h) : poste deja en service, utiliser Plan/Apply via RG" }
    $root = Join-Path $env:ProgramData 'Almeria\Baseline\Transactions'
    if (Test-Path -LiteralPath $root) {
        foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) { if ($d.Name -notlike '*-Deploy-*') { $r.Reasons += "Transaction anterieure hors deploiement ($($d.Name)) : poste deja gere par le socle"; break } }
    }
    $r.Ok = ($r.Reasons.Count -eq 0)
    return [pscustomobject]$r
}

function Copy-AlmReportToTaskSequenceLog {
    if (-not $script:AlmDeployment -or -not $script:AlmDeployment.TsLogPath) { return }
    try {
        $dst = $script:AlmDeployment.TsLogPath
        [IO.File]::WriteAllLines((Join-Path $dst 'Almeria_Baseline_Deploy.log'), [string[]]@($script:AlmSummaryLines + @($script:AlmMessages | ForEach-Object { ConvertTo-AlmAscii ("[$($_.Level)] $($_.ControlId) $($_.Text)") })), (New-Object Text.UTF8Encoding($false)))
        $rep = Join-Path "$script:AlmRoot\Reports" "latest_$($script:AlmProfile)_Deploy.json"
        if ($script:AlmRoot -and (Test-Path -LiteralPath $rep)) { Copy-Item -LiteralPath $rep -Destination (Join-Path $dst 'Almeria_Baseline_Deploy.json') -Force }
    } catch { }
}

function Invoke-AlmDiagnostic {
    # Mode Diagnostic : AUCUNE ecriture (pas de magasin, pas de rapport). Mesure le contexte reel de l'agent RG.
    param([hashtable]$P)
    $o = $script:AlmOs
    $selfCmd = ''; $parentCmd = ''
    try {
        $self = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
        $selfCmd = [string]$self.CommandLine
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($self.ParentProcessId)" -ErrorAction Stop
        $parentCmd = "$($parent.Name) : $($parent.CommandLine)"
    } catch { $parentCmd = 'non lisible' }
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("ALM-DIAG $($script:AlmToolVersion) | $($script:AlmProfile) | aucune ecriture")
    $L.Add("Identite=$($o.UserName) Sid=$($o.UserSid) SYSTEM=$($o.IsSystem) Admin=$($o.IsAdmin)")
    $L.Add("Processus64=$($o.Is64BitProcess) Os64=$($o.Is64BitOs) PROCESSOR_ARCHITECTURE=$env:PROCESSOR_ARCHITECTURE PROCESSOR_ARCHITEW6432=$env:PROCESSOR_ARCHITEW6432")
    $L.Add("PS=$($o.PsVersion) Culture=$($o.Culture)/$($o.UiCulture) Interactif=$($o.Interactive) LanguageMode=$($ExecutionContext.SessionState.LanguageMode)")
    $L.Add("OS=$($o.EditionId) $($o.DisplayVersion) build $($o.Build).$($o.Ubr) $($o.InstallationType)")
    $L.Add("Script=$PSCommandPath Repertoire=$((Get-Location).Path) TEMP=$env:TEMP Profil=$env:USERPROFILE")
    $L.Add("LigneCommande=$selfCmd")
    $L.Add("Parent=$parentCmd")
    $L.Add('PolitiquesExecution=' + ((Get-ExecutionPolicy -List | ForEach-Object { "$($_.Scope):$($_.ExecutionPolicy)" }) -join ';'))
    $L.Add('ParametresRecus=' + (($P.Keys | Sort-Object | Where-Object { $null -ne $P[$_] -and [string]$P[$_] -ne '' -and [string]$P[$_] -ne 'False' } | ForEach-Object { "$_=$($P[$_])" }) -join ' ; '))
    $L.Add('ListeEnableOptions=' + ((Split-AlmList $P.EnableOptions) -join '|'))
    for ($i = 1; $i -le [int]$P.DiagOutputLines; $i++) { $L.Add(('ALM-DIAG LIGNE {0:D5} ' -f $i) + ('x' * 60)) }
    if ([int]$P.DiagSleepSeconds -gt 0) { Start-Sleep -Seconds ([int]$P.DiagSleepSeconds) }
    [Console]::Error.WriteLine('ALM-DIAG STDERR : ligne ecrite sur la sortie d''erreur')
    $L.Add("ALM-DIAG FIN code=$([int]$P.DiagExitCode)")
    $script:AlmSummaryLines = @($L | ForEach-Object { ConvertTo-AlmAscii $_ })
    $script:AlmSkipReport = $true
}

function Invoke-AlmLocalMain {
    # Ne produit aucune sortie : renseigne $script:AlmSummaryLines et $script:AlmExitCode.
    param([Parameter(Mandatory)][ValidateSet('Workstation', 'Server')][string]$BaselineProfile, [Parameter(Mandatory)][hashtable]$P)
    $Mode = $P.Mode
    $code = $script:AlmExit.ERREUR
    $extra = [ordered]@{}
    $locked = $false
    $script:AlmProfile = $BaselineProfile
    $script:AlmEval = [ordered]@{}
    $script:AlmWrite = $null; $script:AlmRoles = $null; $script:AlmCtx = $null; $script:AlmIdentity = $null; $script:AlmDisk = $null
    $script:AlmCatalog = $null; $script:AlmConfig = New-Object psobject; $script:AlmSkipReport = $false
    try {
        $script:AlmDeadline = $script:AlmStart.AddSeconds([int]$P.MaxDurationSeconds)
        $script:AlmOs = Get-AlmOsInfo
        if ($Mode -eq 'Diagnostic') { Invoke-AlmDiagnostic -P $P; $code = [int]$P.DiagExitCode; return }
        if (-not $script:AlmOs.Is64BitProcess) { Write-AlmMessage -Level ERROR -Text 'Processus 32 bits : activer RunAs64Bits dans RG System (aucune action realisee)'; $code = $script:AlmExit.SAUT_PROTEGE; return }
        if (-not ($script:AlmOs.IsAdmin -or $script:AlmOs.IsSystem)) { Write-AlmMessage -Level ERROR -Text 'Droits administrateur ou SYSTEM requis'; $code = $script:AlmExit.SAUT_PROTEGE; return }
        Initialize-AlmStore | Out-Null
        if (-not (Enter-AlmLock)) { Write-AlmMessage -Level ERROR -Text 'Une autre execution du socle est en cours'; $code = $script:AlmExit.VERROU; return }
        $locked = $true
        Import-AlmCatalog
        New-AlmConfigFromParameters -P $P
        $script:AlmIdentity = Get-AlmMachineIdentity
        $isServerOs = ($script:AlmOs.InstallationType -like 'Server*')
        if ($BaselineProfile -eq 'Workstation' -and $isServerOs) { Write-AlmMessage -Level ERROR -Text 'Systeme serveur : utiliser Invoke-ServerBaseline.ps1'; $code = $script:AlmExit.SAUT_PROTEGE; return }
        if ($BaselineProfile -eq 'Server' -and -not $isServerOs) { Write-AlmMessage -Level ERROR -Text 'Systeme client : utiliser Invoke-WorkstationBaseline.ps1'; $code = $script:AlmExit.SAUT_PROTEGE; return }
        $script:AlmCtx = Get-AlmManagementContext -Identity $script:AlmIdentity
        if ($script:AlmCtx.IsDomainController) {
            Write-AlmMessage -Level ERROR -Text 'Controleur de domaine (DC/RODC) detecte : refus de toute execution du socle'
            $script:AlmEval['ALM-SYS-003'] = [pscustomobject]@{ Id = 'ALM-SYS-003'; Title = 'Refus des controleurs de domaine'; Domain = 'Systeme'; Mechanism = 'Probe'; Category = 'Audit'; Applicable = $true; Authority = ''; AuthorityDetail = ''; Current = 'DC detecte'; Target = ''; Status = 'Ecart'; Action = 'None'; Reason = 'Refus'; Restart = ''; CurrentRaw = $null; TargetRaw = $null }
            $code = $script:AlmExit.SAUT_PROTEGE; return
        }
        if ($BaselineProfile -eq 'Server') { $script:AlmRoles = Get-AlmServerRoles }
        Import-AlmLedger
        if ($Mode -eq 'Deploy') {
            if ($BaselineProfile -ne 'Workstation') { Write-AlmMessage -Level ERROR -Text 'Mode Deploy reserve aux postes de travail'; $code = $script:AlmExit.SAUT_PROTEGE; return }
            $dep = Test-AlmDeploymentContext -P $P
            $extra['Deployment'] = $dep
            if (-not $dep.Ok) { foreach ($x in $dep.Reasons) { Write-AlmMessage -Level ERROR -Text $x }; $code = $script:AlmExit.SAUT_PROTEGE; return }
            $script:AlmDeployment = $dep
            Write-AlmMessage -Text "Deploiement initial : sequence de taches detectee, systeme installe depuis $($dep.OsAgeHours) h ; approbation = parametres figes de l'etape de la sequence"
        }
        $script:AlmWrite = Get-AlmWritePermission
        $interrupted = @(Get-AlmTransactions | Where-Object { $_.Status -eq 'Interrompue' -and -not @($_.Records | Where-Object { $_.Type -eq 'RB_END' }).Count })
        if ($interrupted.Count) { Write-AlmMessage -Level WARN -Text ('Transaction(s) interrompue(s) : ' + (($interrupted | ForEach-Object { $_.Id }) -join ', ')) }
        $extra['Transactions'] = @(Get-AlmTransactions | Select-Object -Last 10 | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Kind = $_.Kind; Status = $_.Status } })

        switch ($Mode) {
            'Audit' {
                Invoke-AlmEvaluation | Out-Null
                $extra['SnapshotId'] = Save-AlmSnapshot
                Write-AlmMessage -Text "Cliche d'etat enregistre : $($extra['SnapshotId'])"
                $code = $(if ((Get-AlmActiveIssueCount) -gt 0 -or $interrupted.Count) { $script:AlmExit.ECART } else { $script:AlmExit.OK })
            }
            'Plan' {
                Invoke-AlmEvaluation | Out-Null
                $plan = New-AlmPlan
                Write-AlmJsonFile -Path "$script:AlmRoot\Plans\latest_$BaselineProfile.json" -InputObject $plan
                Write-AlmJsonFile -Path "$script:AlmRoot\Plans\$($plan.Hash.Substring(0, 16)).json" -InputObject $plan
                $extra['Plan'] = $plan
                Write-AlmMessage -Text ("Plan $($plan.Hash) : $(@($plan.Core.Actions).Count) changement(s) ; redemarrage requis pour : " + (@($plan.RestartRequired) -join ','))
                $code = $(if (@($plan.Core.Actions).Count -gt 0 -or (Get-AlmActiveIssueCount) -gt 0) { $script:AlmExit.ECART } else { $script:AlmExit.OK })
            }
            'Apply' {
                if ($P.ResumeTransactionId) {
                    $tx = @(Get-AlmTransactions | Where-Object { $_.Id -eq $P.ResumeTransactionId }) | Select-Object -First 1
                    if (-not $tx -or $tx.Status -ne 'Interrompue') { Write-AlmMessage -Level ERROR -Text 'Transaction a reprendre introuvable ou non interrompue'; $code = $script:AlmExit.SAUT_PROTEGE; return }
                    $diff = Test-AlmSameMachine $tx.Begin.Machine $script:AlmIdentity
                    if ($diff.Count) { Write-AlmMessage -Level ERROR -Text ('Transaction d''une autre machine : ' + ($diff -join ', ')); $code = $script:AlmExit.SAUT_PROTEGE; return }
                    if (-not $script:AlmWrite.Permitted) { Write-AlmMessage -Level ERROR -Text 'Ecriture non autorisee sur cet hote'; $code = $script:AlmExit.SAUT_PROTEGE; return }
                    $actions = @(Read-AlmJsonFile "$($tx.Dir)\actions.json")
                    $res = Invoke-AlmTransaction -Kind 'Apply' -Actions $actions -ResumeTxId $tx.Id
                } else {
                    if ($interrupted.Count) { Write-AlmMessage -Level ERROR -Text 'Transaction interrompue presente : reprendre (-ResumeTransactionId) ou annuler (-Mode Rollback -TransactionId) avant toute nouvelle application'; $code = $script:AlmExit.SAUT_PROTEGE; return }
                    if (-not $script:AlmWrite.Permitted) { Invoke-AlmEvaluation | Out-Null; Write-AlmMessage -Level ERROR -Text 'Ecriture non autorisee sur cet hote'; $code = $script:AlmExit.SAUT_PROTEGE; return }
                    Invoke-AlmEvaluation | Out-Null
                    $plan = New-AlmPlan
                    $approved = $false
                    if ($P.ApprovedPlanHash) { $ah = ([string]$P.ApprovedPlanHash).Trim().ToLower(); $approved = ($ah.Length -ge 16 -and $plan.Hash.ToLower().StartsWith($ah)); if (-not $approved) { Write-AlmMessage -Level ERROR -Text "Plan recalcule ($($plan.Hash)) different du plan approuve : etat ou cible modifies" } }
                    elseif ($P.ApproveStoredPlan) {
                        $stored = Read-AlmJsonFile "$script:AlmRoot\Plans\latest_$BaselineProfile.json"
                        $maxAge = [int](Get-AlmProp $script:AlmConfig 'MaxPlanAgeHours' 168)
                        if (-not $stored) { Write-AlmMessage -Level ERROR -Text 'Aucun plan enregistre : executer -Mode Plan puis le faire valider' }
                        elseif (((Get-Date) - [datetime]$stored.CreatedAt).TotalHours -gt $maxAge) { Write-AlmMessage -Level ERROR -Text "Plan enregistre trop ancien (> $maxAge h)" }
                        elseif ($stored.Hash -ne $plan.Hash) { Write-AlmMessage -Level ERROR -Text 'Plan enregistre different du plan recalcule : etat ou cible modifies depuis la validation' }
                        else { $approved = $true }
                    } else { Write-AlmMessage -Level ERROR -Text 'Apply exige -ApproveStoredPlan ou -ApprovedPlanHash' }
                    if (-not $approved) { $code = $script:AlmExit.SAUT_PROTEGE; return }
                    if (@($plan.Core.Actions).Count -eq 0) { Write-AlmMessage -Text 'Aucun changement a appliquer'; $code = $(if ((Get-AlmActiveIssueCount) -gt 0) { $script:AlmExit.ECART } else { $script:AlmExit.OK }); return }
                    $res = Invoke-AlmTransaction -Kind 'Apply' -Actions $plan.Core.Actions -PlanHash $plan.Hash
                    if (@($plan.RestartRequired).Count) { Write-AlmMessage -Level WARN -Text ('Redemarrage necessaire (non declenche) pour : ' + (@($plan.RestartRequired) -join ',')) }
                }
                $extra['Transaction'] = $res
                Invoke-AlmEvaluation | Out-Null
                if ($res.Interrupted) { $code = $script:AlmExit.DELAI }
                elseif ($res.Failed -gt 0 -or $res.Skipped -gt 0) { $code = $script:AlmExit.ECHEC_PARTIEL }
                elseif ((Get-AlmActiveIssueCount) -gt 0) { $code = $script:AlmExit.ECART }
                else { $code = $script:AlmExit.OK }
            }
            'Deploy' {
                $open = @(Get-AlmTransactions | Where-Object { $_.Status -eq 'Interrompue' -and -not @($_.Records | Where-Object { $_.Type -eq 'RB_END' }).Count })
                if ($open.Count) { Write-AlmMessage -Level ERROR -Text ('Transaction de deploiement interrompue : ' + (($open | ForEach-Object { $_.Id }) -join ', ') + ' (reprise : -Mode Apply -ResumeTransactionId)'); $code = $script:AlmExit.SAUT_PROTEGE; return }
                if (-not $script:AlmWrite.Permitted) { Invoke-AlmEvaluation | Out-Null; Write-AlmMessage -Level ERROR -Text ('Ecriture non autorisee : ' + (@($script:AlmWrite.Reasons) -join ' ; ')); $code = $script:AlmExit.SAUT_PROTEGE; return }
                Invoke-AlmEvaluation | Out-Null
                $plan = New-AlmPlan
                Write-AlmJsonFile -Path "$script:AlmRoot\Plans\latest_$BaselineProfile.json" -InputObject $plan
                $extra['Plan'] = $plan
                if (@($plan.Core.Actions).Count -eq 0) { Write-AlmMessage -Text 'Aucun changement a appliquer (deja conforme)'; $code = $script:AlmExit.OK; return }
                $res = Invoke-AlmTransaction -Kind 'Deploy' -Actions $plan.Core.Actions -PlanHash $plan.Hash
                $extra['Transaction'] = $res
                if (@($plan.RestartRequired).Count) { Write-AlmMessage -Level WARN -Text ('Redemarrage necessaire (prevoir une etape Restart computer en fin de sequence) pour : ' + (@($plan.RestartRequired) -join ',')) }
                Invoke-AlmEvaluation | Out-Null
                $left = @($script:AlmEval.Values | Where-Object { @('Socle', 'OptionActivee') -contains $_.Category -and @('Ecart', 'Conflit', 'NonVerifiable') -contains $_.Status } | ForEach-Object { $_.Id })
                if ($left.Count) { Write-AlmMessage -Level WARN -Text ('Non appliques au deploiement (prerequis, autorite ou valeur respectee) : ' + ($left -join ',') + ' ; seront repris par les audits et plans RG') }
                if ($res.Interrupted) { $code = $script:AlmExit.DELAI } elseif ($res.Failed -gt 0) { $code = $script:AlmExit.ECHEC_PARTIEL } else { $code = $script:AlmExit.OK }
            }
            'Verify' {
                Invoke-AlmEvaluation | Out-Null
                foreach ($e in $script:AlmEval.Values) {
                    if ($e.Restart -like 'Redemarrage*' -and $e.Status -eq 'Conforme' -and $script:AlmOwned.ContainsKey($e.Id) -and $script:AlmOs.LastBoot) {
                        if ([datetime]$script:AlmOwned[$e.Id].Time -gt $script:AlmOs.LastBoot) { $e.Status = 'ApplicationDifferee'; $e.Reason = 'Ecrit, effectif apres redemarrage' }
                    }
                }
                if ($P.GenerateTestEvents) { $extra['TestEvents'] = Invoke-AlmTestEvents }
                $lb = [int](Get-AlmProp $script:AlmCatalog.Thresholds 'EvidenceLookbackDays' 7)
                $extra['Evidence'] = Get-AlmEventEvidence -LookbackDays $lb
                $extra['EvidenceNote'] = 'ObserveLocalement = evenement genere sur la machine. La reception au collecteur et l''exploitabilite en detection se prouvent cote SIEM.'
                $code = $(if ((Get-AlmActiveIssueCount) -gt 0) { $script:AlmExit.ECART } else { $script:AlmExit.OK })
            }
            'Rollback' {
                if ($P.TransactionId) {
                    $tx = @(Get-AlmTransactions | Where-Object { $_.Id -eq $P.TransactionId }) | Select-Object -First 1
                    if (-not $tx) { Write-AlmMessage -Level ERROR -Text 'Transaction introuvable'; $code = $script:AlmExit.SAUT_PROTEGE; return }
                    $diff = Test-AlmSameMachine $tx.Begin.Machine $script:AlmIdentity
                    if ($diff.Count) { Write-AlmMessage -Level ERROR -Text ('Sauvegarde d''une autre machine ou d''un autre domaine : ' + ($diff -join ', ')); $code = $script:AlmExit.SAUT_PROTEGE; return }
                    if (@($tx.Records | Where-Object { $_.Type -eq 'RB_END' -and $_.Status -eq 'Annulee' }).Count) { Write-AlmMessage -Text 'Transaction deja annulee'; $code = $script:AlmExit.OK; return }
                    $res = Invoke-AlmRollbackTransaction -Tx $tx
                    $extra['Rollback'] = $res
                    $code = $(if ($res.Status -eq 'Annulee') { $script:AlmExit.OK } else { $script:AlmExit.RESTAURATION_INCOMPLETE })
                } elseif ($P.ToOrigin -or $P.SnapshotId) {
                    # powershell.exe -File transmet 'A,B' comme une seule chaine : decoupage explicite
                    $filter = @(Split-AlmList $P.ControlId)
                    if ($filter.Count -eq 0) { Write-AlmMessage -Level ERROR -Text 'Restauration globale : -ControlId explicite requis (ex. ALM-*)'; $code = $script:AlmExit.SAUT_PROTEGE; return }
                    $actions = @()
                    if ($P.ToOrigin) {
                        foreach ($id in @($script:AlmOrigins.Keys)) {
                            if (-not (Test-AlmIdMatch $id $filter)) { continue }
                            $o = $script:AlmOwned[$id]
                            if (-not $o) { Write-AlmMessage -Level WARN -ControlId $id -Text 'Plus de valeur Almeria active : rien a restaurer'; continue }
                            $actions += [pscustomobject]@{ Id = $id; Before = $o.Value; Desired = $script:AlmOrigins[$id].Before }
                        }
                        $kind = 'RestaurationOrigine'
                    } else {
                        $snap = Read-AlmJsonFile "$script:AlmRoot\Snapshots\$($P.SnapshotId).json"
                        if (-not $snap) { Write-AlmMessage -Level ERROR -Text 'Cliche introuvable'; $code = $script:AlmExit.SAUT_PROTEGE; return }
                        $diff = Test-AlmSameMachine $snap.Machine $script:AlmIdentity
                        if ($diff.Count) { Write-AlmMessage -Level ERROR -Text ('Cliche d''une autre machine : ' + ($diff -join ', ')); $code = $script:AlmExit.SAUT_PROTEGE; return }
                        foreach ($sp in $snap.States.PSObject.Properties) {
                            if (-not (Test-AlmIdMatch $sp.Name $filter)) { continue }
                            $c = Get-AlmControl $sp.Name; if (-not $c) { continue }
                            $auth = Get-AlmControlAuthority $c
                            if (@('Aucune', 'AlmeriaLocal') -notcontains $auth.Authority -and -not ($auth.Authority -eq 'Inconnue' -and (Get-AlmProp $script:AlmConfig 'BypassAuthority' $false))) { Write-AlmMessage -Level WARN -ControlId $c.Id -Text "Encore gere par $($auth.Authority) : restauration locale differee"; continue }
                            $expected = New-AlmDesiredRaw $c (Get-AlmTargetValue $c)
                            $actions += [pscustomobject]@{ Id = $c.Id; Before = $expected; Desired = $sp.Value }
                        }
                        $kind = 'RestaurationCliche'
                    }
                    if (-not $script:AlmWrite.Permitted) { Write-AlmMessage -Level WARN -Text 'Restauration demandee explicitement sur un hote sans autorisation d''ecriture standard : seuls les reglages sans autorite tierce sont traites' }
                    if ($actions.Count -eq 0) { Write-AlmMessage -Text 'Aucune restauration applicable'; $code = $script:AlmExit.OK; return }
                    $res = Invoke-AlmTransaction -Kind $kind -Actions $actions
                    $extra['Restoration'] = $res
                    $code = $(if ($res.Failed -or $res.Skipped -or $res.Interrupted) { $script:AlmExit.RESTAURATION_INCOMPLETE } else { $script:AlmExit.OK })
                } else { Write-AlmMessage -Level ERROR -Text 'Rollback : preciser -TransactionId, ou -ToOrigin / -SnapshotId avec -ControlId'; $code = $script:AlmExit.SAUT_PROTEGE }
            }
        }
    } catch {
        Write-AlmMessage -Level ERROR -Text ("Erreur fatale : " + $_.Exception.Message + ' @ ' + $_.InvocationInfo.PositionMessage)
        $code = $script:AlmExit.ERREUR
    } finally {
        if ($script:AlmSkipReport) { } else { try { Write-AlmReportAndSummary -Mode $Mode -Code $code -Extra $extra } catch { $script:AlmSummaryLines = @("ALM-BASELINE Code=$code rapport impossible : " + (ConvertTo-AlmAscii $_.Exception.Message)) } }
        if ($Mode -eq 'Deploy') { Copy-AlmReportToTaskSequenceLog }
        if ($locked) { Exit-AlmLock }
        $script:AlmExitCode = $code
    }
}
#endregion
#endregion ALM-EMBED

Invoke-AlmLocalMain -BaselineProfile 'Workstation' -P @{
    Mode = $Mode; ClientCode = $ClientCode; EnableOptions = $EnableOptions; DisableControls = $DisableControls
    OverrideExisting = $OverrideExisting; LocalException = $LocalException; ConfirmedRoles = @();
    BypassAuthority = [bool]$BypassAuthority; AllowOutOfSupportBuild = [bool]$AllowOutOfSupportBuild
    ApproveStoredPlan = [bool]$ApproveStoredPlan; ApprovedPlanHash = $ApprovedPlanHash; MaxPlanAgeHours = $MaxPlanAgeHours; MaxOsAgeHours = $MaxOsAgeHours
    ResumeTransactionId = $ResumeTransactionId; TransactionId = $TransactionId; ToOrigin = [bool]$ToOrigin; SnapshotId = $SnapshotId
    ControlId = $ControlId; GenerateTestEvents = [bool]$GenerateTestEvents; MaxDurationSeconds = $MaxDurationSeconds
    DiagOutputLines = $DiagOutputLines; DiagSleepSeconds = $DiagSleepSeconds; DiagExitCode = $DiagExitCode
}
foreach ($almLine in @($script:AlmSummaryLines)) { Write-Output $almLine }
exit ([int]$script:AlmExitCode)

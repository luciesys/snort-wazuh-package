-- =============================================================================
-- ðŸ›¡ï¸  SIEM AFRICA - BASE DE DONNÃ‰ES COMPLÃˆTE v2.0
-- =============================================================================
-- Solution de CybersÃ©curitÃ© pour les PME Africaines
-- IUT de Douala - Projet de Fin d'Ã‰tudes
-- 
-- Contenu: 25 catÃ©gories, 507 rÃ¨gles (207 Wazuh + 300 Snort)
-- =============================================================================

PRAGMA encoding = "UTF-8";
PRAGMA foreign_keys = ON;

-- Suppression des tables existantes
DROP TABLE IF EXISTS recommandations;
DROP TABLE IF EXISTS alertes_log;
DROP TABLE IF EXISTS regles;
DROP TABLE IF EXISTS categories;
DROP TABLE IF EXISTS utilisateurs;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS audit_log;

-- =============================================================================
-- TABLE: CATEGORIES (25 catÃ©gories)
-- =============================================================================

CREATE TABLE categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    nom TEXT NOT NULL,
    description TEXT,
    icone TEXT DEFAULT 'ðŸ””',
    couleur TEXT DEFAULT '#6c757d'
);

INSERT INTO categories (code, nom, description, icone, couleur) VALUES
('authentification', 'Authentification', 'Alertes liÃ©es aux connexions', 'ðŸ”', '#dc3545'),
('integrite', 'IntÃ©gritÃ© des fichiers', 'Modifications de fichiers surveillÃ©s', 'ðŸ“', '#fd7e14'),
('rootkit', 'Rootkits & Malwares', 'DÃ©tection de logiciels malveillants', 'ðŸ¦ ', '#dc3545'),
('politique', 'Politique de sÃ©curitÃ©', 'Violations des politiques', 'ðŸ“‹', '#ffc107'),
('service', 'Services systÃ¨me', 'Alertes sur les services', 'âš™ï¸', '#17a2b8'),
('reseau', 'RÃ©seau', 'ActivitÃ©s rÃ©seau suspectes', 'ðŸŒ', '#6f42c1'),
('application', 'Applications', 'Alertes applications web', 'ðŸ’»', '#20c997'),
('systeme', 'SystÃ¨me', 'Ã‰vÃ©nements systÃ¨me', 'ðŸ–¥ï¸', '#6c757d'),
('audit', 'Audit', 'Journaux audit systÃ¨me', 'ðŸ“', '#17a2b8'),
('pare_feu', 'Pare-feu', 'Alertes du pare-feu', 'ðŸ›¡ï¸', '#fd7e14'),
('ids', 'DÃ©tection intrusion', 'Alertes IDS/IPS', 'ðŸš¨', '#dc3545'),
('web', 'SÃ©curitÃ© Web', 'Attaques web', 'ðŸŒ', '#e83e8c'),
('vulnerabilite', 'VulnÃ©rabilitÃ©s', 'Tentatives exploitation', 'ðŸ”“', '#dc3545'),
('compliance', 'ConformitÃ©', 'Alertes conformitÃ©', 'âœ…', '#28a745'),
('non_identifie', 'Non identifiÃ©', 'Alertes non catÃ©gorisÃ©es', 'â“', '#6c757d'),
('scan', 'Scan & Reconnaissance', 'Scans de ports et reconnaissance', 'ðŸ”', '#fd7e14'),
('injection_sql', 'Injection SQL', 'Tentatives injection SQL', 'ðŸ’‰', '#dc3545'),
('xss', 'Cross-Site Scripting', 'Attaques XSS', 'ðŸ“œ', '#e83e8c'),
('dos', 'DoS / DDoS', 'Attaques dÃ©ni de service', 'ðŸ’¥', '#dc3545'),
('backdoor', 'Backdoors & Shells', 'Portes dÃ©robÃ©es', 'ðŸšª', '#dc3545'),
('brute_force', 'Brute Force', 'Attaques force brute', 'ðŸ”¨', '#fd7e14'),
('exploit', 'Exploits', 'Tentatives exploitation failles', 'ðŸŽ¯', '#dc3545'),
('malware', 'Malware & Virus', 'Logiciels malveillants', 'ðŸ¦ ', '#dc3545'),
('protocol', 'Protocoles suspects', 'Utilisation suspecte protocoles', 'ðŸ“¡', '#6f42c1'),
('phishing', 'Phishing & Spam', 'Tentatives phishing', 'ðŸ“§', '#ffc107');

-- =============================================================================
-- TABLE: REGLES
-- =============================================================================

CREATE TABLE regles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wazuh_rule_id INTEGER UNIQUE NOT NULL,
    nom_fr TEXT NOT NULL,
    description TEXT,
    gravite TEXT CHECK(gravite IN ('critique', 'haute', 'moyenne', 'faible', 'info')) DEFAULT 'moyenne',
    categorie_id INTEGER,
    impact TEXT,
    cause_probable TEXT,
    mitre_id TEXT,
    source TEXT DEFAULT 'wazuh',
    FOREIGN KEY (categorie_id) REFERENCES categories(id)
);

-- =============================================================================
-- RÃˆGLES WAZUH (207 rÃ¨gles)
-- =============================================================================

INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
-- Authentification SSH
(5501, 'Connexion PAM rÃ©ussie', 'Authentification PAM rÃ©ussie', 'info', 1, 'Utilisateur connectÃ©', 'Connexion normale', 'T1078', 'wazuh'),
(5502, 'Ã‰chec authentification PAM', 'Ã‰chec authentification PAM', 'moyenne', 1, 'Tentative connexion Ã©chouÃ©e', 'Mot de passe incorrect', 'T1110', 'wazuh'),
(5503, 'Compte utilisateur verrouillÃ©', 'Compte verrouillÃ© aprÃ¨s Ã©checs', 'haute', 1, 'Utilisateur bloquÃ©', 'Trop de tentatives Ã©chouÃ©es', 'T1110', 'wazuh'),
(5504, 'Session PAM ouverte', 'Nouvelle session utilisateur', 'info', 1, 'Session dÃ©marrÃ©e', 'Connexion normale', 'T1078', 'wazuh'),
(5505, 'Session PAM fermÃ©e', 'Session utilisateur fermÃ©e', 'info', 1, 'Session terminÃ©e', 'DÃ©connexion normale', 'T1078', 'wazuh'),
(5551, 'Connexion SSH rÃ©ussie', 'Connexion SSH avec succÃ¨s', 'info', 1, 'AccÃ¨s distant Ã©tabli', 'Connexion SSH lÃ©gitime', 'T1021.004', 'wazuh'),
(5710, 'Tentative connexion SSH Ã©chouÃ©e', 'Ã‰chec de connexion SSH', 'moyenne', 1, 'Tentative accÃ¨s Ã©chouÃ©e', 'Mot de passe ou clÃ© invalide', 'T1110.001', 'wazuh'),
(5711, 'Plusieurs Ã©checs SSH - Possible brute force', 'Multiples Ã©checs SSH dÃ©tectÃ©s', 'haute', 1, 'Possible attaque brute force', 'Attaquant devine mot de passe', 'T1110.001', 'wazuh'),
(5712, 'Attaque brute force SSH confirmÃ©e', 'Attaque brute force SSH confirmÃ©e', 'critique', 1, 'Serveur sous attaque', 'Outil de brute force utilisÃ©', 'T1110.001', 'wazuh'),
(5715, 'Connexion SSH root refusÃ©e', 'Connexion root SSH refusÃ©e', 'haute', 1, 'Tentative accÃ¨s root', 'Config SSH interdit root', 'T1078.003', 'wazuh'),
(5716, 'Auth SSH par clÃ© rÃ©ussie', 'Connexion SSH par clÃ© publique', 'info', 1, 'AccÃ¨s sÃ©curisÃ© par clÃ©', 'Auth par clÃ© configurÃ©e', 'T1021.004', 'wazuh'),
(5720, 'Utilisateur SSH invalide', 'Tentative avec utilisateur inexistant', 'moyenne', 1, 'Test de noms utilisateurs', 'Reconnaissance ou erreur', 'T1078', 'wazuh'),
(5721, 'DÃ©connexion SSH', 'Utilisateur dÃ©connectÃ© de SSH', 'info', 1, 'Session SSH terminÃ©e', 'DÃ©connexion volontaire', 'T1078', 'wazuh'),
(5722, 'SSH depuis IP interdite', 'Connexion depuis IP bloquÃ©e', 'haute', 1, 'AccÃ¨s depuis source non autorisÃ©e', 'IP dans liste noire', 'T1021.004', 'wazuh'),
(5601, 'Connexion FTP rÃ©ussie', 'Connexion FTP Ã©tablie', 'info', 1, 'AccÃ¨s FTP Ã©tabli', 'Connexion FTP normale', 'T1021', 'wazuh'),
(5602, 'Ã‰chec connexion FTP', 'Tentative FTP Ã©chouÃ©e', 'moyenne', 1, 'AccÃ¨s FTP refusÃ©', 'Identifiants incorrects', 'T1110', 'wazuh'),
(5901, 'Connexion sudo rÃ©ussie', 'Commande sudo exÃ©cutÃ©e', 'info', 1, 'Commande privilÃ©giÃ©e exÃ©cutÃ©e', 'Utilisation normale sudo', 'T1548.003', 'wazuh'),
(5902, 'Ã‰chec sudo - Mot de passe incorrect', 'Ã‰chec authentification sudo', 'moyenne', 1, 'Ã‰lÃ©vation privilÃ¨ges Ã©chouÃ©e', 'Mot de passe incorrect', 'T1548.003', 'wazuh'),
(5903, 'Sudo - Utilisateur non autorisÃ©', 'Utilisateur non autorisÃ© sudo', 'haute', 1, 'Tentative accÃ¨s root non autorisÃ©', 'Utilisateur pas dans groupe sudo', 'T1548.003', 'wazuh'),
(5904, 'Sudo - Commande non autorisÃ©e', 'Commande sudo interdite', 'haute', 1, 'Tentative contournement restrictions', 'Commande pas dans sudoers', 'T1548.003', 'wazuh'),
(5905, 'Sudo - 3 Ã©checs consÃ©cutifs', 'Trois Ã©checs sudo consÃ©cutifs', 'haute', 1, 'Possible brute force sudo', 'Oubli mot de passe ou attaque', 'T1548.003', 'wazuh'),
(5301, 'Connexion utilisateur rÃ©ussie', 'Utilisateur connectÃ© au systÃ¨me', 'info', 1, 'Session utilisateur dÃ©marrÃ©e', 'Connexion normale', 'T1078', 'wazuh'),
(5302, 'DÃ©connexion utilisateur', 'Utilisateur dÃ©connectÃ©', 'info', 1, 'Session terminÃ©e', 'DÃ©connexion normale', 'T1078', 'wazuh'),
(5303, 'Changement utilisateur (su)', 'Commande su utilisÃ©e', 'info', 1, 'Changement contexte utilisateur', 'Utilisation normale su', 'T1548.003', 'wazuh'),
(5304, 'Ã‰chec changement utilisateur', 'Commande su Ã©chouÃ©e', 'moyenne', 1, 'Changement utilisateur refusÃ©', 'Mot de passe incorrect', 'T1548.003', 'wazuh'),

-- IntÃ©gritÃ© fichiers
(550, 'Fichier ajoutÃ©', 'Nouveau fichier crÃ©Ã©', 'moyenne', 2, 'Nouveau fichier dÃ©tectÃ©', 'Installation ou crÃ©ation manuelle', 'T1027', 'wazuh'),
(551, 'Fichier modifiÃ©', 'Fichier surveillÃ© modifiÃ©', 'moyenne', 2, 'Contenu fichier modifiÃ©', 'Mise Ã  jour ou modification suspecte', 'T1565.001', 'wazuh'),
(552, 'Fichier supprimÃ©', 'Fichier surveillÃ© supprimÃ©', 'haute', 2, 'Fichier critique supprimÃ©', 'Suppression manuelle ou malware', 'T1485', 'wazuh'),
(553, 'Permissions fichier modifiÃ©es', 'Permissions fichier changÃ©es', 'moyenne', 2, 'Droits accÃ¨s modifiÃ©s', 'Changement configuration', 'T1222', 'wazuh'),
(554, 'PropriÃ©taire fichier modifiÃ©', 'PropriÃ©taire fichier changÃ©', 'moyenne', 2, 'PropriÃ©tÃ© fichier transfÃ©rÃ©e', 'Changement administratif', 'T1222', 'wazuh'),
(591, 'Modification /etc/passwd', 'Fichier passwd modifiÃ©', 'haute', 2, 'Comptes utilisateurs modifiÃ©s', 'Ajout ou modification compte', 'T1136', 'wazuh'),
(592, 'Modification /etc/shadow', 'Fichier shadow modifiÃ©', 'haute', 2, 'Mots de passe modifiÃ©s', 'Changement mot de passe', 'T1003', 'wazuh'),
(593, 'Modification /etc/group', 'Fichier groupes modifiÃ©', 'moyenne', 2, 'Groupes systÃ¨me modifiÃ©s', 'Ajout ou modification groupe', 'T1136', 'wazuh'),
(594, 'Modification /etc/sudoers', 'Fichier sudoers modifiÃ©', 'critique', 2, 'PrivilÃ¨ges sudo modifiÃ©s', 'Changement droits admin', 'T1548.003', 'wazuh'),
(516, 'Alerte intÃ©gritÃ© - Fichier critique', 'Fichier systÃ¨me critique modifiÃ©', 'critique', 2, 'IntÃ©gritÃ© systÃ¨me compromise', 'Modification non autorisÃ©e', 'T1565.001', 'wazuh'),

-- Rootkits
(510, 'Rootkit dÃ©tectÃ© - Fichier suspect', 'Fichier rootkit potentiel', 'critique', 3, 'SystÃ¨me potentiellement compromis', 'Infection par rootkit', 'T1014', 'wazuh'),
(511, 'Rootkit dÃ©tectÃ© - Processus cachÃ©', 'Processus cachÃ© dÃ©tectÃ©', 'critique', 3, 'Processus malveillant actif', 'Rootkit cachant processus', 'T1014', 'wazuh'),
(512, 'Rootkit dÃ©tectÃ© - Port cachÃ©', 'Port rÃ©seau cachÃ© dÃ©tectÃ©', 'critique', 3, 'Communication malveillante possible', 'Backdoor ou rootkit actif', 'T1014', 'wazuh'),
(513, 'Trojan dÃ©tectÃ©', 'Cheval de Troie identifiÃ©', 'critique', 3, 'Malware actif sur systÃ¨me', 'Infection par trojan', 'T1204', 'wazuh'),
(514, 'Signature malware dÃ©tectÃ©e', 'Signature malware connue trouvÃ©e', 'critique', 3, 'Malware connu prÃ©sent', 'Fichier infectÃ© dÃ©tectÃ©', 'T1204', 'wazuh'),
(515, 'Interface rÃ©seau mode promiscuous', 'Carte rÃ©seau capture tout trafic', 'haute', 3, 'Possible sniffing rÃ©seau', 'Outil capture ou malware', 'T1040', 'wazuh'),

-- Services
(600, 'Service dÃ©marrÃ©', 'Service systÃ¨me dÃ©marrÃ©', 'info', 5, 'Service actif', 'DÃ©marrage normal', 'T1543', 'wazuh'),
(601, 'Service arrÃªtÃ©', 'Service systÃ¨me arrÃªtÃ©', 'info', 5, 'Service inactif', 'ArrÃªt normal ou problÃ¨me', 'T1489', 'wazuh'),
(602, 'Service a Ã©chouÃ©', 'Service systÃ¨me en erreur', 'haute', 5, 'Service non fonctionnel', 'Erreur config ou crash', 'T1489', 'wazuh'),
(603, 'Nouveau service installÃ©', 'Nouveau service ajoutÃ©', 'moyenne', 5, 'Nouveau programme installÃ©', 'Installation lÃ©gitime ou malware', 'T1543', 'wazuh'),
(604, 'Service systemd rechargÃ©', 'Configuration systemd rechargÃ©e', 'info', 5, 'Configuration mise Ã  jour', 'Changement configuration', 'T1543', 'wazuh'),

-- RÃ©seau
(700, 'Nouvelle connexion rÃ©seau', 'Connexion rÃ©seau Ã©tablie', 'info', 6, 'Communication rÃ©seau active', 'Connexion normale', 'T1071', 'wazuh'),
(701, 'Connexion rÃ©seau suspecte', 'Connexion destination inhabituelle', 'haute', 6, 'Communication potentiellement malveillante', 'Possible exfiltration ou C2', 'T1071', 'wazuh'),
(702, 'Scan de ports dÃ©tectÃ©', 'ActivitÃ© scan ports identifiÃ©e', 'haute', 6, 'Reconnaissance rÃ©seau en cours', 'Attaquant cherche vulnÃ©rabilitÃ©s', 'T1046', 'wazuh'),
(703, 'Tentative connexion bloquÃ©e', 'Pare-feu a bloquÃ© connexion', 'info', 6, 'Connexion non autorisÃ©e refusÃ©e', 'RÃ¨gle pare-feu appliquÃ©e', 'T1071', 'wazuh'),
(704, 'Trafic DNS suspect', 'RequÃªtes DNS anormales', 'moyenne', 6, 'Possible tunneling DNS ou malware', 'Exfiltration via DNS', 'T1071.004', 'wazuh'),
(705, 'Connexion vers IP malveillante', 'Connexion vers IP liste noire', 'critique', 6, 'Communication avec infra malveillante', 'SystÃ¨me compromis contactant C2', 'T1071', 'wazuh'),

-- Applications web
(1001, 'Erreur application web', 'Erreur dans logs web', 'info', 7, 'ProblÃ¨me applicatif', 'Bug ou erreur utilisateur', 'T1190', 'wazuh'),
(1002, 'Erreur HTTP 500', 'Erreur interne serveur web', 'moyenne', 7, 'Serveur web en erreur', 'Bug applicatif ou surcharge', 'T1190', 'wazuh'),
(1003, 'Erreur HTTP 404 multiple', 'Nombreuses erreurs 404', 'moyenne', 7, 'Possible scan vulnÃ©rabilitÃ©s web', 'Scanner cherchant fichiers sensibles', 'T1595', 'wazuh'),
(1004, 'Tentative SQL injection', 'Patterns SQL injection dÃ©tectÃ©s', 'critique', 7, 'Tentative injection SQL', 'Attaquant ciblant base donnÃ©es', 'T1190', 'wazuh'),
(1005, 'Tentative XSS dÃ©tectÃ©e', 'Patterns XSS dans requÃªtes', 'haute', 7, 'Tentative cross-site scripting', 'Attaquant injectant JavaScript', 'T1059.007', 'wazuh'),
(1100, 'Apache - DÃ©marrage', 'Serveur Apache dÃ©marrÃ©', 'info', 7, 'Serveur web actif', 'DÃ©marrage normal', 'T1190', 'wazuh'),
(1101, 'Apache - ArrÃªt', 'Serveur Apache arrÃªtÃ©', 'info', 7, 'Serveur web inactif', 'ArrÃªt normal ou crash', 'T1489', 'wazuh'),
(1102, 'Apache - Erreur configuration', 'Erreur config Apache', 'haute', 7, 'Configuration invalide', 'Erreur syntaxe config', 'T1190', 'wazuh'),
(1200, 'Nginx - DÃ©marrage', 'Serveur Nginx dÃ©marrÃ©', 'info', 7, 'Serveur web actif', 'DÃ©marrage normal', 'T1190', 'wazuh'),
(1201, 'Nginx - ArrÃªt', 'Serveur Nginx arrÃªtÃ©', 'info', 7, 'Serveur web inactif', 'ArrÃªt normal ou crash', 'T1489', 'wazuh'),
(1300, 'MySQL - Connexion rÃ©ussie', 'Connexion MySQL Ã©tablie', 'info', 7, 'AccÃ¨s base donnÃ©es Ã©tabli', 'Connexion normale', 'T1213', 'wazuh'),
(1301, 'MySQL - Ã‰chec connexion', 'Ã‰chec connexion MySQL', 'moyenne', 7, 'AccÃ¨s base donnÃ©es refusÃ©', 'Identifiants incorrects', 'T1110', 'wazuh'),
(1302, 'MySQL - RequÃªte suspecte', 'RequÃªte SQL potentiellement dangereuse', 'haute', 7, 'Possible tentative attaque', 'Injection SQL ou requÃªte malformÃ©e', 'T1190', 'wazuh'),

-- SystÃ¨me
(530, 'DÃ©marrage systÃ¨me', 'SystÃ¨me a dÃ©marrÃ©', 'info', 8, 'SystÃ¨me opÃ©rationnel', 'RedÃ©marrage normal', 'T1078', 'wazuh'),
(531, 'ArrÃªt systÃ¨me', 'SystÃ¨me s arrÃªte', 'info', 8, 'SystÃ¨me en arrÃªt', 'ArrÃªt planifiÃ© ou problÃ¨me', 'T1529', 'wazuh'),
(532, 'Nouvel utilisateur crÃ©Ã©', 'Compte utilisateur crÃ©Ã©', 'moyenne', 8, 'Nouveau compte systÃ¨me', 'CrÃ©ation lÃ©gitime ou suspecte', 'T1136', 'wazuh'),
(533, 'Utilisateur supprimÃ©', 'Compte utilisateur supprimÃ©', 'moyenne', 8, 'Compte retirÃ© systÃ¨me', 'Suppression administrative', 'T1531', 'wazuh'),
(534, 'Groupe crÃ©Ã©', 'Nouveau groupe crÃ©Ã©', 'info', 8, 'Nouveau groupe systÃ¨me', 'Organisation droits', 'T1136', 'wazuh'),
(535, 'Utilisateur ajoutÃ© Ã  groupe', 'Utilisateur ajoutÃ© Ã  un groupe', 'info', 8, 'Droits utilisateur modifiÃ©s', 'Changement permissions', 'T1078', 'wazuh'),
(536, 'Mot de passe changÃ©', 'Mot de passe utilisateur modifiÃ©', 'info', 8, 'Credentials mis Ã  jour', 'Changement normal ou forcÃ©', 'T1078', 'wazuh'),
(537, 'Cron job ajoutÃ©', 'TÃ¢che planifiÃ©e ajoutÃ©e', 'moyenne', 8, 'Nouvelle tÃ¢che automatique', 'Automatisation ou persistance malware', 'T1053', 'wazuh'),
(538, 'Cron job modifiÃ©', 'TÃ¢che planifiÃ©e modifiÃ©e', 'moyenne', 8, 'TÃ¢che automatique changÃ©e', 'Maintenance ou modification suspecte', 'T1053', 'wazuh'),
(539, 'Espace disque faible', 'Espace disque presque plein', 'haute', 8, 'Risque dysfonctionnement', 'Disque plein bientÃ´t', 'T1485', 'wazuh'),
(540, 'Erreur kernel', 'Erreur kernel dÃ©tectÃ©e', 'haute', 8, 'ProblÃ¨me systÃ¨me grave', 'Bug kernel ou matÃ©riel dÃ©faillant', 'T1014', 'wazuh'),
(541, 'Module kernel chargÃ©', 'Module kernel chargÃ©', 'moyenne', 8, 'Nouveau module noyau', 'Driver lÃ©gitime ou rootkit', 'T1547', 'wazuh'),
(542, 'OOM Killer activÃ©', 'Processus tuÃ© par manque mÃ©moire', 'haute', 8, 'MÃ©moire insuffisante', 'Fuite mÃ©moire ou surcharge', 'T1499', 'wazuh'),

-- Audit
(800, 'Audit - Commande exÃ©cutÃ©e', 'Commande enregistrÃ©e par auditd', 'info', 9, 'ActivitÃ© utilisateur tracÃ©e', 'Commande normale ou suspecte', 'T1059', 'wazuh'),
(801, 'Audit - Fichier accÃ©dÃ©', 'AccÃ¨s fichier surveillÃ©', 'info', 9, 'Lecture fichier sensible', 'AccÃ¨s lÃ©gitime ou non', 'T1005', 'wazuh'),
(802, 'Audit - Changement configuration', 'Configuration systÃ¨me modifiÃ©e', 'moyenne', 9, 'ParamÃ¨tres systÃ¨me changÃ©s', 'Administration ou compromission', 'T1562', 'wazuh'),
(803, 'Audit - Ã‰lÃ©vation privilÃ¨ges', 'Tentative Ã©lÃ©vation privilÃ¨ges', 'haute', 9, 'Droits Ã©levÃ©s demandÃ©s', 'Action administrative ou attaque', 'T1548', 'wazuh'),

-- Pare-feu
(4100, 'Pare-feu - Paquet acceptÃ©', 'Paquet acceptÃ© par pare-feu', 'info', 10, 'Trafic autorisÃ©', 'Communication normale', 'T1071', 'wazuh'),
(4101, 'Pare-feu - Paquet bloquÃ©', 'Paquet bloquÃ© par pare-feu', 'info', 10, 'Trafic non autorisÃ© refusÃ©', 'RÃ¨gle filtrage appliquÃ©e', 'T1071', 'wazuh'),
(4102, 'Pare-feu - Scan dÃ©tectÃ©', 'Pare-feu a dÃ©tectÃ© un scan', 'haute', 10, 'Reconnaissance en cours', 'Attaquant cherchant ports ouverts', 'T1046', 'wazuh'),
(4103, 'Pare-feu - RÃ¨gle ajoutÃ©e', 'Nouvelle rÃ¨gle pare-feu ajoutÃ©e', 'moyenne', 10, 'Configuration pare-feu modifiÃ©e', 'Ajout rÃ¨gle', 'T1562.004', 'wazuh'),
(4104, 'Pare-feu - RÃ¨gle supprimÃ©e', 'RÃ¨gle pare-feu supprimÃ©e', 'haute', 10, 'Protection potentiellement rÃ©duite', 'Suppression rÃ¨gle', 'T1562.004', 'wazuh'),

-- IDS gÃ©nÃ©riques
(86001, 'IDS - Alerte Snort gÃ©nÃ©rique', 'Alerte Snort gÃ©nÃ©rÃ©e', 'moyenne', 11, 'ActivitÃ© suspecte dÃ©tectÃ©e par Snort', 'Signature IDS correspondante', 'T1071', 'wazuh'),
(86002, 'IDS - Plusieurs alertes Snort', 'Multiples alertes Snort', 'haute', 11, 'Attaque probable en cours', 'Nombreuses signatures dÃ©clenchÃ©es', 'T1071', 'wazuh'),

-- Compliance
(9001, 'PCI-DSS - Violation dÃ©tectÃ©e', 'Non-conformitÃ© PCI-DSS', 'haute', 14, 'ConformitÃ© PCI-DSS compromise', 'Violation rÃ¨gles paiement', 'T1078', 'wazuh'),
(9002, 'GDPR - AccÃ¨s donnÃ©es personnelles', 'AccÃ¨s donnÃ©es personnelles', 'moyenne', 14, 'DonnÃ©es personnelles consultÃ©es', 'AccÃ¨s lÃ©gitime ou non', 'T1005', 'wazuh'),
(9003, 'HIPAA - Violation potentielle', 'Possible violation HIPAA', 'haute', 14, 'DonnÃ©es mÃ©dicales exposÃ©es', 'AccÃ¨s non autorisÃ© donnÃ©es santÃ©', 'T1005', 'wazuh'),

-- Politique
(5100, 'Violation politique sÃ©curitÃ©', 'RÃ¨gle sÃ©curitÃ© violÃ©e', 'haute', 4, 'Non-conformitÃ© dÃ©tectÃ©e', 'Action non autorisÃ©e', 'T1078', 'wazuh'),
(5101, 'AccÃ¨s hors heures autorisÃ©es', 'Connexion hors heures travail', 'moyenne', 4, 'AccÃ¨s heure inhabituelle', 'Travail tardif ou accÃ¨s non autorisÃ©', 'T1078', 'wazuh'),
(5102, 'Tentative accÃ¨s ressource interdite', 'AccÃ¨s ressource non autorisÃ©e', 'haute', 4, 'Tentative violation politique', 'AccÃ¨s donnÃ©es restreintes', 'T1078', 'wazuh'),

-- RÃ¨gle par dÃ©faut
(99999, 'Alerte non identifiÃ©e', 'Alerte pas encore traduite', 'moyenne', 15, 'Impact inconnu - analyse requise', 'Origine inconnue', NULL, 'wazuh');

-- =============================================================================
-- RÃˆGLES SNORT (300 rÃ¨gles) - CatÃ©gories 16-25
-- =============================================================================

-- SCAN & RECONNAISSANCE (40 rÃ¨gles) - CatÃ©gorie 16
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87001, 'Scan de ports TCP dÃ©tectÃ©', 'Scan de ports TCP identifiÃ©', 'haute', 16, 'Attaquant cartographie ports ouverts', 'Outil Nmap utilisÃ©', 'T1046', 'snort'),
(87002, 'Scan de ports UDP dÃ©tectÃ©', 'Scan de ports UDP identifiÃ©', 'haute', 16, 'Recherche services UDP vulnÃ©rables', 'Scanner ports UDP actif', 'T1046', 'snort'),
(87003, 'Scan SYN furtif dÃ©tectÃ©', 'Scan TCP SYN half-open', 'haute', 16, 'Scan discret Ã©vitant dÃ©tection', 'Nmap SYN scan', 'T1046', 'snort'),
(87004, 'Scan FIN dÃ©tectÃ©', 'Scan TCP FIN anormal', 'haute', 16, 'Ã‰vasion pour contourner pare-feux', 'Scan FIN ports filtrÃ©s', 'T1046', 'snort'),
(87005, 'Scan NULL dÃ©tectÃ©', 'Scan TCP sans flags', 'haute', 16, 'Technique scan Ã©vasif', 'Paquets TCP sans flag', 'T1046', 'snort'),
(87006, 'Scan XMAS dÃ©tectÃ©', 'Scan TCP XMAS tous flags', 'haute', 16, 'Scan tous flags TCP activÃ©s', 'Fingerprinting OS', 'T1046', 'snort'),
(87007, 'Scan ACK dÃ©tectÃ©', 'Scan TCP ACK dÃ©tectÃ©', 'moyenne', 16, 'Cartographie rÃ¨gles pare-feu', 'ID ports filtrÃ©s vs non-filtrÃ©s', 'T1046', 'snort'),
(87008, 'Tentative fingerprinting OS', 'ID systÃ¨me exploitation', 'moyenne', 16, 'Attaquant identifie OS pour cibler exploits', 'Nmap OS detection', 'T1046', 'snort'),
(87009, 'Scan Nmap dÃ©tectÃ©', 'Signature Nmap identifiÃ©e', 'haute', 16, 'Outil reconnaissance Nmap utilisÃ©', 'Scan automatisÃ©', 'T1046', 'snort'),
(87010, 'Scan massif dÃ©tectÃ©', 'Scan nombreux ports rapidement', 'critique', 16, 'Reconnaissance agressive rÃ©seau', 'Scan rapide type masscan', 'T1046', 'snort'),
(87011, 'Scan vulnÃ©rabilitÃ©s dÃ©tectÃ©', 'Scanner vulnÃ©rabilitÃ©s identifiÃ©', 'haute', 16, 'Recherche automatisÃ©e failles', 'Nessus, OpenVAS ou Ã©quivalent', 'T1595', 'snort'),
(87012, 'Ping sweep dÃ©tectÃ©', 'Balayage ICMP rÃ©seau', 'moyenne', 16, 'DÃ©couverte hÃ´tes actifs', 'Reconnaissance prÃ©liminaire', 'T1046', 'snort'),
(87013, 'Traceroute dÃ©tectÃ©', 'Tentative traÃ§age route', 'faible', 16, 'Cartographie topologie rÃ©seau', 'Reconnaissance infrastructure', 'T1046', 'snort'),
(87014, 'Scan ARP dÃ©tectÃ©', 'Balayage ARP rÃ©seau local', 'moyenne', 16, 'DÃ©couverte machines LAN', 'arp-scan ou similaire', 'T1046', 'snort'),
(87015, 'Banner grabbing dÃ©tectÃ©', 'RÃ©cupÃ©ration banniÃ¨res', 'moyenne', 16, 'ID versions services', 'Reconnaissance logiciels', 'T1046', 'snort'),
(87016, 'Scan SMB dÃ©tectÃ©', 'Ã‰numÃ©ration partages SMB', 'haute', 16, 'Recherche partages Windows', 'enum4linux ou smbclient', 'T1135', 'snort'),
(87017, 'Ã‰numÃ©ration SNMP dÃ©tectÃ©e', 'Scan informations SNMP', 'haute', 16, 'Extraction infos systÃ¨me via SNMP', 'Community strings testÃ©es', 'T1046', 'snort'),
(87018, 'Scan LDAP dÃ©tectÃ©', 'Ã‰numÃ©ration annuaire LDAP', 'haute', 16, 'Extraction infos Active Directory', 'Reconnaissance AD', 'T1087', 'snort'),
(87019, 'Scan NetBIOS dÃ©tectÃ©', 'Ã‰numÃ©ration NetBIOS rÃ©seau', 'moyenne', 16, 'DÃ©couverte noms machines Windows', 'nbtscan ou Ã©quivalent', 'T1046', 'snort'),
(87020, 'Scan RPC dÃ©tectÃ©', 'Ã‰numÃ©ration services RPC', 'moyenne', 16, 'ID services RPC disponibles', 'rpcinfo ou rpcclient', 'T1046', 'snort'),
(87021, 'Scan ports web dÃ©tectÃ©', 'Scan ciblant HTTP/HTTPS', 'moyenne', 16, 'Recherche serveurs web', 'Reconnaissance web', 'T1046', 'snort'),
(87022, 'Scan base donnÃ©es dÃ©tectÃ©', 'Scan ports bases donnÃ©es', 'haute', 16, 'Recherche MySQL PostgreSQL MSSQL', 'Ciblage donnÃ©es', 'T1046', 'snort'),
(87023, 'Ã‰numÃ©ration DNS dÃ©tectÃ©e', 'RequÃªtes DNS reconnaissance', 'moyenne', 16, 'Transfert zone ou Ã©numÃ©ration', 'dig dnsenum fierce', 'T1046', 'snort'),
(87024, 'Scan SSH dÃ©tectÃ©', 'Scan ciblant port SSH', 'moyenne', 16, 'Recherche serveurs SSH', 'PrÃ©paration attaque SSH', 'T1046', 'snort'),
(87025, 'Scan Telnet dÃ©tectÃ©', 'Scan port Telnet', 'haute', 16, 'Recherche services Telnet non sÃ©curisÃ©s', 'Protocole non chiffrÃ© ciblÃ©', 'T1046', 'snort'),
(87026, 'Scan VNC dÃ©tectÃ©', 'Scan ports VNC', 'haute', 16, 'Recherche bureaux distants', 'Ciblage accÃ¨s graphique', 'T1046', 'snort'),
(87027, 'Scan RDP dÃ©tectÃ©', 'Scan port Remote Desktop', 'haute', 16, 'Recherche serveurs Windows RDP', 'PrÃ©paration attaque RDP', 'T1046', 'snort'),
(87028, 'Scan FTP dÃ©tectÃ©', 'Scan port FTP', 'moyenne', 16, 'Recherche serveurs FTP', 'Ciblage transfert fichiers', 'T1046', 'snort'),
(87029, 'Scan service mail dÃ©tectÃ©', 'Scan ports SMTP/POP/IMAP', 'moyenne', 16, 'Recherche serveurs messagerie', 'Ciblage infra email', 'T1046', 'snort'),
(87030, 'Scan IPv6 dÃ©tectÃ©', 'Reconnaissance rÃ©seau IPv6', 'moyenne', 16, 'Scan adresses IPv6', 'Reconnaissance dual-stack', 'T1046', 'snort'),
(87031, 'Fragmentation scan dÃ©tectÃ©', 'Scan paquets fragmentÃ©s', 'haute', 16, 'Technique Ã©vasion IDS', 'Fragmentation Ã©viter dÃ©tection', 'T1046', 'snort'),
(87032, 'Idle scan dÃ©tectÃ©', 'Scan utilisant hÃ´te zombie', 'critique', 16, 'Technique scan trÃ¨s furtif', 'Utilisation tiers pour scanner', 'T1046', 'snort'),
(87033, 'Decoy scan dÃ©tectÃ©', 'Scan adresses sources multiples', 'haute', 16, 'Tentative masquer vraie source', 'Nmap decoy scan', 'T1046', 'snort'),
(87034, 'Scan TTL anormal', 'Paquets TTL suspect', 'moyenne', 16, 'Technique fingerprinting', 'Analyse comportement rÃ©seau', 'T1046', 'snort'),
(87035, 'Scan ports privilÃ©giÃ©s', 'Scan ports 1-1024', 'moyenne', 16, 'Recherche services systÃ¨me', 'Scan ports rÃ©servÃ©s', 'T1046', 'snort'),
(87036, 'Scan ports hauts', 'Scan ports supÃ©rieurs 1024', 'faible', 16, 'Recherche services applicatifs', 'Scan ports non privilÃ©giÃ©s', 'T1046', 'snort'),
(87037, 'Scan horizontal dÃ©tectÃ©', 'MÃªme port plusieurs hÃ´tes', 'haute', 16, 'Recherche service spÃ©cifique rÃ©seau', 'Ciblage vulnÃ©rabilitÃ© connue', 'T1046', 'snort'),
(87038, 'Scan vertical dÃ©tectÃ©', 'Plusieurs ports un hÃ´te', 'moyenne', 16, 'Ã‰numÃ©ration complÃ¨te machine', 'Analyse approfondie serveur', 'T1046', 'snort'),
(87039, 'Service version scan dÃ©tectÃ©', 'ID versions services', 'moyenne', 16, 'Recherche versions vulnÃ©rables', 'Nmap service detection', 'T1046', 'snort'),
(87040, 'Script scan Nmap dÃ©tectÃ©', 'ExÃ©cution scripts NSE Nmap', 'haute', 16, 'Scan avancÃ© scripts Nmap', 'DÃ©tection vulnÃ©rabilitÃ©s automatisÃ©e', 'T1595', 'snort');

-- INJECTION SQL (35 rÃ¨gles) - CatÃ©gorie 17
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87041, 'Injection SQL - UNION SELECT', 'Injection SQL avec UNION SELECT', 'critique', 17, 'Extraction donnÃ©es base', 'Attaquant lit tables', 'T1190', 'snort'),
(87042, 'Injection SQL - OR 1=1', 'Pattern classique injection SQL', 'critique', 17, 'Contournement authentification', 'Bypass login par SQL injection', 'T1190', 'snort'),
(87043, 'Injection SQL - commentaire', 'Commentaires SQL malveillants', 'haute', 17, 'Neutralisation requÃªte originale', 'Troncature requÃªte par -- ou #', 'T1190', 'snort'),
(87044, 'Injection SQL - SLEEP/BENCHMARK', 'Injection SQL temporelle', 'haute', 17, 'Blind SQL injection temps', 'Test vulnÃ©rabilitÃ© par dÃ©lai', 'T1190', 'snort'),
(87045, 'Injection SQL - stacked queries', 'RequÃªtes SQL empilÃ©es', 'critique', 17, 'ExÃ©cution commandes SQL multiples', 'Tentative modification donnÃ©es', 'T1190', 'snort'),
(87046, 'Injection SQL - DROP TABLE', 'Tentative suppression table', 'critique', 17, 'Destruction donnÃ©es', 'Attaque destructrice base', 'T1485', 'snort'),
(87047, 'Injection SQL - INSERT INTO', 'Tentative insertion donnÃ©es', 'haute', 17, 'Injection donnÃ©es malveillantes', 'CrÃ©ation compte admin ou backdoor', 'T1190', 'snort'),
(87048, 'Injection SQL - UPDATE SET', 'Tentative modification donnÃ©es', 'critique', 17, 'AltÃ©ration donnÃ©es existantes', 'Modification mots passe ou privilÃ¨ges', 'T1565', 'snort'),
(87049, 'Injection SQL - DELETE FROM', 'Tentative suppression donnÃ©es', 'critique', 17, 'Effacement donnÃ©es', 'Suppression logs ou utilisateurs', 'T1485', 'snort'),
(87050, 'Injection SQL - LOAD_FILE', 'Tentative lecture fichier serveur', 'critique', 17, 'Lecture fichiers systÃ¨me via MySQL', 'Extraction /etc/passwd ou config', 'T1005', 'snort'),
(87051, 'Injection SQL - INTO OUTFILE', 'Tentative Ã©criture fichier', 'critique', 17, 'Ã‰criture webshell sur serveur', 'CrÃ©ation backdoor via SQL', 'T1505.003', 'snort'),
(87052, 'Injection SQL - information_schema', 'Ã‰numÃ©ration structure base', 'haute', 17, 'DÃ©couverte tables et colonnes', 'Cartographie base donnÃ©es', 'T1190', 'snort'),
(87053, 'Injection SQL - extractvalue', 'Injection SQL basÃ©e XML', 'haute', 17, 'Technique extraction donnÃ©es', 'Exploitation fonctions XML MySQL', 'T1190', 'snort'),
(87054, 'Injection SQL - updatexml', 'Injection via fonction updatexml', 'haute', 17, 'Extraction donnÃ©es par erreur XML', 'Error-based SQL injection', 'T1190', 'snort'),
(87055, 'Injection SQL - CONCAT', 'Utilisation CONCAT extraction', 'haute', 17, 'Assemblage donnÃ©es extraites', 'Technique rÃ©cupÃ©ration donnÃ©es', 'T1190', 'snort'),
(87056, 'Injection SQL - HEX encoding', 'Injection SQL encodÃ©e hexa', 'haute', 17, 'Tentative Ã©vasion filtres', 'Bypass WAF par encodage', 'T1190', 'snort'),
(87057, 'Injection SQL - CHAR encoding', 'Injection utilisant CHAR', 'haute', 17, 'Ã‰vasion filtres caractÃ¨res', 'Construction payload par CHAR()', 'T1190', 'snort'),
(87058, 'Injection SQL - double encoding', 'Double encodage URL dÃ©tectÃ©', 'haute', 17, 'Tentative bypass filtres', 'Ã‰vasion par double URL encoding', 'T1190', 'snort'),
(87059, 'Injection SQL - SQLMap dÃ©tectÃ©', 'Signature outil SQLMap', 'critique', 17, 'Utilisation outil automatisÃ©', 'Attaque SQL injection automatisÃ©e', 'T1190', 'snort'),
(87060, 'Injection SQL - auth bypass', 'Contournement login par SQL', 'critique', 17, 'AccÃ¨s non autorisÃ© application', 'admin or Ã©quivalent dÃ©tectÃ©', 'T1190', 'snort'),
(87061, 'Injection SQL - error based', 'Injection provoquant erreurs SQL', 'haute', 17, 'Extraction infos via messages erreur', 'Exploitation erreurs SQL affichÃ©es', 'T1190', 'snort'),
(87062, 'Injection SQL - blind boolean', 'Injection SQL aveugle boolÃ©enne', 'haute', 17, 'Extraction bit par bit', 'Test conditions vraies/fausses', 'T1190', 'snort'),
(87063, 'Injection SQL - second order', 'Injection SQL second ordre', 'haute', 17, 'Payload stockÃ© puis exÃ©cutÃ©', 'Injection diffÃ©rÃ©e temps', 'T1190', 'snort'),
(87064, 'Injection SQL - proc stockÃ©e', 'Appel procÃ©dure stockÃ©e malveillant', 'critique', 17, 'ExÃ©cution code cÃ´tÃ© serveur', 'xp_cmdshell ou Ã©quivalent', 'T1190', 'snort'),
(87065, 'Injection SQL - NoSQL', 'Injection base NoSQL', 'haute', 17, 'Attaque MongoDB ou similaire', 'Injection opÃ©rateurs NoSQL', 'T1190', 'snort'),
(87066, 'Injection SQL - ORDER BY', 'Ã‰numÃ©ration colonnes ORDER BY', 'moyenne', 17, 'DÃ©couverte nombre colonnes', 'PrÃ©paration attaque UNION', 'T1190', 'snort'),
(87067, 'Injection SQL - GROUP BY', 'Injection via clause GROUP BY', 'moyenne', 17, 'Extraction donnÃ©es agrÃ©gÃ©es', 'Manipulation requÃªtes groupÃ©es', 'T1190', 'snort'),
(87068, 'Injection SQL - HAVING', 'Injection via clause HAVING', 'moyenne', 17, 'Bypass filtres sur agrÃ©gats', 'Technique Ã©vasion avancÃ©e', 'T1190', 'snort'),
(87069, 'Injection SQL - sous-requÃªte', 'Injection avec sous-requÃªte', 'haute', 17, 'RequÃªte imbriquÃ©e malveillante', 'Extraction complexe donnÃ©es', 'T1190', 'snort'),
(87070, 'Injection SQL - CASE WHEN', 'Injection conditionnelle', 'haute', 17, 'Extraction conditionnelle donnÃ©es', 'Blind injection avec conditions', 'T1190', 'snort'),
(87071, 'Injection SQL - base64', 'Payload SQL encodÃ© base64', 'haute', 17, 'Tentative Ã©vasion dÃ©tection', 'Obfuscation payload', 'T1190', 'snort'),
(87072, 'Injection SQL - PostgreSQL', 'Injection spÃ©cifique PostgreSQL', 'haute', 17, 'Exploitation fonctions PostgreSQL', 'Syntaxe spÃ©cifique dÃ©tectÃ©e', 'T1190', 'snort'),
(87073, 'Injection SQL - MSSQL', 'Injection spÃ©cifique Microsoft SQL', 'haute', 17, 'Exploitation fonctions MSSQL', 'xp_cmdshell ou OPENROWSET', 'T1190', 'snort'),
(87074, 'Injection SQL - Oracle', 'Injection spÃ©cifique Oracle', 'haute', 17, 'Exploitation fonctions Oracle', 'UTL_HTTP ou DBMS dÃ©tectÃ©', 'T1190', 'snort'),
(87075, 'Injection SQL - SQLite', 'Injection spÃ©cifique SQLite', 'haute', 17, 'Exploitation SQLite', 'Syntaxe SQLite malveillante', 'T1190', 'snort');

-- XSS - CROSS-SITE SCRIPTING (35 rÃ¨gles) - CatÃ©gorie 18
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87076, 'XSS - balise script dÃ©tectÃ©e', 'Injection balise script', 'haute', 18, 'ExÃ©cution JavaScript malveillant', 'XSS rÃ©flÃ©chi ou stockÃ©', 'T1059.007', 'snort'),
(87077, 'XSS - Ã©vÃ©nement onload', 'Attribut onload malveillant', 'haute', 18, 'ExÃ©cution code au chargement', 'Injection via attribut Ã©vÃ©nement', 'T1059.007', 'snort'),
(87078, 'XSS - Ã©vÃ©nement onerror', 'Attribut onerror malveillant', 'haute', 18, 'ExÃ©cution via erreur provoquÃ©e', 'XSS dÃ©clenchÃ© par erreur image', 'T1059.007', 'snort'),
(87079, 'XSS - Ã©vÃ©nement onclick', 'Attribut onclick injectÃ©', 'haute', 18, 'Code exÃ©cutÃ© au clic', 'PiÃ¨ge au clic', 'T1059.007', 'snort'),
(87080, 'XSS - javascript: URI', 'URI javascript: dÃ©tectÃ©', 'haute', 18, 'ExÃ©cution via protocole javascript', 'Injection dans href ou src', 'T1059.007', 'snort'),
(87081, 'XSS - data: URI', 'URI data: contenu actif', 'haute', 18, 'Contenu exÃ©cutable encodÃ©', 'Payload dans data URI', 'T1059.007', 'snort'),
(87082, 'XSS - balise img malveillante', 'Injection via balise image', 'haute', 18, 'XSS sans balise script', 'Technique Ã©vasion filtres', 'T1059.007', 'snort'),
(87083, 'XSS - balise svg malveillante', 'Injection via SVG', 'haute', 18, 'XSS via contenu SVG', 'Vecteur attaque moderne', 'T1059.007', 'snort'),
(87084, 'XSS - balise iframe', 'Injection iframe malveillant', 'haute', 18, 'Inclusion contenu externe', 'Clickjacking ou vol donnÃ©es', 'T1059.007', 'snort'),
(87085, 'XSS - balise body', 'Attribut Ã©vÃ©nement sur body', 'haute', 18, 'ExÃ©cution au chargement page', 'Injection dans balise body', 'T1059.007', 'snort'),
(87086, 'XSS - document.cookie', 'AccÃ¨s cookies dÃ©tectÃ©', 'critique', 18, 'Vol session utilisateur', 'Exfiltration cookies', 'T1539', 'snort'),
(87087, 'XSS - document.location', 'Redirection malveillante', 'haute', 18, 'Redirection vers site malveillant', 'Phishing ou drive-by download', 'T1059.007', 'snort'),
(87088, 'XSS - window.location', 'Manipulation URL', 'haute', 18, 'Redirection forcÃ©e utilisateur', 'Vol session ou phishing', 'T1059.007', 'snort'),
(87089, 'XSS - eval() dÃ©tectÃ©', 'Utilisation eval()', 'critique', 18, 'ExÃ©cution code arbitraire', 'Fonction dangereuse utilisÃ©e', 'T1059.007', 'snort'),
(87090, 'XSS - innerHTML', 'Manipulation innerHTML', 'haute', 18, 'Injection HTML dans DOM', 'Modification dynamique contenu', 'T1059.007', 'snort'),
(87091, 'XSS - document.write', 'Utilisation document.write', 'haute', 18, 'Ã‰criture directe document', 'Injection contenu', 'T1059.007', 'snort'),
(87092, 'XSS - fromCharCode', 'Obfuscation par fromCharCode', 'haute', 18, 'Ã‰vasion filtres par encodage', 'Payload construit char par char', 'T1059.007', 'snort'),
(87093, 'XSS - unescape', 'Utilisation unescape()', 'haute', 18, 'DÃ©codage payload obfusquÃ©', 'Technique Ã©vasion', 'T1059.007', 'snort'),
(87094, 'XSS - atob/btoa', 'Encodage base64 JavaScript', 'haute', 18, 'Payload encodÃ© base64', 'Obfuscation code malveillant', 'T1059.007', 'snort'),
(87095, 'XSS - expression CSS', 'Expression CSS malveillante', 'haute', 18, 'XSS via propriÃ©tÃ© CSS', 'Technique IE ancienne', 'T1059.007', 'snort'),
(87096, 'XSS - balise style', 'Injection balise style', 'moyenne', 18, 'Manipulation CSS malveillante', 'Exfiltration via CSS', 'T1059.007', 'snort'),
(87097, 'XSS - balise link', 'Injection link malveillant', 'haute', 18, 'Chargement ressource externe', 'Inclusion CSS malveillant', 'T1059.007', 'snort'),
(87098, 'XSS - balise meta', 'Injection meta refresh', 'moyenne', 18, 'Redirection automatique', 'Refresh vers site malveillant', 'T1059.007', 'snort'),
(87099, 'XSS - balise object', 'Injection objet malveillant', 'haute', 18, 'Chargement contenu actif', 'Flash ou ActiveX malveillant', 'T1059.007', 'snort'),
(87100, 'XSS - balise embed', 'Injection via embed', 'haute', 18, 'Contenu embarquÃ© malveillant', 'Plugin malveillant chargÃ©', 'T1059.007', 'snort'),
(87101, 'XSS - balise form', 'Formulaire injectÃ©', 'haute', 18, 'Formulaire phishing', 'Vol credentials', 'T1059.007', 'snort'),
(87102, 'XSS - balise input', 'Input Ã©vÃ©nement malveillant', 'haute', 18, 'ExÃ©cution sur interaction', 'XSS via champ formulaire', 'T1059.007', 'snort'),
(87103, 'XSS - balise button', 'Bouton code malveillant', 'haute', 18, 'ExÃ©cution au clic', 'PiÃ¨ge sur bouton', 'T1059.007', 'snort'),
(87104, 'XSS - balise textarea', 'Textarea avec injection', 'moyenne', 18, 'Code injectÃ© zone texte', 'Stockage payload', 'T1059.007', 'snort'),
(87105, 'XSS - balise marquee', 'Injection via marquee', 'moyenne', 18, 'Ã‰vÃ©nement sur dÃ©filement', 'Balise obsolÃ¨te exploitÃ©e', 'T1059.007', 'snort'),
(87106, 'XSS - XMLHttpRequest', 'RequÃªte AJAX malveillante', 'haute', 18, 'Exfiltration donnÃ©es via XHR', 'Communication serveur attaquant', 'T1059.007', 'snort'),
(87107, 'XSS - fetch API', 'Utilisation malveillante fetch', 'haute', 18, 'Exfiltration via API moderne', 'Vol donnÃ©es par fetch', 'T1059.007', 'snort'),
(87108, 'XSS - WebSocket', 'WebSocket vers serveur malveillant', 'haute', 18, 'Canal communication persistant', 'C2 via WebSocket', 'T1059.007', 'snort'),
(87109, 'XSS - postMessage', 'Exploitation postMessage', 'haute', 18, 'Communication inter-frames malveillante', 'Bypass same-origin policy', 'T1059.007', 'snort'),
(87110, 'XSS - mutation observer', 'Surveillance DOM malveillante', 'moyenne', 18, 'Observation changements DOM', 'Technique keylogging', 'T1059.007', 'snort');

-- DoS / DDoS (35 rÃ¨gles) - CatÃ©gorie 19
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87111, 'DoS - SYN Flood dÃ©tectÃ©', 'Inondation paquets SYN', 'critique', 19, 'Saturation connexions TCP', 'Attaque dÃ©ni de service', 'T1499.001', 'snort'),
(87112, 'DoS - UDP Flood dÃ©tectÃ©', 'Inondation paquets UDP', 'critique', 19, 'Saturation bande passante', 'Attaque volumÃ©trique UDP', 'T1499.001', 'snort'),
(87113, 'DoS - ICMP Flood dÃ©tectÃ©', 'Inondation paquets ICMP', 'haute', 19, 'Saturation par ping', 'Ping flood ou smurf attack', 'T1499.001', 'snort'),
(87114, 'DoS - HTTP Flood dÃ©tectÃ©', 'Nombreuses requÃªtes HTTP', 'critique', 19, 'Surcharge serveur web', 'Attaque applicative HTTP', 'T1499.002', 'snort'),
(87115, 'DoS - Slowloris dÃ©tectÃ©', 'Attaque Slowloris identifiÃ©e', 'haute', 19, 'Ã‰puisement connexions', 'Connexions lentes ouvertes', 'T1499.002', 'snort'),
(87116, 'DoS - Slow POST dÃ©tectÃ©', 'Attaque Slow POST', 'haute', 19, 'RequÃªtes POST trÃ¨s lentes', 'Ã‰puisement threads serveur', 'T1499.002', 'snort'),
(87117, 'DoS - Slow READ dÃ©tectÃ©', 'Attaque Slow Read', 'haute', 19, 'Lecture trÃ¨s lente rÃ©ponses', 'Maintien connexions ouvertes', 'T1499.002', 'snort'),
(87118, 'DoS - DNS Amplification', 'Amplification DNS dÃ©tectÃ©e', 'critique', 19, 'Attaque rÃ©flexion DNS', 'Serveur DNS amplificateur', 'T1498.002', 'snort'),
(87119, 'DoS - NTP Amplification', 'Amplification NTP dÃ©tectÃ©e', 'critique', 19, 'Attaque rÃ©flexion NTP', 'Serveur NTP exploitÃ©', 'T1498.002', 'snort'),
(87120, 'DoS - SSDP Amplification', 'Amplification SSDP dÃ©tectÃ©e', 'critique', 19, 'Attaque rÃ©flexion SSDP', 'PÃ©riphÃ©riques UPnP exploitÃ©s', 'T1498.002', 'snort'),
(87121, 'DoS - Memcached Amplification', 'Amplification Memcached', 'critique', 19, 'Attaque massive rÃ©flexion', 'Serveurs Memcached exposÃ©s', 'T1498.002', 'snort'),
(87122, 'DoS - ACK Flood dÃ©tectÃ©', 'Inondation paquets ACK', 'haute', 19, 'Surcharge par paquets ACK', 'Variation SYN flood', 'T1499.001', 'snort'),
(87123, 'DoS - RST Flood dÃ©tectÃ©', 'Inondation paquets RST', 'haute', 19, 'Interruption connexions', 'Attaque reset TCP', 'T1499.001', 'snort'),
(87124, 'DoS - FIN Flood dÃ©tectÃ©', 'Inondation paquets FIN', 'haute', 19, 'Fermeture forcÃ©e connexions', 'Attaque par paquets FIN', 'T1499.001', 'snort'),
(87125, 'DoS - Fragmentation attack', 'Attaque par fragmentation', 'haute', 19, 'Paquets fragmentÃ©s malveillants', 'Teardrop ou similaire', 'T1499.001', 'snort'),
(87126, 'DoS - Ping of Death', 'Ping de la mort dÃ©tectÃ©', 'haute', 19, 'Paquet ICMP surdimensionnÃ©', 'Tentative crash systÃ¨me', 'T1499.001', 'snort'),
(87127, 'DoS - Land Attack', 'Attaque Land dÃ©tectÃ©e', 'haute', 19, 'Source et destination identiques', 'Attaque bouclage TCP', 'T1499.001', 'snort'),
(87128, 'DoS - Smurf Attack', 'Attaque Smurf dÃ©tectÃ©e', 'haute', 19, 'Amplification ICMP broadcast', 'Ping vers adresse broadcast', 'T1498.002', 'snort'),
(87129, 'DoS - Christmas Tree Attack', 'Paquets XMAS malveillants', 'haute', 19, 'Tous flags TCP activÃ©s', 'Attaque paquets malformÃ©s', 'T1499.001', 'snort'),
(87130, 'DoS - Connection exhaustion', 'Ã‰puisement connexions', 'haute', 19, 'Toutes connexions utilisÃ©es', 'Saturation sockets', 'T1499.001', 'snort'),
(87131, 'DoS - Bandwidth exhaustion', 'Saturation bande passante', 'critique', 19, 'Lien rÃ©seau saturÃ©', 'Attaque volumÃ©trique', 'T1499.001', 'snort'),
(87132, 'DoS - Application layer', 'Attaque couche application', 'haute', 19, 'Ciblage application', 'DoS applicatif sophistiquÃ©', 'T1499.002', 'snort'),
(87133, 'DoS - SSL/TLS exhaustion', 'Attaque sur SSL/TLS', 'haute', 19, 'Surcharge handshake SSL', 'Ã‰puisement CPU par crypto', 'T1499.001', 'snort'),
(87134, 'DoS - Recursive bomb', 'Bombe rÃ©cursive dÃ©tectÃ©e', 'haute', 19, 'RequÃªte causant rÃ©cursion infinie', 'XML bomb ou zip bomb', 'T1499.004', 'snort'),
(87135, 'DoS - Regex bomb', 'Expression rÃ©guliÃ¨re malveillante', 'haute', 19, 'Regex causant backtracking', 'ReDoS attack', 'T1499.004', 'snort'),
(87136, 'DDoS - Botnet dÃ©tectÃ©', 'Trafic botnet identifiÃ©', 'critique', 19, 'Attaque distribuÃ©e en cours', 'RÃ©seau machines zombies', 'T1499.001', 'snort'),
(87137, 'DDoS - Source spoofing', 'Adresses sources falsifiÃ©es', 'critique', 19, 'Impossible bloquer source rÃ©elle', 'IP spoofing attaque DDoS', 'T1499.001', 'snort'),
(87138, 'DoS - Request smuggling', 'Contrebande requÃªtes', 'haute', 19, 'DÃ©synchronisation serveur', 'HTTP request smuggling', 'T1499.002', 'snort'),
(87139, 'DoS - Cache poisoning', 'Empoisonnement cache', 'haute', 19, 'Cache servant contenu malveillant', 'Web cache poisoning DoS', 'T1499.002', 'snort'),
(87140, 'DoS - Hash collision', 'Attaque collision hash', 'haute', 19, 'Surcharge CPU serveur', 'Hash DoS attack', 'T1499.004', 'snort'),
(87141, 'DoS - Zip bomb dÃ©tectÃ©', 'Archive compressÃ©e malveillante', 'haute', 19, 'DÃ©compression causant crash', 'Fichier zip de la mort', 'T1499.004', 'snort'),
(87142, 'DoS - XML bomb dÃ©tectÃ©', 'Bombe XML billion laughs', 'haute', 19, 'Parsing XML Ã©puisement mÃ©moire', 'XXE DoS attack', 'T1499.004', 'snort'),
(87143, 'DoS - DHCP starvation', 'Ã‰puisement baux DHCP', 'haute', 19, 'Plus adresses IP disponibles', 'Attaque serveur DHCP', 'T1499.001', 'snort'),
(87144, 'DoS - ARP flooding', 'Inondation ARP', 'haute', 19, 'Saturation table ARP', 'Attaque rÃ©seau local', 'T1499.001', 'snort'),
(87145, 'DoS - MAC flooding', 'Inondation adresses MAC', 'haute', 19, 'Saturation table MAC switch', 'Transformation switch en hub', 'T1499.001', 'snort');

-- BACKDOORS & SHELLS (30 rÃ¨gles) - CatÃ©gorie 20
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87146, 'Backdoor - Reverse shell dÃ©tectÃ©', 'Connexion shell inversÃ©e', 'critique', 20, 'Attaquant a accÃ¨s systÃ¨me', 'Shell sortant vers attaquant', 'T1059', 'snort'),
(87147, 'Backdoor - Bind shell dÃ©tectÃ©', 'Shell en Ã©coute dÃ©tectÃ©', 'critique', 20, 'Port backdoor ouvert', 'Shell attendant connexion', 'T1059', 'snort'),
(87148, 'Backdoor - Netcat shell', 'Netcat utilisÃ© comme shell', 'critique', 20, 'Outil polyvalent backdoor', 'nc -e /bin/bash dÃ©tectÃ©', 'T1059.004', 'snort'),
(87149, 'Backdoor - Web shell PHP', 'Shell PHP dÃ©tectÃ©', 'critique', 20, 'Backdoor web serveur PHP', 'c99 r57 ou shell custom', 'T1505.003', 'snort'),
(87150, 'Backdoor - Web shell ASP', 'Shell ASP dÃ©tectÃ©', 'critique', 20, 'Backdoor web serveur IIS', 'Shell ASP/ASPX malveillant', 'T1505.003', 'snort'),
(87151, 'Backdoor - Web shell JSP', 'Shell JSP dÃ©tectÃ©', 'critique', 20, 'Backdoor serveur Java', 'Shell JSP malveillant', 'T1505.003', 'snort'),
(87152, 'Backdoor - Meterpreter dÃ©tectÃ©', 'Payload Metasploit identifiÃ©', 'critique', 20, 'Framework attaque Metasploit', 'Meterpreter shell actif', 'T1059', 'snort'),
(87153, 'Backdoor - Cobalt Strike beacon', 'Beacon Cobalt Strike', 'critique', 20, 'Outil attaque avancÃ© dÃ©tectÃ©', 'Infrastructure C2 Cobalt Strike', 'T1071', 'snort'),
(87154, 'Backdoor - Empire agent', 'Agent PowerShell Empire', 'critique', 20, 'Framework post-exploitation', 'Agent Empire actif', 'T1059.001', 'snort'),
(87155, 'Backdoor - Trafic C2 dÃ©tectÃ©', 'Communication Command Control', 'critique', 20, 'Machine communique serveur attaquant', 'Canal commande Ã©tabli', 'T1071', 'snort'),
(87156, 'Backdoor - IRC bot dÃ©tectÃ©', 'Bot IRC malveillant', 'haute', 20, 'Machine partie botnet IRC', 'ContrÃ´le via canal IRC', 'T1071.001', 'snort'),
(87157, 'Backdoor - Tunnel SSH dÃ©tectÃ©', 'Tunnel SSH suspect', 'haute', 20, 'SSH utilisÃ© tunneling', 'Exfiltration ou C2 via SSH', 'T1572', 'snort'),
(87158, 'Backdoor - Tunnel DNS dÃ©tectÃ©', 'Tunnel DNS identifiÃ©', 'critique', 20, 'Communication cachÃ©e via DNS', 'Exfiltration requÃªtes DNS', 'T1572', 'snort'),
(87159, 'Backdoor - Tunnel ICMP dÃ©tectÃ©', 'Tunnel ICMP identifiÃ©', 'haute', 20, 'DonnÃ©es cachÃ©es paquets ICMP', 'Covert channel ICMP', 'T1572', 'snort'),
(87160, 'Backdoor - Tunnel HTTP dÃ©tectÃ©', 'Tunnel HTTP suspect', 'haute', 20, 'Communication C2 via HTTP', 'Trafic malveillant dans HTTP', 'T1071.001', 'snort'),
(87161, 'Backdoor - RAT dÃ©tectÃ©', 'Remote Access Trojan', 'critique', 20, 'ContrÃ´le distance systÃ¨me', 'RAT actif machine', 'T1219', 'snort'),
(87162, 'Backdoor - njRAT dÃ©tectÃ©', 'Trojan njRAT identifiÃ©', 'critique', 20, 'Malware contrÃ´le distance', 'njRAT actif', 'T1219', 'snort'),
(87163, 'Backdoor - DarkComet dÃ©tectÃ©', 'Trojan DarkComet', 'critique', 20, 'RAT DarkComet actif', 'ContrÃ´le total machine', 'T1219', 'snort'),
(87164, 'Backdoor - Poison Ivy dÃ©tectÃ©', 'Trojan Poison Ivy', 'critique', 20, 'RAT sophistiquÃ© actif', 'Malware espionnage', 'T1219', 'snort'),
(87165, 'Backdoor - Quasar RAT dÃ©tectÃ©', 'Trojan Quasar identifiÃ©', 'critique', 20, 'RAT open-source actif', 'Outil admin malveillant', 'T1219', 'snort'),
(87166, 'Backdoor - TeamViewer abuse', 'TeamViewer usage suspect', 'haute', 20, 'Outil lÃ©gitime utilisÃ© malicieusement', 'AccÃ¨s distant non autorisÃ©', 'T1219', 'snort'),
(87167, 'Backdoor - AnyDesk abuse', 'AnyDesk usage suspect', 'haute', 20, 'Outil accÃ¨s distant abusÃ©', 'ContrÃ´le non autorisÃ©', 'T1219', 'snort'),
(87168, 'Backdoor - Cryptominer dÃ©tectÃ©', 'Mineur cryptomonnaie', 'haute', 20, 'Ressources utilisÃ©es minage', 'Cryptojacking actif', 'T1496', 'snort'),
(87169, 'Backdoor - Keylogger dÃ©tectÃ©', 'Enregistreur frappe', 'critique', 20, 'Capture saisies clavier', 'Vol mots de passe', 'T1056.001', 'snort'),
(87170, 'Backdoor - Rootkit communication', 'Communication rootkit dÃ©tectÃ©e', 'critique', 20, 'Rootkit actif communique', 'SystÃ¨me profondÃ©ment compromis', 'T1014', 'snort'),
(87171, 'Backdoor - Persistence mechanism', 'MÃ©canisme persistance', 'haute', 20, 'Backdoor configure persistance', 'Survie au redÃ©marrage', 'T1547', 'snort'),
(87172, 'Backdoor - Scheduled task', 'TÃ¢che planifiÃ©e suspecte', 'haute', 20, 'ExÃ©cution programmÃ©e malware', 'Persistance par tÃ¢che planifiÃ©e', 'T1053', 'snort'),
(87173, 'Backdoor - Registry persistence', 'Persistance via registre', 'haute', 20, 'ClÃ© registre malveillante', 'Autorun malveillant', 'T1547.001', 'snort'),
(87174, 'Backdoor - Service malveillant', 'Service systÃ¨me backdoor', 'haute', 20, 'Service crÃ©Ã© malware', 'Persistance par service', 'T1543.003', 'snort'),
(87175, 'Backdoor - DLL hijacking', 'DÃ©tournement DLL', 'haute', 20, 'DLL lÃ©gitime remplacÃ©e', 'ExÃ©cution code malveillant', 'T1574.001', 'snort');

-- BRUTE FORCE (25 rÃ¨gles) - CatÃ©gorie 21
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87176, 'Brute Force - SSH dÃ©tectÃ©', 'Attaque force brute SSH', 'critique', 21, 'Tentative deviner mot passe SSH', 'Outil Hydra ou Medusa', 'T1110.001', 'snort'),
(87177, 'Brute Force - FTP dÃ©tectÃ©', 'Attaque force brute FTP', 'haute', 21, 'Tentative deviner identifiants FTP', 'Attaque automatisÃ©e FTP', 'T1110.001', 'snort'),
(87178, 'Brute Force - Telnet dÃ©tectÃ©', 'Attaque force brute Telnet', 'haute', 21, 'Tentative service Telnet', 'Protocole non sÃ©curisÃ© ciblÃ©', 'T1110.001', 'snort'),
(87179, 'Brute Force - HTTP Basic Auth', 'Attaque auth HTTP', 'haute', 21, 'Force brute Basic Auth', 'Tentative accÃ¨s web', 'T1110.001', 'snort'),
(87180, 'Brute Force - HTTP Form', 'Attaque formulaire web', 'haute', 21, 'Force brute login web', 'Soumission massive credentials', 'T1110.001', 'snort'),
(87181, 'Brute Force - RDP dÃ©tectÃ©', 'Attaque force brute RDP', 'critique', 21, 'Tentative Remote Desktop', 'Ciblage accÃ¨s Windows', 'T1110.001', 'snort'),
(87182, 'Brute Force - VNC dÃ©tectÃ©', 'Attaque force brute VNC', 'haute', 21, 'Tentative bureau distant VNC', 'AccÃ¨s graphique ciblÃ©', 'T1110.001', 'snort'),
(87183, 'Brute Force - SMB dÃ©tectÃ©', 'Attaque force brute SMB', 'haute', 21, 'Tentative partages Windows', 'AccÃ¨s fichiers ciblÃ©', 'T1110.001', 'snort'),
(87184, 'Brute Force - SMTP dÃ©tectÃ©', 'Attaque force brute SMTP', 'moyenne', 21, 'Tentative serveur mail', 'Compromission compte email', 'T1110.001', 'snort'),
(87185, 'Brute Force - POP3 dÃ©tectÃ©', 'Attaque force brute POP3', 'moyenne', 21, 'Tentative boÃ®te mail POP', 'Vol emails ciblÃ©', 'T1110.001', 'snort'),
(87186, 'Brute Force - IMAP dÃ©tectÃ©', 'Attaque force brute IMAP', 'moyenne', 21, 'Tentative boÃ®te mail IMAP', 'AccÃ¨s emails ciblÃ©', 'T1110.001', 'snort'),
(87187, 'Brute Force - MySQL dÃ©tectÃ©', 'Attaque force brute MySQL', 'haute', 21, 'Tentative base donnÃ©es', 'AccÃ¨s donnÃ©es ciblÃ©', 'T1110.001', 'snort'),
(87188, 'Brute Force - PostgreSQL', 'Attaque force brute PostgreSQL', 'haute', 21, 'Tentative base PostgreSQL', 'Base donnÃ©es ciblÃ©e', 'T1110.001', 'snort'),
(87189, 'Brute Force - MSSQL dÃ©tectÃ©', 'Attaque force brute MSSQL', 'haute', 21, 'Tentative SQL Server', 'Base Microsoft ciblÃ©e', 'T1110.001', 'snort'),
(87190, 'Brute Force - MongoDB dÃ©tectÃ©', 'Attaque force brute MongoDB', 'haute', 21, 'Tentative base NoSQL', 'MongoDB ciblÃ©', 'T1110.001', 'snort'),
(87191, 'Brute Force - LDAP dÃ©tectÃ©', 'Attaque force brute LDAP', 'haute', 21, 'Tentative annuaire', 'Active Directory ciblÃ©', 'T1110.001', 'snort'),
(87192, 'Brute Force - SNMP community', 'Force brute community SNMP', 'moyenne', 21, 'Test community strings', 'AccÃ¨s info systÃ¨me', 'T1110.001', 'snort'),
(87193, 'Brute Force - Wordpress', 'Attaque wp-login', 'haute', 21, 'Force brute admin WordPress', 'CMS ciblÃ©', 'T1110.001', 'snort'),
(87194, 'Brute Force - Joomla dÃ©tectÃ©', 'Attaque admin Joomla', 'haute', 21, 'Force brute admin Joomla', 'CMS ciblÃ©', 'T1110.001', 'snort'),
(87195, 'Brute Force - Drupal dÃ©tectÃ©', 'Attaque admin Drupal', 'haute', 21, 'Force brute admin Drupal', 'CMS ciblÃ©', 'T1110.001', 'snort'),
(87196, 'Credential Stuffing dÃ©tectÃ©', 'Credentials volÃ©s utilisÃ©s', 'haute', 21, 'Test couples user/pass connus', 'Base donnÃ©es leaks utilisÃ©e', 'T1110.004', 'snort'),
(87197, 'Password Spraying dÃ©tectÃ©', 'PulvÃ©risation mots passe', 'haute', 21, 'MÃªme password plusieurs comptes', 'Ã‰vitement verrouillage', 'T1110.003', 'snort'),
(87198, 'Brute Force - Hydra dÃ©tectÃ©', 'Outil Hydra identifiÃ©', 'critique', 21, 'Outil force brute populaire', 'THC-Hydra en action', 'T1110.001', 'snort'),
(87199, 'Brute Force - Medusa dÃ©tectÃ©', 'Outil Medusa identifiÃ©', 'critique', 21, 'Outil force brute rapide', 'Medusa en action', 'T1110.001', 'snort'),
(87200, 'Brute Force - Ncrack dÃ©tectÃ©', 'Outil Ncrack identifiÃ©', 'critique', 21, 'Outil Nmap force brute', 'Ncrack en action', 'T1110.001', 'snort');

-- EXPLOITS (35 rÃ¨gles) - CatÃ©gorie 22
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87201, 'Exploit - Buffer overflow dÃ©tectÃ©', 'Tentative dÃ©passement tampon', 'critique', 22, 'ExÃ©cution code arbitraire possible', 'Exploitation vulnÃ©rabilitÃ© mÃ©moire', 'T1203', 'snort'),
(87202, 'Exploit - Format string attack', 'Attaque chaÃ®ne format', 'critique', 22, 'Lecture/Ã©criture mÃ©moire arbitraire', 'Exploitation printf vulnÃ©rable', 'T1203', 'snort'),
(87203, 'Exploit - Heap overflow dÃ©tectÃ©', 'DÃ©passement tas dÃ©tectÃ©', 'critique', 22, 'Corruption de la heap', 'Exploitation avancÃ©e', 'T1203', 'snort'),
(87204, 'Exploit - Stack overflow dÃ©tectÃ©', 'DÃ©passement pile dÃ©tectÃ©', 'critique', 22, 'Corruption de la stack', 'Buffer overflow classique', 'T1203', 'snort'),
(87205, 'Exploit - Use after free', 'Utilisation aprÃ¨s libÃ©ration', 'critique', 22, 'Exploitation mÃ©moire libÃ©rÃ©e', 'VulnÃ©rabilitÃ© UAF', 'T1203', 'snort'),
(87206, 'Exploit - Integer overflow', 'DÃ©passement entier', 'haute', 22, 'Calcul causant overflow', 'Contournement vÃ©rifications', 'T1203', 'snort'),
(87207, 'Exploit - Path traversal', 'TraversÃ©e rÃ©pertoires', 'haute', 22, 'AccÃ¨s fichiers hors webroot', 'Lecture fichiers sensibles', 'T1083', 'snort'),
(87208, 'Exploit - Local File Inclusion', 'Inclusion fichier local', 'critique', 22, 'Inclusion fichiers serveur', 'LFI vers RCE possible', 'T1505', 'snort'),
(87209, 'Exploit - Remote File Inclusion', 'Inclusion fichier distant', 'critique', 22, 'Inclusion code malveillant externe', 'RFI menant Ã  RCE', 'T1505', 'snort'),
(87210, 'Exploit - Command injection', 'Injection commande OS', 'critique', 22, 'ExÃ©cution commandes systÃ¨me', 'Shell command injection', 'T1059', 'snort'),
(87211, 'Exploit - LDAP injection', 'Injection LDAP dÃ©tectÃ©e', 'haute', 22, 'Manipulation requÃªtes LDAP', 'Bypass auth AD', 'T1190', 'snort'),
(87212, 'Exploit - XPath injection', 'Injection XPath dÃ©tectÃ©e', 'haute', 22, 'Manipulation requÃªtes XML', 'Extraction donnÃ©es XML', 'T1190', 'snort'),
(87213, 'Exploit - XXE dÃ©tectÃ©', 'XML External Entity attack', 'critique', 22, 'Inclusion entitÃ©s externes XML', 'Lecture fichiers ou SSRF', 'T1190', 'snort'),
(87214, 'Exploit - SSRF dÃ©tectÃ©', 'Server-Side Request Forgery', 'haute', 22, 'RequÃªtes forgÃ©es cÃ´tÃ© serveur', 'AccÃ¨s rÃ©seau interne', 'T1190', 'snort'),
(87215, 'Exploit - Deserialization attack', 'Attaque dÃ©sÃ©rialisation', 'critique', 22, 'Objet malveillant dÃ©sÃ©rialisÃ©', 'RCE via dÃ©sÃ©rialisation', 'T1190', 'snort'),
(87216, 'Exploit - Shellshock dÃ©tectÃ©', 'VulnÃ©rabilitÃ© Shellshock', 'critique', 22, 'Exploitation Bash CVE-2014-6271', 'ExÃ©cution code via CGI', 'T1190', 'snort'),
(87217, 'Exploit - Heartbleed dÃ©tectÃ©', 'VulnÃ©rabilitÃ© Heartbleed', 'critique', 22, 'Fuite mÃ©moire OpenSSL', 'Vol clÃ©s privÃ©es possible', 'T1190', 'snort'),
(87218, 'Exploit - EternalBlue dÃ©tectÃ©', 'Exploit EternalBlue SMB', 'critique', 22, 'Exploitation MS17-010', 'Propagation type WannaCry', 'T1210', 'snort'),
(87219, 'Exploit - BlueKeep dÃ©tectÃ©', 'VulnÃ©rabilitÃ© BlueKeep RDP', 'critique', 22, 'Exploitation CVE-2019-0708', 'RCE sur RDP sans auth', 'T1210', 'snort'),
(87220, 'Exploit - Log4Shell dÃ©tectÃ©', 'VulnÃ©rabilitÃ© Log4j', 'critique', 22, 'Exploitation CVE-2021-44228', 'RCE via JNDI injection', 'T1190', 'snort'),
(87221, 'Exploit - ProxyLogon dÃ©tectÃ©', 'VulnÃ©rabilitÃ© Exchange', 'critique', 22, 'Exploitation CVE-2021-26855', 'AccÃ¨s Exchange sans auth', 'T1190', 'snort'),
(87222, 'Exploit - ProxyShell dÃ©tectÃ©', 'ChaÃ®ne ProxyShell Exchange', 'critique', 22, 'Exploitation CVE-2021-34473', 'RCE sur Exchange', 'T1190', 'snort'),
(87223, 'Exploit - Spring4Shell dÃ©tectÃ©', 'VulnÃ©rabilitÃ© Spring Framework', 'critique', 22, 'Exploitation CVE-2022-22965', 'RCE applications Spring', 'T1190', 'snort'),
(87224, 'Exploit - Metasploit payload', 'Payload Metasploit dÃ©tectÃ©', 'critique', 22, 'Utilisation framework exploit', 'Attaque automatisÃ©e', 'T1203', 'snort'),
(87225, 'Exploit - Struts RCE dÃ©tectÃ©', 'VulnÃ©rabilitÃ© Apache Struts', 'critique', 22, 'Exploitation Struts', 'RCE applications Java', 'T1190', 'snort'),
(87226, 'Exploit - Drupalgeddon dÃ©tectÃ©', 'VulnÃ©rabilitÃ© Drupal', 'critique', 22, 'Exploitation Drupal RCE', 'Compromission CMS', 'T1190', 'snort'),
(87227, 'Exploit - ThinkPHP RCE', 'VulnÃ©rabilitÃ© ThinkPHP', 'critique', 22, 'Exploitation framework PHP', 'RCE applications ThinkPHP', 'T1190', 'snort'),
(87228, 'Exploit - Jenkins RCE', 'VulnÃ©rabilitÃ© Jenkins', 'critique', 22, 'Exploitation Jenkins', 'Compromission CI/CD', 'T1190', 'snort'),
(87229, 'Exploit - Jira RCE', 'VulnÃ©rabilitÃ© Atlassian Jira', 'critique', 22, 'Exploitation Jira', 'RCE gestionnaire tickets', 'T1190', 'snort'),
(87230, 'Exploit - Confluence RCE', 'VulnÃ©rabilitÃ© Confluence', 'critique', 22, 'Exploitation CVE-2022-26134', 'RCE wiki Confluence', 'T1190', 'snort'),
(87231, 'Exploit - vCenter RCE', 'VulnÃ©rabilitÃ© VMware vCenter', 'critique', 22, 'Exploitation vCenter', 'Compromission infra virtuelle', 'T1190', 'snort'),
(87232, 'Exploit - Citrix ADC', 'VulnÃ©rabilitÃ© Citrix Gateway', 'critique', 22, 'Exploitation CVE-2019-19781', 'Compromission accÃ¨s distant', 'T1190', 'snort'),
(87233, 'Exploit - PulseSecure VPN', 'VulnÃ©rabilitÃ© Pulse Secure', 'critique', 22, 'Exploitation VPN Pulse', 'AccÃ¨s rÃ©seau compromis', 'T1190', 'snort'),
(87234, 'Exploit - Fortinet VPN', 'VulnÃ©rabilitÃ© FortiGate', 'critique', 22, 'Exploitation VPN Fortinet', 'AccÃ¨s rÃ©seau compromis', 'T1190', 'snort'),
(87235, 'Exploit - SolarWinds SUNBURST', 'Backdoor SolarWinds', 'critique', 22, 'DÃ©tection SUNBURST', 'Supply chain attack', 'T1195.002', 'snort');

-- MALWARE & VIRUS (30 rÃ¨gles) - CatÃ©gorie 23
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87236, 'Malware - Ransomware dÃ©tectÃ©', 'Comportement ransomware', 'critique', 23, 'Chiffrement fichiers en cours', 'Cryptolocker ou similaire', 'T1486', 'snort'),
(87237, 'Malware - WannaCry dÃ©tectÃ©', 'Ransomware WannaCry', 'critique', 23, 'WannaCry identifiÃ©', 'Propagation via EternalBlue', 'T1486', 'snort'),
(87238, 'Malware - Ryuk dÃ©tectÃ©', 'Ransomware Ryuk', 'critique', 23, 'Ryuk ransomware actif', 'Ciblage entreprises', 'T1486', 'snort'),
(87239, 'Malware - REvil dÃ©tectÃ©', 'Ransomware REvil/Sodinokibi', 'critique', 23, 'REvil identifiÃ©', 'Ransomware-as-a-Service', 'T1486', 'snort'),
(87240, 'Malware - Emotet dÃ©tectÃ©', 'Trojan Emotet', 'critique', 23, 'Emotet actif', 'Loader malware', 'T1204', 'snort'),
(87241, 'Malware - TrickBot dÃ©tectÃ©', 'Trojan TrickBot', 'critique', 23, 'TrickBot identifiÃ©', 'Vol credentials bancaires', 'T1204', 'snort'),
(87242, 'Malware - Qbot dÃ©tectÃ©', 'Trojan Qakbot', 'critique', 23, 'Qbot actif', 'Banking trojan', 'T1204', 'snort'),
(87243, 'Malware - Dridex dÃ©tectÃ©', 'Trojan Dridex', 'critique', 23, 'Dridex identifiÃ©', 'Vol bancaire', 'T1204', 'snort'),
(87244, 'Malware - Zeus dÃ©tectÃ©', 'Trojan Zeus/Zbot', 'critique', 23, 'Zeus actif', 'Banking trojan historique', 'T1204', 'snort'),
(87245, 'Malware - Mirai dÃ©tectÃ©', 'Botnet Mirai', 'critique', 23, 'Infection Mirai', 'Botnet IoT', 'T1584', 'snort'),
(87246, 'Malware - Conficker dÃ©tectÃ©', 'Ver Conficker', 'haute', 23, 'Conficker identifiÃ©', 'Ver se propageant via SMB', 'T1210', 'snort'),
(87247, 'Malware - Agent Tesla', 'Spyware Agent Tesla', 'critique', 23, 'Keylogger Agent Tesla', 'Vol credentials', 'T1056.001', 'snort'),
(87248, 'Malware - FormBook dÃ©tectÃ©', 'Infostealer FormBook', 'critique', 23, 'FormBook actif', 'Vol donnÃ©es formulaires', 'T1056', 'snort'),
(87249, 'Malware - LokiBot dÃ©tectÃ©', 'Infostealer LokiBot', 'haute', 23, 'LokiBot identifiÃ©', 'Vol mots de passe', 'T1555', 'snort'),
(87250, 'Malware - RedLine Stealer', 'Infostealer RedLine', 'critique', 23, 'RedLine actif', 'Vol donnÃ©es navigateur', 'T1555.003', 'snort'),
(87251, 'Malware - Raccoon Stealer', 'Infostealer Raccoon', 'critique', 23, 'Raccoon identifiÃ©', 'MaaS - Malware as Service', 'T1555', 'snort'),
(87252, 'Malware - AsyncRAT dÃ©tectÃ©', 'RAT AsyncRAT', 'critique', 23, 'AsyncRAT actif', 'ContrÃ´le distance', 'T1219', 'snort'),
(87253, 'Malware - RemcosRAT dÃ©tectÃ©', 'Trojan Remcos', 'critique', 23, 'Remcos identifiÃ©', 'Outil surveillance', 'T1219', 'snort'),
(87254, 'Malware - NanoCore dÃ©tectÃ©', 'RAT NanoCore', 'critique', 23, 'NanoCore actif', 'RAT vendu darknet', 'T1219', 'snort'),
(87255, 'Malware - Adware dÃ©tectÃ©', 'Logiciel publicitaire', 'moyenne', 23, 'Adware installÃ©', 'PublicitÃ©s intrusives', 'T1204', 'snort'),
(87256, 'Malware - Spyware dÃ©tectÃ©', 'Logiciel espion', 'haute', 23, 'Spyware actif', 'Surveillance utilisateur', 'T1056', 'snort'),
(87257, 'Malware - Worm detected', 'Ver informatique dÃ©tectÃ©', 'haute', 23, 'Ver en propagation', 'Auto-rÃ©plication rÃ©seau', 'T1210', 'snort'),
(87258, 'Malware - Dropper dÃ©tectÃ©', 'Programme dÃ©posant malware', 'haute', 23, 'Dropper identifiÃ©', 'Installation charge utile', 'T1204', 'snort'),
(87259, 'Malware - Downloader dÃ©tectÃ©', 'TÃ©lÃ©chargeur malware', 'haute', 23, 'Downloader actif', 'TÃ©lÃ©chargement payload', 'T1105', 'snort'),
(87260, 'Malware - Cryptominer dÃ©tectÃ©', 'Mineur cryptomonnaie', 'haute', 23, 'Minage non autorisÃ©', 'Cryptojacking', 'T1496', 'snort'),
(87261, 'Malware - XMRig dÃ©tectÃ©', 'Mineur Monero XMRig', 'haute', 23, 'XMRig actif', 'Minage Monero', 'T1496', 'snort'),
(87262, 'Malware - Cobalt Strike', 'Framework Cobalt Strike', 'critique', 23, 'Beacon CS identifiÃ©', 'Outil red team malveillant', 'T1071', 'snort'),
(87263, 'Malware - Mimikatz detected', 'Outil Mimikatz', 'critique', 23, 'Mimikatz utilisÃ©', 'Extraction credentials', 'T1003', 'snort'),
(87264, 'Malware - PsExec abuse', 'Usage suspect PsExec', 'haute', 23, 'PsExec lateral movement', 'DÃ©placement latÃ©ral', 'T1570', 'snort'),
(87265, 'Malware - BazarLoader dÃ©tectÃ©', 'Loader BazarBackdoor', 'critique', 23, 'BazarLoader actif', 'Chargeur ransomware', 'T1204', 'snort');

-- PROTOCOLES SUSPECTS (20 rÃ¨gles) - CatÃ©gorie 24
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87266, 'Protocole - DNS over HTTPS suspect', 'DoH vers serveur non standard', 'moyenne', 24, 'DNS chiffrÃ© serveur inconnu', 'Possible exfiltration ou C2', 'T1071.004', 'snort'),
(87267, 'Protocole - DNS over TLS suspect', 'DoT vers serveur non standard', 'moyenne', 24, 'DNS chiffrÃ© suspect', 'Canal cachÃ© potentiel', 'T1071.004', 'snort'),
(87268, 'Protocole - ICMP payload anormal', 'DonnÃ©es suspectes ICMP', 'haute', 24, 'Tunnel ICMP probable', 'Exfiltration via ping', 'T1572', 'snort'),
(87269, 'Protocole - DNS requÃªte longue', 'Sous-domaine anormalement long', 'haute', 24, 'Possible tunnel DNS', 'DonnÃ©es encodÃ©es DNS', 'T1071.004', 'snort'),
(87270, 'Protocole - DNS type TXT suspect', 'RequÃªte TXT inhabituelle', 'moyenne', 24, 'Possible canal C2', 'Commandes dans records TXT', 'T1071.004', 'snort'),
(87271, 'Protocole - HTTP port non standard', 'HTTP port inhabituel', 'moyenne', 24, 'Service web non standard', 'Possible backdoor web', 'T1571', 'snort'),
(87272, 'Protocole - SSL port non standard', 'HTTPS port inhabituel', 'moyenne', 24, 'Chiffrement port suspect', 'C2 chiffrÃ© probable', 'T1571', 'snort'),
(87273, 'Protocole - IRC trafic dÃ©tectÃ©', 'Communication IRC', 'haute', 24, 'Protocole IRC utilisÃ©', 'Possible botnet IRC', 'T1071.001', 'snort'),
(87274, 'Protocole - Tor trafic dÃ©tectÃ©', 'Connexion rÃ©seau Tor', 'haute', 24, 'Utilisation Tor', 'Anonymisation ou darknet', 'T1090.003', 'snort'),
(87275, 'Protocole - VPN non autorisÃ©', 'Connexion VPN suspecte', 'moyenne', 24, 'VPN non approuvÃ© utilisÃ©', 'Contournement politique', 'T1572', 'snort'),
(87276, 'Protocole - Proxy non autorisÃ©', 'Utilisation proxy suspect', 'moyenne', 24, 'Proxy non approuvÃ©', 'Contournement filtrage', 'T1090', 'snort'),
(87277, 'Protocole - SOCKS trafic dÃ©tectÃ©', 'Proxy SOCKS identifiÃ©', 'moyenne', 24, 'Tunnel SOCKS actif', 'Pivoting ou exfiltration', 'T1090', 'snort'),
(87278, 'Protocole - P2P trafic dÃ©tectÃ©', 'Trafic peer-to-peer', 'faible', 24, 'Application P2P utilisÃ©e', 'Torrent ou partage fichiers', 'T1071', 'snort'),
(87279, 'Protocole - Bitcoin trafic', 'Communication cryptocurrency', 'moyenne', 24, 'Trafic Bitcoin dÃ©tectÃ©', 'Possible ransomware paiement', 'T1496', 'snort'),
(87280, 'Protocole - Telnet en clair', 'Auth Telnet visible', 'haute', 24, 'Credentials en clair', 'Protocole non sÃ©curisÃ©', 'T1552', 'snort'),
(87281, 'Protocole - FTP en clair', 'Auth FTP visible', 'haute', 24, 'Mot passe FTP exposÃ©', 'Protocole non sÃ©curisÃ©', 'T1552', 'snort'),
(87282, 'Protocole - HTTP Basic Auth clair', 'Credentials HTTP clair', 'haute', 24, 'Auth non chiffrÃ©e', 'Vol credentials possible', 'T1552', 'snort'),
(87283, 'Protocole - SMTP relay suspect', 'Relais SMTP non autorisÃ©', 'haute', 24, 'Serveur mail relais', 'Spam ou phishing', 'T1071.003', 'snort'),
(87284, 'Protocole - NTP amplification', 'RequÃªte NTP monlist', 'haute', 24, 'Commande NTP dangereuse', 'PrÃ©paration attaque DDoS', 'T1498.002', 'snort'),
(87285, 'Protocole - SNMP community default', 'Community SNMP dÃ©faut', 'haute', 24, 'SNMP mal configurÃ©', 'public ou private utilisÃ©', 'T1552', 'snort');

-- PHISHING & SPAM (15 rÃ¨gles) - CatÃ©gorie 25
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, source) VALUES
(87286, 'Phishing - URL suspecte dÃ©tectÃ©e', 'Lien phishing probable', 'haute', 25, 'Utilisateur ciblÃ© phishing', 'Email ou site hameÃ§onnage', 'T1566', 'snort'),
(87287, 'Phishing - Typosquatting dÃ©tectÃ©', 'Domaine similaire marque', 'haute', 25, 'Faux site imitant lÃ©gitime', 'Usurpation identitÃ©', 'T1566.002', 'snort'),
(87288, 'Phishing - Homograph attack', 'CaractÃ¨res Unicode trompeurs', 'haute', 25, 'URL visuellement trompeuse', 'CaractÃ¨res ressemblants', 'T1566.002', 'snort'),
(87289, 'Phishing - Faux login Microsoft', 'Page login O365 frauduleuse', 'critique', 25, 'Vol credentials Microsoft', 'Phishing ciblant Office 365', 'T1566.002', 'snort'),
(87290, 'Phishing - Faux login Google', 'Page login Google frauduleuse', 'critique', 25, 'Vol credentials Google', 'Phishing ciblant Gmail', 'T1566.002', 'snort'),
(87291, 'Phishing - Faux login bancaire', 'Page bancaire frauduleuse', 'critique', 25, 'Vol credentials bancaires', 'Phishing financier', 'T1566.002', 'snort'),
(87292, 'Spam - Relais spam dÃ©tectÃ©', 'Serveur utilisÃ© spam', 'haute', 25, 'Envoi massif emails', 'Serveur compromis ou mal config', 'T1071.003', 'snort'),
(87293, 'Spam - Campagne spam', 'Envoi massif dÃ©tectÃ©', 'moyenne', 25, 'Volume anormal emails', 'Campagne spam active', 'T1071.003', 'snort'),
(87294, 'Phishing - Document malveillant', 'PiÃ¨ce jointe suspecte', 'haute', 25, 'Document macro malveillante', 'Dropper piÃ¨ce jointe', 'T1566.001', 'snort'),
(87295, 'Phishing - Lien raccourci suspect', 'URL shortener vers malware', 'moyenne', 25, 'Lien bit.ly malveillant', 'Masquage URL malveillante', 'T1566.002', 'snort'),
(87296, 'Phishing - QR code malveillant', 'QR code vers site frauduleux', 'moyenne', 25, 'Quishing dÃ©tectÃ©', 'QR code phishing', 'T1566.002', 'snort'),
(87297, 'Phishing - Clone site lÃ©gitime', 'Copie site web dÃ©tectÃ©e', 'haute', 25, 'Site clonÃ© vol credentials', 'Kit phishing utilisÃ©', 'T1566.002', 'snort'),
(87298, 'Spam - Bounce attack', 'Attaque rebond email', 'moyenne', 25, 'Exploitation bounces', 'Spam via messages erreur', 'T1071.003', 'snort'),
(87299, 'Phishing - Credential harvesting', 'RÃ©colte credentials', 'critique', 25, 'Formulaire volant identifiants', 'Page capture active', 'T1566.002', 'snort'),
(87300, 'Phishing - Spear phishing dÃ©tectÃ©', 'Phishing ciblÃ© identifiÃ©', 'critique', 25, 'Attaque ciblÃ©e individu', 'Recherche prÃ©alable victime', 'T1566.001', 'snort');

-- =============================================================================
-- TABLE: RECOMMANDATIONS
-- =============================================================================

CREATE TABLE recommandations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    regle_id INTEGER NOT NULL,
    ordre INTEGER DEFAULT 1,
    action TEXT NOT NULL,
    commande TEXT,
    niveau TEXT CHECK(niveau IN ('debutant', 'intermediaire', 'avance')) DEFAULT 'debutant',
    FOREIGN KEY (regle_id) REFERENCES regles(id)
);

-- Recommandations Wazuh
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 5710), 1, 'VÃ©rifiez les logs SSH pour identifier la source', 'cat /var/log/auth.log | grep "Failed password" | tail -20', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5710), 2, 'Identifiez les IP qui tentent de se connecter', 'grep "Failed password" /var/log/auth.log | awk ''{print $11}'' | sort | uniq -c | sort -rn', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5710), 3, 'Bloquez IP suspecte avec pare-feu', 'sudo ufw deny from IP_SUSPECTE', 'intermediaire'),

((SELECT id FROM regles WHERE wazuh_rule_id = 5711), 1, 'Installez fail2ban pour bloquer automatiquement', 'sudo apt install fail2ban -y', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5711), 2, 'VÃ©rifiez statut fail2ban', 'sudo systemctl status fail2ban', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5711), 3, 'Consultez IP bannies', 'sudo fail2ban-client status sshd', 'intermediaire'),

((SELECT id FROM regles WHERE wazuh_rule_id = 5712), 1, 'URGENT: Bloquez immÃ©diatement IP attaquante', 'sudo ufw deny from IP_ATTAQUANTE', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5712), 2, 'Changez mots de passe comptes ciblÃ©s', 'sudo passwd NOM_UTILISATEUR', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5712), 3, 'DÃ©sactivez auth par mot de passe SSH', 'sudo nano /etc/ssh/sshd_config # PasswordAuthentication no', 'avance'),

((SELECT id FROM regles WHERE wazuh_rule_id = 510), 1, 'CRITIQUE: Isolez immÃ©diatement serveur', 'sudo ip link set eth0 down', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 510), 2, 'Lancez scan antirootkit', 'sudo rkhunter --check', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 510), 3, 'Analysez processus en cours', 'ps auxf | less', 'intermediaire'),

((SELECT id FROM regles WHERE wazuh_rule_id = 1004), 1, 'Identifiez source attaque logs web', 'cat /var/log/apache2/access.log | grep -i "union\\|select" | tail -20', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 1004), 2, 'Bloquez IP attaquant', 'sudo ufw deny from IP_ATTAQUANTE', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 1004), 3, 'Activez WAF ModSecurity', 'sudo apt install libapache2-mod-security2 -y', 'avance');

-- Recommandations Snort - Scan
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 87001), 1, 'Identifiez IP qui scanne votre rÃ©seau', 'cat /var/log/snort/alert | grep "scan" | tail -20', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87001), 2, 'Bloquez IP du scanner', 'sudo ufw deny from IP_SCANNER', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87001), 3, 'VÃ©rifiez ports visÃ©s', 'sudo tcpdump -i any src host IP_SCANNER -n', 'intermediaire'),

((SELECT id FROM regles WHERE wazuh_rule_id = 87009), 1, 'Outil Nmap cible votre serveur', 'cat /var/log/snort/alert | grep -i nmap', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87009), 2, 'Bloquez immÃ©diatement IP source', 'sudo ufw deny from IP_ATTAQUANTE', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87009), 3, 'Analysez ports scannÃ©s', 'grep IP_ATTAQUANTE /var/log/snort/alert', 'intermediaire');

-- Recommandations Snort - SQL Injection
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 87041), 1, 'CRITIQUE: Attaque SQL injection en cours!', 'VÃ©rifiez immÃ©diatement applications web', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87041), 2, 'Bloquez IP attaquant', 'sudo ufw deny from IP_ATTAQUANTE', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87041), 3, 'Sauvegardez base donnÃ©es', 'mysqldump --all-databases > backup_urgence.sql', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87041), 4, 'Utilisez requÃªtes prÃ©parÃ©es', 'Consultez OWASP SQL Injection Prevention', 'avance'),

((SELECT id FROM regles WHERE wazuh_rule_id = 87042), 1, 'Tentative bypass authentification SQL', 'VÃ©rifiez logs serveur web', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87042), 2, 'Bloquez IP source', 'sudo ufw deny from IP_ATTAQUANTE', 'debutant');

-- Recommandations Snort - XSS
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 87076), 1, 'Injection script malveillant dÃ©tectÃ©e', 'VÃ©rifiez logs serveur web', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87076), 2, 'Bloquez IP source attaque', 'sudo ufw deny from IP_ATTAQUANTE', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87076), 3, 'Activez en-tÃªtes sÃ©curitÃ©', 'Ajoutez Content-Security-Policy config web', 'intermediaire'),

((SELECT id FROM regles WHERE wazuh_rule_id = 87086), 1, 'CRITIQUE: Vol cookies dÃ©tectÃ©!', 'Invalidez toutes sessions utilisateurs', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87086), 2, 'Bloquez IP attaquant', 'sudo ufw deny from IP_ATTAQUANTE', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87086), 3, 'Activez HttpOnly sur cookies', 'Modifiez config application', 'avance');

-- Recommandations Snort - DDoS
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 87111), 1, 'URGENT: Attaque DDoS en cours!', 'Contactez hÃ©bergeur ou FAI immÃ©diatement', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87111), 2, 'Activez SYN cookies', 'echo 1 > /proc/sys/net/ipv4/tcp_syncookies', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87111), 3, 'Limitez connexions par IP', 'sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT', 'avance'),

((SELECT id FROM regles WHERE wazuh_rule_id = 87114), 1, 'Attaque HTTP Flood dÃ©tectÃ©e', 'VÃ©rifiez charge serveur web', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87114), 2, 'Activez rate limiting', 'Configurez mod_evasive Apache', 'intermediaire');

-- Recommandations Snort - Backdoors
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 87146), 1, 'CRITIQUE: Attaquant a accÃ¨s systÃ¨me!', 'Isolez immÃ©diatement serveur', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87146), 2, 'Identifiez connexions sortantes', 'sudo netstat -tulpn | grep ESTABLISHED', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87146), 3, 'Tuez processus suspects', 'sudo kill -9 PID_SUSPECT', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87146), 4, 'Analysez fichiers rÃ©cemment modifiÃ©s', 'find / -mtime -1 -type f 2>/dev/null | head -50', 'avance'),

((SELECT id FROM regles WHERE wazuh_rule_id = 87149), 1, 'CRITIQUE: Web shell PHP dÃ©tectÃ©!', 'Identifiez et supprimez fichier', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87149), 2, 'Recherchez fichiers PHP suspects', 'find /var/www -name "*.php" -mtime -7 -type f', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87149), 3, 'VÃ©rifiez logs accÃ¨s', 'grep -r "cmd=\\|exec\\|system" /var/log/apache2/', 'intermediaire');

-- Recommandations Snort - Brute Force
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 87176), 1, 'Attaque brute force SSH dÃ©tectÃ©e Snort', 'VÃ©rifiez tentatives connexion', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87176), 2, 'Bloquez IP attaquante', 'sudo ufw deny from IP_ATTAQUANTE', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87176), 3, 'Installez fail2ban', 'sudo apt install fail2ban && sudo systemctl enable fail2ban', 'intermediaire'),

((SELECT id FROM regles WHERE wazuh_rule_id = 87181), 1, 'Attaque brute force RDP dÃ©tectÃ©e', 'Limitez accÃ¨s RDP par IP', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87181), 2, 'Activez NLA sur RDP', 'Configurez Network Level Authentication', 'intermediaire');

-- Recommandations Snort - Malware
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 87236), 1, 'CRITIQUE: Ransomware! Isolez systÃ¨me!', 'DÃ©branchez cÃ¢ble rÃ©seau physiquement', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87236), 2, 'NE PAYEZ PAS ranÃ§on', 'Contactez autoritÃ©s (police, ANSSI)', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87236), 3, 'Identifiez type ransomware', 'Consultez nomoreransom.org', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87236), 4, 'Restaurez depuis sauvegardes', 'Utilisez sauvegardes hors ligne', 'avance'),

((SELECT id FROM regles WHERE wazuh_rule_id = 87240), 1, 'Malware Emotet - Isolez systÃ¨me', 'DÃ©connectez rÃ©seau immÃ©diatement', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87240), 2, 'Changez tous mots de passe', 'Utilisez ordinateur non infectÃ©', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87240), 3, 'Scannez plusieurs antivirus', 'Malwarebytes, ESET Online Scanner', 'intermediaire');

-- Recommandations Snort - Phishing
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 87286), 1, 'Lien phishing dÃ©tectÃ© - NE CLIQUEZ PAS', 'Supprimez email ou fermez page', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87286), 2, 'Si cliquÃ©, changez mots de passe', 'Commencez par comptes bancaires et email', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87286), 3, 'Signalez phishing', 'signal-spam.fr ou phishing-initiative.fr', 'intermediaire'),

((SELECT id FROM regles WHERE wazuh_rule_id = 87289), 1, 'CRITIQUE: Faux login Microsoft dÃ©tectÃ©', 'Alertez utilisateurs de ne pas se connecter', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 87289), 2, 'Bloquez domaine malveillant', 'Ajoutez Ã  blacklist DNS', 'intermediaire');

-- Recommandation par dÃ©faut
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
((SELECT id FROM regles WHERE wazuh_rule_id = 99999), 1, 'Analysez dÃ©tail alerte dans Wazuh', 'cat /var/ossec/logs/alerts/alerts.json | tail -20', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 99999), 2, 'Recherchez informations rÃ¨gle', 'Consultez documentation Wazuh', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 99999), 3, 'Contactez Ã©quipe sÃ©curitÃ© si nÃ©cessaire', 'Escaladez selon procÃ©dure interne', 'debutant');

-- =============================================================================
-- TABLE: ALERTES_LOG (Historique des alertes)
-- =============================================================================

CREATE TABLE alertes_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    wazuh_alert_id TEXT,
    wazuh_rule_id INTEGER,
    agent_id TEXT,
    agent_name TEXT,
    source_ip TEXT,
    dest_ip TEXT,
    source_port INTEGER,
    dest_port INTEGER,
    protocole TEXT,
    utilisateur TEXT,
    description_originale TEXT,
    log_complet TEXT,
    gravite TEXT,
    statut TEXT DEFAULT 'nouveau' CHECK(statut IN ('nouveau', 'vu', 'en_cours', 'traite', 'ignore', 'faux_positif')),
    note TEXT,
    traite_par TEXT,
    traite_le DATETIME,
    FOREIGN KEY (wazuh_rule_id) REFERENCES regles(wazuh_rule_id)
);

-- =============================================================================
-- TABLE: UTILISATEURS (Authentification Dashboard)
-- =============================================================================

CREATE TABLE utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    nom_complet TEXT,
    role TEXT DEFAULT 'analyste' CHECK(role IN ('admin', 'analyste', 'lecteur')),
    must_change_password INTEGER DEFAULT 1,
    password_created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    password_expires_at DATETIME,
    last_login DATETIME,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    actif INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- TABLE: SESSIONS
-- =============================================================================

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES utilisateurs(id)
);

-- =============================================================================
-- TABLE: AUDIT_LOG
-- =============================================================================

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    success INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES utilisateurs(id)
);

-- =============================================================================
-- INDEX POUR PERFORMANCES
-- =============================================================================

CREATE INDEX idx_regles_wazuh_rule_id ON regles(wazuh_rule_id);
CREATE INDEX idx_regles_categorie ON regles(categorie_id);
CREATE INDEX idx_regles_gravite ON regles(gravite);
CREATE INDEX idx_regles_source ON regles(source);
CREATE INDEX idx_alertes_timestamp ON alertes_log(timestamp);
CREATE INDEX idx_alertes_wazuh_rule ON alertes_log(wazuh_rule_id);
CREATE INDEX idx_alertes_statut ON alertes_log(statut);
CREATE INDEX idx_alertes_gravite ON alertes_log(gravite);
CREATE INDEX idx_alertes_source_ip ON alertes_log(source_ip);
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_recommandations_regle ON recommandations(regle_id);

-- =============================================================================
-- VUES UTILES
-- =============================================================================

-- Vue: Alertes complÃ¨tes avec traduction
CREATE VIEW vue_alertes_completes AS
SELECT 
    a.id,
    a.timestamp,
    a.wazuh_alert_id,
    a.wazuh_rule_id,
    r.nom_fr AS nom_alerte,
    r.description AS description_fr,
    r.gravite,
    r.impact,
    r.cause_probable,
    r.mitre_id,
    r.source AS source_regle,
    c.nom AS categorie,
    c.icone,
    c.couleur,
    a.agent_id,
    a.agent_name,
    a.source_ip,
    a.dest_ip,
    a.source_port,
    a.dest_port,
    a.protocole,
    a.utilisateur,
    a.description_originale,
    a.statut,
    a.note
FROM alertes_log a
LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
LEFT JOIN categories c ON r.categorie_id = c.id;

-- Vue: Statistiques par gravitÃ©
CREATE VIEW vue_stats_gravite AS
SELECT 
    gravite,
    COUNT(*) AS total,
    SUM(CASE WHEN statut = 'nouveau' THEN 1 ELSE 0 END) AS non_traites
FROM alertes_log
WHERE timestamp >= datetime('now', '-24 hours')
GROUP BY gravite;

-- Vue: Statistiques par catÃ©gorie
CREATE VIEW vue_stats_categorie AS
SELECT 
    c.nom AS categorie,
    c.icone,
    r.source,
    COUNT(a.id) AS total
FROM alertes_log a
LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
LEFT JOIN categories c ON r.categorie_id = c.id
WHERE a.timestamp >= datetime('now', '-7 days')
GROUP BY c.id, r.source
ORDER BY total DESC;

-- Vue: Top IP sources
CREATE VIEW vue_top_ip_sources AS
SELECT 
    source_ip,
    COUNT(*) AS total,
    MAX(timestamp) AS derniere_alerte
FROM alertes_log
WHERE source_ip IS NOT NULL 
  AND source_ip != ''
  AND timestamp >= datetime('now', '-24 hours')
GROUP BY source_ip
ORDER BY total DESC
LIMIT 10;

-- Vue: RÃ©sumÃ© des rÃ¨gles par source
CREATE VIEW vue_regles_par_source AS
SELECT 
    source,
    COUNT(*) AS total_regles,
    SUM(CASE WHEN gravite = 'critique' THEN 1 ELSE 0 END) AS critiques,
    SUM(CASE WHEN gravite = 'haute' THEN 1 ELSE 0 END) AS hautes,
    SUM(CASE WHEN gravite = 'moyenne' THEN 1 ELSE 0 END) AS moyennes,
    SUM(CASE WHEN gravite = 'faible' THEN 1 ELSE 0 END) AS faibles,
    SUM(CASE WHEN gravite = 'info' THEN 1 ELSE 0 END) AS infos
FROM regles
GROUP BY source;

-- =============================================================================
-- VÃ‰RIFICATION FINALE
-- =============================================================================

SELECT 'âœ… Base de donnÃ©es SIEM Africa crÃ©Ã©e avec succÃ¨s!' AS message;
SELECT 'Total rÃ¨gles: ' || COUNT(*) FROM regles;
SELECT 'RÃ¨gles Wazuh: ' || COUNT(*) FROM regles WHERE source = 'wazuh';
SELECT 'RÃ¨gles Snort: ' || COUNT(*) FROM regles WHERE source = 'snort';
SELECT 'CatÃ©gories: ' || COUNT(*) FROM categories;
SELECT 'Recommandations: ' || COUNT(*) FROM recommandations;

-- =============================================================================
-- FIN DU SCRIPT SQL - SIEM AFRICA v2.0
-- =============================================================================
-- 
-- RÃ©sumÃ©:
-- - 25 catÃ©gories d'alertes
-- - 207 rÃ¨gles Wazuh traduites en franÃ§ais
-- - 300 rÃ¨gles Snort traduites en franÃ§ais
-- - 507 rÃ¨gles au total
-- - Recommandations adaptÃ©es aux dÃ©butants
--
-- Projet: SIEM Africa - 
-- =============================================================================

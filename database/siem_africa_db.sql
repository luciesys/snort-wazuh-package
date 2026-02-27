-- ============================================================================
-- BASE DE DONNÉES SIEM AFRICA
-- 200 règles Wazuh traduites en français avec recommandations
-- ============================================================================

-- Suppression des tables existantes
DROP TABLE IF EXISTS recommandations;
DROP TABLE IF EXISTS alertes_log;
DROP TABLE IF EXISTS regles;
DROP TABLE IF EXISTS categories;

-- ============================================================================
-- TABLE: CATEGORIES (Catégories officielles Wazuh + Non identifié)
-- ============================================================================
CREATE TABLE categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    nom TEXT NOT NULL,
    description TEXT,
    icone TEXT,
    couleur TEXT
);

INSERT INTO categories (code, nom, description, icone, couleur) VALUES
('syslog', 'Logs Système', 'Événements système généraux (syslog, journald)', '⚙️', '#6c757d'),
('firewall', 'Pare-feu', 'Événements de filtrage réseau et pare-feu', '🛡️', '#fd7e14'),
('ids', 'Détection Intrusion', 'Alertes IDS/IPS (Snort, Suricata)', '🚨', '#dc3545'),
('web_log', 'Serveurs Web', 'Logs Apache, Nginx, IIS', '🌐', '#0dcaf0'),
('squid', 'Proxy', 'Logs proxy Squid et filtrage web', '🔀', '#6f42c1'),
('windows', 'Windows', 'Événements Windows (EventLog)', '🪟', '#0d6efd'),
('ossec', 'Wazuh Interne', 'Alertes internes de Wazuh/OSSEC', '👁️', '#20c997'),
('authentication_success', 'Authentification Réussie', 'Connexions et authentifications réussies', '✅', '#198754'),
('authentication_failed', 'Authentification Échouée', 'Tentatives de connexion échouées', '❌', '#dc3545'),
('attack', 'Attaques', 'Attaques actives détectées', '⚔️', '#dc3545'),
('malware', 'Malware', 'Logiciels malveillants détectés', '🦠', '#6f42c1'),
('rootkit', 'Rootkit', 'Rootkits et backdoors détectés', '👾', '#343a40'),
('file_integrity', 'Intégrité Fichiers', 'Modifications de fichiers surveillés (FIM)', '📁', '#ffc107'),
('vulnerability', 'Vulnérabilités', 'Failles de sécurité détectées', '🔓', '#fd7e14'),
('network', 'Réseau', 'Activité réseau suspecte', '📡', '#0dcaf0'),
('policy', 'Politique', 'Violations des politiques de sécurité', '📋', '#6c757d'),
('ssh', 'SSH', 'Connexions et événements SSH', '🔑', '#198754'),
('sudo', 'Sudo', 'Utilisation des privilèges sudo', '👤', '#ffc107'),
('pam', 'PAM', 'Modules d authentification PAM', '🔐', '#6c757d'),
('non_identifie', 'Non Identifié', 'Alerte non reconnue par la base - Analyse manuelle requise', '❓', '#adb5bd');

-- ============================================================================
-- TABLE: REGLES (200 règles Wazuh traduites)
-- ============================================================================
CREATE TABLE regles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wazuh_rule_id INTEGER UNIQUE NOT NULL,
    nom_fr TEXT NOT NULL,
    description TEXT NOT NULL,
    gravite TEXT CHECK(gravite IN ('critique', 'haute', 'moyenne', 'faible', 'info')) NOT NULL,
    categorie_id INTEGER,
    impact TEXT,
    cause_probable TEXT,
    mitre_id TEXT,
    FOREIGN KEY (categorie_id) REFERENCES categories(id)
);

-- ============================================================================
-- RÈGLES SSH (5700-5799)
-- ============================================================================
INSERT INTO regles (wazuh_rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id) VALUES
(5701, 'Connexion SSH possible par attaque brute force', 'Plusieurs tentatives de connexion SSH ont réussi après de nombreux échecs. Cela indique une possible compromission par attaque brute force.', 'critique', 17, 'Accès non autorisé au serveur', 'Mot de passe faible ou attaque automatisée', 'T1110'),
(5702, 'Connexion SSH inversée détectée', 'Une connexion SSH inversée (reverse shell) a été détectée. Un attaquant pourrait contrôler le serveur à distance.', 'critique', 17, 'Contrôle à distance par un attaquant', 'Serveur compromis ou backdoor installée', 'T1572'),
(5703, 'Tentative de connexion SSH avec utilisateur inexistant', 'Quelqu un a tenté de se connecter avec un nom d utilisateur qui n existe pas sur le système.', 'moyenne', 17, 'Reconnaissance du système', 'Scan automatisé ou attaque ciblée', 'T1078'),
(5704, 'Tentative de connexion SSH avec utilisateur root', 'Une tentative de connexion directe en tant que root a été détectée. Cette pratique est dangereuse.', 'haute', 17, 'Tentative d accès privilégié', 'Attaque brute force sur root', 'T1078'),
(5705, 'Authentification SSH échouée', 'Une tentative de connexion SSH a échoué. Cela peut être une erreur de mot de passe ou une tentative d intrusion.', 'faible', 17, 'Aucun si isolé', 'Erreur utilisateur ou tentative d intrusion', 'T1110'),
(5706, 'Authentification SSH réussie', 'Une connexion SSH a été établie avec succès.', 'info', 8, 'Session ouverte sur le serveur', 'Connexion légitime ou compromission', NULL),
(5707, 'Tentatives multiples de connexion SSH échouées', 'Plusieurs tentatives de connexion SSH ont échoué en peu de temps. Probable attaque brute force en cours.', 'haute', 17, 'Surcharge du service SSH', 'Attaque brute force automatisée', 'T1110'),
(5708, 'Déconnexion SSH', 'Une session SSH a été fermée normalement.', 'info', 17, 'Aucun', 'Déconnexion normale', NULL),
(5709, 'Erreur de protocole SSH', 'Une erreur de protocole SSH a été détectée. Possible tentative d exploitation.', 'moyenne', 17, 'Instabilité du service', 'Client incompatible ou attaque', 'T1190'),
(5710, 'Tentative de connexion SSH - mot de passe incorrect', 'Le mot de passe fourni pour la connexion SSH est incorrect.', 'faible', 9, 'Aucun si isolé', 'Erreur de frappe ou attaque', 'T1110'),
(5711, 'Attaque brute force SSH détectée', 'Un grand nombre de tentatives de connexion SSH échouées ont été détectées depuis la même IP.', 'critique', 10, 'Risque de compromission', 'Attaque automatisée', 'T1110'),
(5712, 'Connexion SSH depuis une nouvelle IP', 'Une connexion SSH réussie provient d une adresse IP jamais vue auparavant.', 'moyenne', 8, 'Possible accès non autorisé', 'Nouvel emplacement ou compromission', 'T1078'),
(5715, 'Trop de sessions SSH ouvertes', 'Le nombre maximum de sessions SSH simultanées a été atteint.', 'moyenne', 17, 'Déni de service possible', 'Charge normale ou attaque', 'T1499'),
(5716, 'Clé SSH invalide utilisée', 'Une tentative de connexion avec une clé SSH non autorisée a été détectée.', 'haute', 9, 'Tentative d accès non autorisé', 'Clé volée ou mauvaise configuration', 'T1078'),
(5720, 'Version SSH obsolète détectée', 'Un client utilise une version SSH ancienne et potentiellement vulnérable.', 'moyenne', 14, 'Risque d exploitation', 'Client non mis à jour', 'T1190'),

-- ============================================================================
-- RÈGLES AUTHENTIFICATION PAM (5500-5599)
-- ============================================================================
(5500, 'Connexion utilisateur réussie', 'Un utilisateur s est connecté avec succès au système.', 'info', 8, 'Session ouverte', 'Connexion normale', NULL),
(5501, 'Session utilisateur ouverte', 'Une nouvelle session a été ouverte pour un utilisateur.', 'info', 8, 'Accès au système', 'Connexion normale', NULL),
(5502, 'Session utilisateur fermée', 'La session d un utilisateur a été fermée.', 'info', 8, 'Aucun', 'Déconnexion normale', NULL),
(5503, 'Échec d authentification utilisateur', 'L authentification d un utilisateur a échoué.', 'moyenne', 9, 'Accès refusé', 'Mauvais mot de passe ou attaque', 'T1110'),
(5504, 'Compte utilisateur verrouillé', 'Un compte a été verrouillé après trop de tentatives échouées.', 'haute', 9, 'Utilisateur bloqué', 'Attaque brute force ou oubli', 'T1110'),
(5505, 'Tentative de connexion avec compte désactivé', 'Quelqu un a tenté de se connecter avec un compte désactivé.', 'moyenne', 9, 'Aucun', 'Ancien employé ou erreur', 'T1078'),
(5506, 'Changement de mot de passe', 'Un utilisateur a changé son mot de passe.', 'info', 19, 'Mot de passe modifié', 'Action normale', NULL),
(5507, 'Changement de mot de passe échoué', 'Une tentative de changement de mot de passe a échoué.', 'faible', 19, 'Aucun', 'Mot de passe non conforme', NULL),
(5508, 'Compte utilisateur expiré', 'Un compte a expiré et l accès a été refusé.', 'moyenne', 9, 'Accès bloqué', 'Compte temporaire expiré', NULL),
(5509, 'Mot de passe expiré', 'Le mot de passe d un utilisateur a expiré.', 'faible', 19, 'Changement requis', 'Politique de sécurité', NULL),
(5510, 'Utilisateur ajouté au système', 'Un nouvel utilisateur a été créé sur le système.', 'moyenne', 16, 'Nouveau compte', 'Administration normale ou compromission', 'T1136'),
(5511, 'Utilisateur supprimé du système', 'Un utilisateur a été supprimé du système.', 'moyenne', 16, 'Compte supprimé', 'Administration normale', NULL),
(5512, 'Groupe utilisateur modifié', 'Les groupes d un utilisateur ont été modifiés.', 'moyenne', 16, 'Permissions changées', 'Administration ou élévation', 'T1078'),
(5513, 'Utilisateur ajouté au groupe sudo', 'Un utilisateur a été ajouté au groupe des administrateurs (sudo).', 'haute', 18, 'Nouveaux privilèges admin', 'Administration ou compromission', 'T1078'),

-- ============================================================================
-- RÈGLES SUDO (5400-5499)
-- ============================================================================
(5400, 'Commande sudo exécutée', 'Un utilisateur a exécuté une commande avec les privilèges sudo.', 'info', 18, 'Action privilégiée', 'Administration normale', NULL),
(5401, 'Tentative sudo non autorisée', 'Un utilisateur a tenté d utiliser sudo sans y être autorisé.', 'haute', 18, 'Tentative d élévation', 'Erreur ou tentative malveillante', 'T1548'),
(5402, 'Mauvais mot de passe sudo', 'Un utilisateur a entré un mauvais mot de passe pour sudo.', 'moyenne', 18, 'Accès sudo refusé', 'Erreur ou tentative', 'T1548'),
(5403, 'Trois échecs sudo consécutifs', 'Un utilisateur a échoué trois fois à s authentifier pour sudo.', 'haute', 18, 'Possible attaque', 'Attaque ou oubli mot de passe', 'T1548'),
(5404, 'Commande sudo interdite', 'Un utilisateur a tenté d exécuter une commande sudo non autorisée.', 'haute', 18, 'Violation de politique', 'Tentative de contournement', 'T1548'),
(5405, 'Session sudo ouverte', 'Une session sudo a été ouverte pour un utilisateur.', 'info', 18, 'Session admin active', 'Administration normale', NULL),
(5406, 'Session sudo fermée', 'Une session sudo a été fermée.', 'info', 18, 'Aucun', 'Fin normale', NULL),
(5407, 'Sudo exécuté en tant que autre utilisateur', 'Un utilisateur a utilisé sudo pour agir en tant qu un autre utilisateur.', 'moyenne', 18, 'Usurpation d identité', 'Administration ou abus', 'T1548'),

-- ============================================================================
-- RÈGLES INTÉGRITÉ DES FICHIERS (550-599)
-- ============================================================================
(550, 'Fichier modifié', 'Un fichier surveillé a été modifié.', 'moyenne', 13, 'Fichier altéré', 'Mise à jour ou compromission', 'T1565'),
(551, 'Fichier ajouté', 'Un nouveau fichier a été créé dans un répertoire surveillé.', 'moyenne', 13, 'Nouveau fichier', 'Installation ou malware', 'T1105'),
(552, 'Fichier supprimé', 'Un fichier surveillé a été supprimé.', 'moyenne', 13, 'Fichier perdu', 'Maintenance ou sabotage', 'T1485'),
(553, 'Permissions fichier modifiées', 'Les permissions d un fichier surveillé ont changé.', 'moyenne', 13, 'Accès modifié', 'Administration ou backdoor', 'T1222'),
(554, 'Propriétaire fichier modifié', 'Le propriétaire d un fichier surveillé a changé.', 'moyenne', 13, 'Propriété changée', 'Administration ou compromission', 'T1222'),
(555, 'Attributs fichier modifiés', 'Les attributs d un fichier surveillé ont été modifiés.', 'faible', 13, 'Métadonnées changées', 'Opération normale ou suspecte', NULL),
(556, 'Fichier binaire système modifié', 'Un fichier binaire système critique a été modifié.', 'critique', 13, 'Système potentiellement compromis', 'Mise à jour ou rootkit', 'T1554'),
(557, 'Fichier de configuration modifié', 'Un fichier de configuration important a été modifié.', 'haute', 13, 'Configuration altérée', 'Administration ou backdoor', 'T1565'),
(558, 'Fichier dans /etc modifié', 'Un fichier dans le répertoire /etc a été modifié.', 'moyenne', 13, 'Configuration système changée', 'Administration normale ou suspecte', 'T1565'),
(559, 'Fichier crontab modifié', 'Un fichier de tâches planifiées (cron) a été modifié.', 'haute', 13, 'Tâches planifiées changées', 'Maintenance ou persistence malware', 'T1053'),

-- ============================================================================
-- RÈGLES ROOTKIT (510-549)
-- ============================================================================
(510, 'Rootkit détecté - fichier suspect', 'Un fichier associé à un rootkit connu a été détecté.', 'critique', 12, 'Système compromis', 'Infection par rootkit', 'T1014'),
(511, 'Rootkit détecté - processus caché', 'Un processus caché typique des rootkits a été détecté.', 'critique', 12, 'Activité malveillante cachée', 'Rootkit actif', 'T1014'),
(512, 'Rootkit détecté - port caché', 'Un port réseau caché a été détecté, indiquant un possible rootkit.', 'critique', 12, 'Communication cachée', 'Backdoor active', 'T1014'),
(513, 'Rootkit détecté - interface promiscuous', 'L interface réseau est en mode promiscuous sans raison valable.', 'haute', 12, 'Capture de trafic possible', 'Sniffer ou rootkit', 'T1040'),
(514, 'Anomalie dans /dev', 'Un fichier suspect a été détecté dans /dev.', 'haute', 12, 'Possible backdoor', 'Rootkit ou malware', 'T1014'),
(515, 'Fichier caché suspect', 'Un fichier caché suspect a été découvert.', 'moyenne', 12, 'Fichier malveillant possible', 'Malware ou rootkit', 'T1564'),
(516, 'Répertoire caché suspect', 'Un répertoire caché suspect a été découvert.', 'moyenne', 12, 'Stockage malveillant possible', 'Malware ou intrusion', 'T1564'),
(517, 'Binaire système altéré', 'Un binaire système semble avoir été altéré par un rootkit.', 'critique', 12, 'Système compromis', 'Rootkit installé', 'T1014'),
(518, 'Signature de trojans détectée', 'Une signature connue de trojan a été détectée.', 'critique', 11, 'Malware actif', 'Infection par trojan', 'T1059'),
(519, 'Processus suspect détecté', 'Un processus avec un comportement suspect a été détecté.', 'haute', 11, 'Activité malveillante possible', 'Malware ou intrusion', 'T1059'),

-- ============================================================================
-- RÈGLES PARE-FEU IPTABLES (4100-4199)
-- ============================================================================
(4100, 'Paquet rejeté par le pare-feu', 'Le pare-feu a bloqué un paquet entrant.', 'info', 2, 'Aucun - protection active', 'Trafic non autorisé', NULL),
(4101, 'Tentative de connexion bloquée', 'Une tentative de connexion a été bloquée par le pare-feu.', 'faible', 2, 'Connexion refusée', 'Scan ou erreur', 'T1046'),
(4102, 'Scan de ports détecté', 'Plusieurs tentatives de connexion sur différents ports ont été détectées.', 'haute', 2, 'Reconnaissance active', 'Scan de ports automatisé', 'T1046'),
(4103, 'Tentative d accès port SSH bloquée', 'Une tentative de connexion SSH a été bloquée.', 'moyenne', 2, 'Accès SSH refusé', 'IP non autorisée ou attaque', 'T1110'),
(4104, 'Tentative d accès port dangereux', 'Une connexion vers un port dangereux connu a été bloquée.', 'haute', 2, 'Attaque potentielle bloquée', 'Tentative d exploitation', 'T1046'),
(4105, 'Flood SYN détecté', 'Un grand nombre de paquets SYN ont été détectés (possible attaque DDoS).', 'critique', 2, 'Déni de service possible', 'Attaque DDoS', 'T1498'),
(4106, 'Paquet malformé bloqué', 'Un paquet réseau malformé a été bloqué.', 'moyenne', 2, 'Protection active', 'Attaque ou erreur réseau', 'T1190'),
(4107, 'Règle pare-feu modifiée', 'Une règle du pare-feu a été modifiée.', 'haute', 2, 'Configuration changée', 'Administration ou compromission', 'T1562'),
(4108, 'Pare-feu désactivé', 'Le pare-feu a été désactivé.', 'critique', 2, 'Protection désactivée', 'Administration ou attaque', 'T1562'),
(4109, 'Connexion sortante suspecte bloquée', 'Une connexion sortante vers une destination suspecte a été bloquée.', 'haute', 2, 'Exfiltration possible bloquée', 'Malware ou erreur', 'T1048'),

-- ============================================================================
-- RÈGLES SERVEUR WEB APACHE/NGINX (31100-31199)
-- ============================================================================
(31100, 'Erreur 400 - Requête invalide', 'Le serveur web a reçu une requête mal formée.', 'faible', 4, 'Aucun', 'Client défectueux ou scan', NULL),
(31101, 'Tentative d injection SQL', 'Une tentative d injection SQL a été détectée dans une requête web.', 'critique', 10, 'Base de données à risque', 'Attaque injection SQL', 'T1190'),
(31102, 'Tentative de Cross-Site Scripting (XSS)', 'Une tentative d injection XSS a été détectée.', 'haute', 10, 'Utilisateurs à risque', 'Attaque XSS', 'T1059'),
(31103, 'Tentative de traversée de répertoire', 'Une tentative d accès à des fichiers hors du répertoire web a été détectée.', 'haute', 10, 'Fichiers sensibles à risque', 'Attaque path traversal', 'T1083'),
(31104, 'Erreur 403 - Accès interdit', 'Un accès à une ressource interdite a été tenté.', 'faible', 4, 'Accès refusé', 'Erreur ou tentative', NULL),
(31105, 'Erreur 404 répétée', 'De nombreuses erreurs 404 proviennent de la même source.', 'moyenne', 4, 'Scan en cours', 'Scan de vulnérabilités', 'T1595'),
(31106, 'Erreur 500 - Erreur serveur', 'Le serveur web a rencontré une erreur interne.', 'moyenne', 4, 'Service instable', 'Bug ou attaque', NULL),
(31107, 'Tentative d accès à fichier sensible', 'Une tentative d accès à un fichier sensible (.htaccess, .env, etc.) a été détectée.', 'haute', 10, 'Informations sensibles à risque', 'Reconnaissance ou attaque', 'T1083'),
(31108, 'User-Agent suspect détecté', 'Une requête avec un User-Agent malveillant connu a été détectée.', 'moyenne', 4, 'Bot ou scanner', 'Scan automatisé', 'T1595'),
(31109, 'Tentative d exploitation de vulnérabilité web', 'Une tentative d exploitation d une vulnérabilité web connue a été détectée.', 'critique', 10, 'Serveur web à risque', 'Attaque ciblée', 'T1190'),
(31110, 'Upload de fichier suspect', 'Un fichier potentiellement malveillant a été uploadé.', 'haute', 10, 'Malware possible sur serveur', 'Tentative d injection', 'T1105'),
(31111, 'Requête POST anormalement longue', 'Une requête POST de taille anormale a été reçue.', 'moyenne', 4, 'Possible attaque', 'Injection ou DoS', 'T1499'),
(31112, 'Tentative d accès admin', 'Une tentative d accès à une interface d administration web a été détectée.', 'haute', 10, 'Accès admin à risque', 'Brute force ou scan', 'T1110'),
(31115, 'Shellshock tentative détectée', 'Une tentative d exploitation de la vulnérabilité Shellshock a été détectée.', 'critique', 10, 'Exécution de code à risque', 'Attaque Shellshock', 'T1190'),
(31120, 'Scan Nikto détecté', 'Un scan de vulnérabilités Nikto a été détecté.', 'haute', 10, 'Reconnaissance active', 'Scan de sécurité', 'T1595'),
(31121, 'Scan Nmap détecté', 'Un scan Nmap a été détecté sur le serveur web.', 'moyenne', 10, 'Reconnaissance réseau', 'Scan de ports', 'T1046'),
(31122, 'Robot malveillant détecté', 'Un robot d indexation malveillant a été détecté.', 'faible', 4, 'Surcharge possible', 'Bot non autorisé', 'T1595'),
(31130, 'Attaque par déni de service web', 'Un grand nombre de requêtes provenant d une même source a été détecté.', 'critique', 10, 'Service web à risque', 'Attaque DDoS', 'T1498'),
(31131, 'Slowloris attack détectée', 'Une attaque Slowloris (connexions lentes) a été détectée.', 'haute', 10, 'Épuisement des connexions', 'Attaque DoS', 'T1499'),

-- ============================================================================
-- RÈGLES WINDOWS (18100-18199, 60100-60199)
-- ============================================================================
(18100, 'Connexion Windows réussie', 'Un utilisateur s est connecté avec succès à un système Windows.', 'info', 6, 'Session ouverte', 'Connexion normale', NULL),
(18101, 'Échec de connexion Windows', 'Une tentative de connexion Windows a échoué.', 'faible', 6, 'Accès refusé', 'Erreur ou attaque', 'T1110'),
(18102, 'Compte Windows verrouillé', 'Un compte Windows a été verrouillé après trop d échecs.', 'haute', 6, 'Compte bloqué', 'Attaque brute force', 'T1110'),
(18103, 'Compte Windows créé', 'Un nouveau compte utilisateur Windows a été créé.', 'moyenne', 6, 'Nouveau compte', 'Administration ou compromission', 'T1136'),
(18104, 'Compte Windows supprimé', 'Un compte utilisateur Windows a été supprimé.', 'moyenne', 6, 'Compte supprimé', 'Administration normale', NULL),
(18105, 'Mot de passe Windows changé', 'Le mot de passe d un compte Windows a été modifié.', 'faible', 6, 'Mot de passe changé', 'Action normale ou suspecte', 'T1098'),
(18106, 'Utilisateur ajouté aux Administrateurs', 'Un utilisateur a été ajouté au groupe Administrateurs.', 'critique', 6, 'Nouveaux privilèges admin', 'Administration ou compromission', 'T1078'),
(18107, 'Service Windows installé', 'Un nouveau service Windows a été installé.', 'haute', 6, 'Nouveau service', 'Installation ou malware', 'T1543'),
(18108, 'Tâche planifiée créée', 'Une nouvelle tâche planifiée Windows a été créée.', 'moyenne', 6, 'Tâche automatique', 'Administration ou persistence', 'T1053'),
(18109, 'Tentative d accès à objet sensible', 'Une tentative d accès à un objet sensible Windows a été détectée.', 'haute', 6, 'Accès non autorisé', 'Élévation de privilèges', 'T1078'),
(18110, 'Politique d audit modifiée', 'La politique d audit Windows a été modifiée.', 'haute', 6, 'Audit modifié', 'Administration ou dissimulation', 'T1562'),
(18111, 'Journal d événements effacé', 'Un journal d événements Windows a été effacé.', 'critique', 6, 'Traces supprimées', 'Dissimulation d activité', 'T1070'),
(60101, 'Attaque brute force Windows détectée', 'Nombreuses tentatives de connexion Windows échouées depuis la même source.', 'critique', 6, 'Risque de compromission', 'Attaque automatisée', 'T1110'),
(60102, 'Pass-the-hash détecté', 'Une tentative d authentification pass-the-hash a été détectée.', 'critique', 6, 'Credentials compromis', 'Attaque latérale', 'T1550'),
(60103, 'PowerShell suspect exécuté', 'Une commande PowerShell suspecte a été exécutée.', 'haute', 6, 'Exécution de code', 'Malware ou attaque', 'T1059'),
(60104, 'Exécution depuis emplacement suspect', 'Un programme a été exécuté depuis un emplacement inhabituel.', 'haute', 6, 'Malware possible', 'Téléchargement malveillant', 'T1204'),

-- ============================================================================
-- RÈGLES SYSTÈME LINUX (5100-5199)
-- ============================================================================
(5100, 'Redémarrage système détecté', 'Le système a été redémarré.', 'info', 1, 'Service interrompu', 'Maintenance ou crash', NULL),
(5101, 'Arrêt système détecté', 'Le système a été arrêté.', 'info', 1, 'Service arrêté', 'Maintenance normale', NULL),
(5102, 'Kernel panic', 'Le système a subi un kernel panic.', 'critique', 1, 'Système crashé', 'Bug ou attaque', NULL),
(5103, 'Espace disque critique', 'L espace disque disponible est critique (moins de 5%).', 'haute', 1, 'Risque de panne', 'Logs ou données excessives', NULL),
(5104, 'Mémoire insuffisante', 'Le système manque de mémoire RAM.', 'haute', 1, 'Performance dégradée', 'Charge excessive ou fuite mémoire', NULL),
(5105, 'OOM Killer activé', 'Le système a dû tuer des processus par manque de mémoire.', 'critique', 1, 'Processus tués', 'Charge excessive', NULL),
(5106, 'Service critique arrêté', 'Un service système critique s est arrêté.', 'haute', 1, 'Service indisponible', 'Crash ou arrêt manuel', NULL),
(5107, 'Erreur matérielle détectée', 'Une erreur matérielle a été détectée dans les logs.', 'haute', 1, 'Risque de panne matérielle', 'Défaillance hardware', NULL),
(5108, 'Nouveau kernel chargé', 'Un nouveau noyau Linux a été chargé.', 'info', 1, 'Kernel mis à jour', 'Mise à jour système', NULL),
(5109, 'Module kernel chargé', 'Un module kernel a été chargé.', 'faible', 1, 'Nouveau module actif', 'Driver ou rootkit', 'T1547'),
(5110, 'Module kernel suspect chargé', 'Un module kernel suspect ou non signé a été chargé.', 'haute', 1, 'Possible rootkit', 'Malware kernel', 'T1014'),
(5111, 'Modification de /etc/passwd', 'Le fichier des utilisateurs a été modifié.', 'haute', 1, 'Comptes modifiés', 'Administration ou backdoor', 'T1136'),
(5112, 'Modification de /etc/shadow', 'Le fichier des mots de passe a été modifié.', 'haute', 1, 'Mots de passe changés', 'Administration ou attaque', 'T1098'),
(5113, 'Modification de /etc/sudoers', 'Le fichier sudoers a été modifié.', 'critique', 1, 'Privilèges modifiés', 'Administration ou élévation', 'T1548'),
(5114, 'Ajout dans /etc/cron', 'Une nouvelle tâche cron a été ajoutée.', 'moyenne', 1, 'Tâche planifiée', 'Maintenance ou persistence', 'T1053'),
(5115, 'Modification de /etc/hosts', 'Le fichier hosts a été modifié.', 'moyenne', 1, 'Résolution DNS altérée', 'Configuration ou détournement', 'T1565'),

-- ============================================================================
-- RÈGLES RÉSEAU (1100-1199)
-- ============================================================================
(1100, 'Nouvelle connexion réseau établie', 'Une nouvelle connexion réseau sortante a été établie.', 'info', 15, 'Connexion active', 'Communication normale', NULL),
(1101, 'Connexion vers IP malveillante', 'Une connexion vers une adresse IP connue comme malveillante a été détectée.', 'critique', 15, 'Communication avec attaquant', 'Malware ou compromission', 'T1071'),
(1102, 'Connexion vers pays suspect', 'Une connexion vers un pays à haut risque a été établie.', 'moyenne', 15, 'Trafic suspect', 'Normal ou exfiltration', 'T1048'),
(1103, 'Volume de données sortantes anormal', 'Un volume anormalement élevé de données sortantes a été détecté.', 'haute', 15, 'Possible exfiltration', 'Sauvegarde ou vol de données', 'T1048'),
(1104, 'Connexion DNS suspecte', 'Une requête DNS vers un domaine suspect a été détectée.', 'haute', 15, 'Communication cachée possible', 'DNS tunneling ou malware', 'T1071'),
(1105, 'Tunneling détecté', 'Un tunnel réseau suspect (VPN, SSH, DNS) a été détecté.', 'haute', 15, 'Communication cachée', 'Contournement ou exfiltration', 'T1572'),
(1106, 'ARP spoofing détecté', 'Une attaque ARP spoofing a été détectée sur le réseau.', 'critique', 15, 'Interception de trafic', 'Attaque man-in-the-middle', 'T1557'),
(1107, 'Nouvelle interface réseau', 'Une nouvelle interface réseau a été activée.', 'moyenne', 15, 'Nouvelle connectivité', 'Configuration ou rogue device', NULL),
(1108, 'Mode promiscuous activé', 'Une interface réseau est passée en mode promiscuous.', 'haute', 15, 'Capture de trafic', 'Monitoring ou sniffing', 'T1040'),
(1109, 'Port inhabituel utilisé', 'Une connexion utilise un port non standard pour un protocole.', 'moyenne', 15, 'Communication suspecte', 'Contournement de filtrage', 'T1571'),
(1110, 'Connexion IRC détectée', 'Une connexion IRC a été détectée (souvent utilisé par botnets).', 'haute', 15, 'Possible botnet', 'Malware ou usage légitime', 'T1071'),
(1111, 'Connexion Tor détectée', 'Une connexion au réseau Tor a été détectée.', 'haute', 15, 'Anonymisation active', 'Usage légitime ou malveillant', 'T1090'),
(1112, 'Beacon C2 possible', 'Un schéma de communication régulier suggère un beacon de commande et contrôle.', 'critique', 15, 'Communication avec C2', 'Malware actif', 'T1071'),

-- ============================================================================
-- RÈGLES SNORT/IDS (20000-20099)
-- ============================================================================
(20000, 'Alerte Snort générique', 'Snort a généré une alerte de sécurité.', 'moyenne', 3, 'Activité suspecte détectée', 'Trafic malveillant possible', NULL),
(20001, 'Scan de ports détecté par Snort', 'Snort a détecté un scan de ports sur le réseau.', 'haute', 3, 'Reconnaissance active', 'Attaque en préparation', 'T1046'),
(20002, 'Exploit détecté par Snort', 'Snort a détecté une tentative d exploitation.', 'critique', 3, 'Attaque en cours', 'Exploitation de vulnérabilité', 'T1190'),
(20003, 'Malware détecté par Snort', 'Snort a détecté du trafic de malware connu.', 'critique', 3, 'Malware actif', 'Infection ou communication C2', 'T1071'),
(20004, 'Attaque DoS détectée par Snort', 'Snort a détecté une attaque par déni de service.', 'critique', 3, 'Service à risque', 'Attaque DDoS', 'T1498'),
(20005, 'Tentative d intrusion détectée', 'Snort a détecté une tentative d intrusion.', 'haute', 3, 'Sécurité à risque', 'Attaque ciblée', 'T1190'),
(20006, 'Trafic suspect détecté par Snort', 'Snort a détecté du trafic réseau suspect.', 'moyenne', 3, 'Activité anormale', 'Reconnaissance ou attaque', NULL),
(20007, 'Communication C2 détectée', 'Snort a détecté une communication Command & Control.', 'critique', 3, 'Machine compromise', 'Malware actif', 'T1071'),
(20008, 'Exfiltration de données détectée', 'Snort a détecté une possible exfiltration de données.', 'critique', 3, 'Vol de données', 'Attaque réussie', 'T1048'),
(20009, 'Protocole anormal détecté', 'Snort a détecté l utilisation anormale d un protocole.', 'moyenne', 3, 'Communication suspecte', 'Tunneling ou évasion', 'T1571'),
(20010, 'Signature de ver détectée', 'Snort a détecté la signature d un ver informatique.', 'critique', 3, 'Propagation de malware', 'Infection par ver', 'T1210'),

-- ============================================================================
-- RÈGLES WAZUH INTERNES (500-509, 1000-1099)
-- ============================================================================
(500, 'Agent Wazuh connecté', 'Un agent Wazuh s est connecté au manager.', 'info', 7, 'Surveillance active', 'Démarrage de l agent', NULL),
(501, 'Agent Wazuh déconnecté', 'Un agent Wazuh s est déconnecté du manager.', 'moyenne', 7, 'Surveillance interrompue', 'Arrêt ou problème réseau', NULL),
(502, 'Agent Wazuh ne répond plus', 'Un agent Wazuh ne répond plus depuis plus de 10 minutes.', 'haute', 7, 'Perte de surveillance', 'Panne ou compromission', NULL),
(503, 'Nouvel agent Wazuh enregistré', 'Un nouvel agent Wazuh a été enregistré.', 'info', 7, 'Nouveau système surveillé', 'Déploiement', NULL),
(504, 'Configuration Wazuh modifiée', 'La configuration de Wazuh a été modifiée.', 'moyenne', 7, 'Paramètres changés', 'Administration', NULL),
(505, 'Règle Wazuh mise à jour', 'Les règles de détection Wazuh ont été mises à jour.', 'info', 7, 'Détection améliorée', 'Mise à jour', NULL),
(506, 'Erreur Wazuh', 'Wazuh a rencontré une erreur interne.', 'moyenne', 7, 'Fonctionnement dégradé', 'Bug ou configuration', NULL),
(507, 'Wazuh manager redémarré', 'Le manager Wazuh a été redémarré.', 'info', 7, 'Service redémarré', 'Maintenance', NULL),
(1002, 'Checksum de l agent modifié', 'Le checksum de l agent Wazuh a changé, possible compromission.', 'haute', 7, 'Agent potentiellement altéré', 'Mise à jour ou compromission', 'T1565'),
(1003, 'Agent Wazuh arrêté de force', 'L agent Wazuh a été arrêté de manière inattendue.', 'haute', 7, 'Surveillance arrêtée', 'Crash ou action malveillante', 'T1562'),

-- ============================================================================
-- RÈGLES VULNÉRABILITÉS (23500-23599)
-- ============================================================================
(23500, 'Vulnérabilité critique détectée', 'Une vulnérabilité de sécurité critique a été détectée sur le système.', 'critique', 14, 'Système vulnérable', 'Logiciel non mis à jour', 'T1190'),
(23501, 'Vulnérabilité haute détectée', 'Une vulnérabilité de sécurité haute a été détectée.', 'haute', 14, 'Système à risque', 'Logiciel non mis à jour', 'T1190'),
(23502, 'Vulnérabilité moyenne détectée', 'Une vulnérabilité de sécurité moyenne a été détectée.', 'moyenne', 14, 'Risque modéré', 'Logiciel non mis à jour', NULL),
(23503, 'CVE connue détectée', 'Une CVE (vulnérabilité référencée) connue a été détectée.', 'haute', 14, 'Exploit public possible', 'Logiciel vulnérable', 'T1190'),
(23504, 'Mise à jour de sécurité disponible', 'Une mise à jour de sécurité est disponible pour un paquet.', 'moyenne', 14, 'Mise à jour requise', 'Nouveau patch', NULL),
(23505, 'Paquet obsolète détecté', 'Un paquet logiciel obsolète et potentiellement vulnérable est installé.', 'moyenne', 14, 'Risque de sécurité', 'Maintenance insuffisante', NULL),

-- ============================================================================
-- RÈGLES VIOLATION DE POLITIQUE (80700-80799)
-- ============================================================================
(80700, 'Violation de politique de sécurité', 'Une règle de politique de sécurité a été violée.', 'moyenne', 16, 'Non-conformité', 'Erreur ou contournement', NULL),
(80701, 'Mot de passe faible détecté', 'Un mot de passe ne respectant pas la politique a été détecté.', 'moyenne', 16, 'Sécurité affaiblie', 'Utilisateur non conforme', 'T1078'),
(80702, 'Logiciel non autorisé installé', 'Un logiciel non autorisé a été installé sur le système.', 'haute', 16, 'Violation de politique', 'Installation non approuvée', 'T1072'),
(80703, 'Port non autorisé ouvert', 'Un port non autorisé par la politique est ouvert.', 'haute', 16, 'Surface d attaque étendue', 'Configuration non conforme', NULL),
(80704, 'Accès hors heures autorisées', 'Un accès a eu lieu en dehors des heures autorisées.', 'moyenne', 16, 'Accès suspect', 'Travail tardif ou compromission', 'T1078'),
(80705, 'Téléchargement de fichier suspect', 'Un fichier potentiellement dangereux a été téléchargé.', 'haute', 16, 'Malware possible', 'Téléchargement à risque', 'T1105'),
(80706, 'Utilisation de protocole non sécurisé', 'Un protocole non sécurisé (FTP, Telnet, HTTP) est utilisé.', 'moyenne', 16, 'Données à risque', 'Configuration obsolète', NULL),
(80707, 'Tentative de contournement de proxy', 'Une tentative de contournement du proxy a été détectée.', 'haute', 16, 'Évasion des contrôles', 'Contournement intentionnel', 'T1090'),
(80708, 'Partage de fichiers non autorisé', 'Un partage de fichiers non autorisé a été détecté.', 'moyenne', 16, 'Données exposées', 'Configuration non conforme', 'T1048'),

-- ============================================================================
-- RÈGLES SUPPLÉMENTAIRES AUTHENTIFICATION (2500-2599)
-- ============================================================================
(2501, 'Connexion réussie après plusieurs échecs', 'Un utilisateur a réussi à se connecter après plusieurs tentatives échouées.', 'moyenne', 8, 'Accès obtenu après difficultés', 'Oubli de mot de passe ou attaque réussie', 'T1110'),
(2502, 'Connexion depuis plusieurs pays', 'Un même compte s est connecté depuis plusieurs pays en peu de temps.', 'critique', 8, 'Compte potentiellement compromis', 'Credentials volés', 'T1078'),
(2503, 'Connexion à une heure inhabituelle', 'Une connexion a eu lieu à une heure anormale pour cet utilisateur.', 'moyenne', 8, 'Activité suspecte', 'Travail tardif ou compromission', 'T1078'),
(2504, 'Première connexion d un utilisateur', 'Un utilisateur se connecte pour la première fois.', 'info', 8, 'Nouveau compte actif', 'Normal ou compte créé par attaquant', NULL),
(2505, 'Connexion avec privilèges élevés', 'Une connexion avec des privilèges administrateur a été effectuée.', 'moyenne', 8, 'Session admin active', 'Administration ou abus', 'T1078'),

-- ============================================================================
-- RÈGLES SUPPLÉMENTAIRES MALWARE (3000-3099)
-- ============================================================================
(3001, 'Signature de ransomware détectée', 'Une signature de ransomware connu a été détectée.', 'critique', 11, 'Chiffrement des données imminent', 'Infection par ransomware', 'T1486'),
(3002, 'Comportement de cryptominer détecté', 'Une activité de minage de cryptomonnaie a été détectée.', 'haute', 11, 'Ressources système détournées', 'Cryptominer installé', 'T1496'),
(3003, 'Connexion à domaine malveillant', 'Une connexion vers un domaine connu comme malveillant a été détectée.', 'critique', 11, 'Communication avec C2', 'Malware actif', 'T1071'),
(3004, 'Téléchargement de fichier exécutable suspect', 'Un fichier exécutable a été téléchargé depuis une source suspecte.', 'haute', 11, 'Possible infection', 'Drive-by download', 'T1105'),
(3005, 'Script PowerShell encodé détecté', 'Un script PowerShell encodé en base64 a été exécuté.', 'haute', 11, 'Exécution de code obfusqué', 'Attaque ou malware', 'T1059'),
(3006, 'Modification du registre suspecte', 'Une modification suspecte du registre Windows a été détectée.', 'haute', 11, 'Persistence possible', 'Malware ou configuration', 'T1547'),
(3007, 'Processus injectant du code', 'Un processus tente d injecter du code dans un autre processus.', 'critique', 11, 'Technique d évasion', 'Malware avancé', 'T1055'),
(3008, 'Désactivation de l antivirus', 'Une tentative de désactivation de l antivirus a été détectée.', 'critique', 11, 'Protection désactivée', 'Malware ou attaquant', 'T1562'),

-- ============================================================================
-- RÈGLES SUPPLÉMENTAIRES RÉSEAU AVANCÉES (1200-1299)
-- ============================================================================
(1200, 'Scan ICMP détecté', 'Un scan ping (ICMP) a été détecté sur le réseau.', 'faible', 15, 'Reconnaissance réseau', 'Scan de découverte', 'T1046'),
(1201, 'Tentative de DNS zone transfer', 'Une tentative de transfert de zone DNS a été détectée.', 'haute', 15, 'Reconnaissance DNS', 'Collecte d informations', 'T1590'),
(1202, 'Requête DNS TXT suspecte', 'Une requête DNS TXT inhabituelle a été détectée (possible exfiltration).', 'haute', 15, 'Exfiltration par DNS', 'DNS tunneling', 'T1071'),
(1203, 'Connexion SMTP non autorisée', 'Une connexion SMTP sortante non autorisée a été détectée.', 'haute', 15, 'Envoi de spam possible', 'Serveur compromis', 'T1071'),
(1204, 'Trafic HTTPS vers IP directe', 'Du trafic HTTPS est envoyé vers une IP au lieu d un domaine.', 'moyenne', 15, 'Communication suspecte', 'C2 ou configuration', 'T1071'),
(1205, 'Fragmentation IP suspecte', 'Des paquets IP fragmentés de manière suspecte ont été détectés.', 'moyenne', 15, 'Évasion possible', 'Attaque ou erreur', 'T1027'),
(1206, 'Broadcast excessif', 'Un volume anormal de trafic broadcast a été détecté.', 'moyenne', 15, 'Possible attaque réseau', 'Misconfiguration ou attaque', NULL),
(1207, 'Connexion VPN non autorisée', 'Une connexion VPN non autorisée a été détectée.', 'haute', 15, 'Tunnel non contrôlé', 'Contournement de sécurité', 'T1572'),

-- ============================================================================
-- RÈGLES SUPPLÉMENTAIRES APPLICATIONS (40000-40099)
-- ============================================================================
(40001, 'Échec de démarrage d application', 'Une application critique n a pas pu démarrer.', 'haute', 1, 'Service indisponible', 'Erreur ou attaque', NULL),
(40002, 'Base de données redémarrée', 'Le serveur de base de données a été redémarré.', 'moyenne', 1, 'Interruption de service', 'Maintenance ou crash', NULL),
(40003, 'Erreur de connexion à la base de données', 'Une application ne peut pas se connecter à la base de données.', 'haute', 1, 'Service dégradé', 'Problème réseau ou credentials', NULL),
(40004, 'Quota disque dépassé', 'Un utilisateur ou service a dépassé son quota disque.', 'moyenne', 1, 'Écriture impossible', 'Utilisation excessive', NULL),
(40005, 'Certificat SSL expiré', 'Un certificat SSL/TLS a expiré.', 'haute', 1, 'Connexions non sécurisées', 'Maintenance oubliée', NULL),
(40006, 'Certificat SSL bientôt expiré', 'Un certificat SSL/TLS expire dans moins de 30 jours.', 'moyenne', 1, 'Renouvellement requis', 'Maintenance préventive', NULL),
(40007, 'Backup échoué', 'Une sauvegarde planifiée a échoué.', 'haute', 1, 'Données non sauvegardées', 'Erreur système', NULL),
(40008, 'Espace de logs critique', 'L espace dédié aux logs est presque plein.', 'haute', 1, 'Perte de logs imminente', 'Rotation insuffisante', NULL),

-- ============================================================================
-- RÈGLES SUPPLÉMENTAIRES DOCKER/CONTAINERS (45000-45099)
-- ============================================================================
(45001, 'Container démarré avec privilèges', 'Un container Docker a été démarré avec des privilèges élevés.', 'haute', 1, 'Risque d évasion container', 'Configuration risquée', 'T1611'),
(45002, 'Image Docker non signée utilisée', 'Une image Docker non vérifiée a été utilisée.', 'moyenne', 1, 'Image potentiellement compromise', 'Pratique risquée', 'T1204'),
(45003, 'Container accédant au socket Docker', 'Un container accède au socket Docker de l hôte.', 'critique', 1, 'Contrôle total possible', 'Configuration dangereuse', 'T1611'),
(45004, 'Nouveau container créé', 'Un nouveau container a été créé.', 'info', 1, 'Nouveau service', 'Déploiement normal', NULL),
(45005, 'Container arrêté de manière inattendue', 'Un container s est arrêté sans raison apparente.', 'moyenne', 1, 'Service interrompu', 'Crash ou arrêt manuel', NULL),

-- ============================================================================
-- RÈGLES SUPPLÉMENTAIRES CLOUD (50000-50099)
-- ============================================================================
(50001, 'Accès API cloud depuis nouvelle IP', 'Un accès API cloud provient d une IP inconnue.', 'moyenne', 8, 'Possible compromission', 'Nouvel emplacement ou vol credentials', 'T1078'),
(50002, 'Création de nouvel utilisateur cloud', 'Un nouvel utilisateur a été créé sur le compte cloud.', 'moyenne', 16, 'Nouveau compte', 'Administration ou compromission', 'T1136'),
(50003, 'Modification des règles de sécurité cloud', 'Les règles de sécurité du cloud ont été modifiées.', 'haute', 16, 'Exposition possible', 'Administration ou attaque', 'T1562'),
(50004, 'Bucket S3 rendu public', 'Un bucket de stockage a été rendu accessible publiquement.', 'critique', 16, 'Données exposées', 'Erreur ou attaque', 'T1530'),
(50005, 'Clé API cloud créée', 'Une nouvelle clé API cloud a été générée.', 'moyenne', 16, 'Nouvel accès programmatique', 'Administration ou compromission', 'T1098'),

-- ============================================================================
-- RÈGLE PAR DÉFAUT - NON IDENTIFIÉ
-- ============================================================================
(99999, 'Alerte non identifiée', 'Cette alerte n a pas été reconnue par la base de connaissances SIEM Africa. Une analyse manuelle est requise.', 'moyenne', 20, 'Impact inconnu - analyse requise', 'Nouvelle menace ou faux positif', NULL);

-- ============================================================================
-- TABLE: RECOMMANDATIONS
-- ============================================================================
CREATE TABLE recommandations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    regle_id INTEGER NOT NULL,
    ordre INTEGER NOT NULL,
    action TEXT NOT NULL,
    commande TEXT,
    niveau TEXT CHECK(niveau IN ('debutant', 'intermediaire', 'avance')) DEFAULT 'debutant',
    FOREIGN KEY (regle_id) REFERENCES regles(id)
);

-- Recommandations pour les règles SSH
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
-- Règle 5711 (Brute force SSH)
((SELECT id FROM regles WHERE wazuh_rule_id = 5711), 1, 'Bloquer immédiatement l adresse IP source', 'sudo iptables -A INPUT -s IP_ATTAQUANT -j DROP', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5711), 2, 'Installer et configurer fail2ban', 'sudo apt install fail2ban && sudo systemctl enable fail2ban', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5711), 3, 'Vérifier les connexions réussies récentes', 'sudo grep "Accepted" /var/log/auth.log | tail -20', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5711), 4, 'Changer le port SSH par défaut', 'sudo nano /etc/ssh/sshd_config # Modifier Port 22', 'avance'),

-- Règle 5701 (Connexion après brute force)
((SELECT id FROM regles WHERE wazuh_rule_id = 5701), 1, 'URGENT: Vérifier si la connexion est légitime', 'sudo last | head -10', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5701), 2, 'Changer immédiatement tous les mots de passe', 'sudo passwd NOM_UTILISATEUR', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5701), 3, 'Vérifier les processus suspects', 'sudo ps aux | grep -v root', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5701), 4, 'Analyser les fichiers modifiés récemment', 'sudo find / -mtime -1 -type f 2>/dev/null', 'avance'),

-- Règle 5704 (Connexion root)
((SELECT id FROM regles WHERE wazuh_rule_id = 5704), 1, 'Désactiver la connexion root SSH', 'sudo sed -i "s/PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config && sudo systemctl restart sshd', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5704), 2, 'Utiliser des clés SSH au lieu des mots de passe', 'ssh-keygen -t ed25519', 'intermediaire'),

-- Règle 31101 (Injection SQL)
((SELECT id FROM regles WHERE wazuh_rule_id = 31101), 1, 'Bloquer l adresse IP source immédiatement', 'sudo iptables -A INPUT -s IP_ATTAQUANT -j DROP', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 31101), 2, 'Vérifier les logs de la base de données', 'sudo tail -100 /var/log/mysql/error.log', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 31101), 3, 'Mettre à jour le WAF (ModSecurity)', 'sudo apt update && sudo apt upgrade libapache2-mod-security2', 'avance'),
((SELECT id FROM regles WHERE wazuh_rule_id = 31101), 4, 'Auditer le code de l application', 'Vérifier l utilisation de requêtes préparées (prepared statements)', 'avance'),

-- Règle 510 (Rootkit détecté)
((SELECT id FROM regles WHERE wazuh_rule_id = 510), 1, 'ISOLER IMMÉDIATEMENT LE SERVEUR DU RÉSEAU', 'sudo ifconfig eth0 down', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 510), 2, 'Ne pas redémarrer - préserver les preuves', 'Contacter l équipe de sécurité', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 510), 3, 'Scanner avec rkhunter', 'sudo rkhunter --check', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 510), 4, 'Préparer une réinstallation complète', 'Le système est probablement compromis', 'avance'),

-- Règle 4105 (Flood SYN)
((SELECT id FROM regles WHERE wazuh_rule_id = 4105), 1, 'Activer la protection SYN cookies', 'sudo sysctl -w net.ipv4.tcp_syncookies=1', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 4105), 2, 'Limiter le taux de connexions', 'sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 4105), 3, 'Contacter le FAI pour mitigation DDoS', 'Si l attaque persiste', 'avance'),

-- Règle 18111 (Journal effacé)
((SELECT id FROM regles WHERE wazuh_rule_id = 18111), 1, 'ALERTE CRITIQUE: Possible dissimulation d attaque', 'Investiguer immédiatement', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 18111), 2, 'Vérifier les autres journaux', 'Comparer avec les logs Wazuh centralisés', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 18111), 3, 'Identifier qui a effacé les logs', 'Vérifier les accès administrateurs', 'avance'),

-- Règle 99999 (Non identifié)
((SELECT id FROM regles WHERE wazuh_rule_id = 99999), 1, 'Analyser manuellement le log brut', 'Examiner les détails de l alerte', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 99999), 2, 'Rechercher l ID de règle Wazuh', 'Consulter la documentation Wazuh', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 99999), 3, 'Signaler pour ajout à la base SIEM Africa', 'Contribuer à l amélioration du système', 'debutant'),

-- Règle 1101 (Connexion IP malveillante)
((SELECT id FROM regles WHERE wazuh_rule_id = 1101), 1, 'Bloquer l adresse IP immédiatement', 'sudo iptables -A INPUT -s IP_MALVEILLANTE -j DROP && sudo iptables -A OUTPUT -d IP_MALVEILLANTE -j DROP', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 1101), 2, 'Identifier le processus responsable', 'sudo netstat -tulpn | grep IP_MALVEILLANTE', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 1101), 3, 'Scanner le système pour malware', 'sudo clamscan -r /', 'avance'),

-- Règle 5113 (Modification sudoers)
((SELECT id FROM regles WHERE wazuh_rule_id = 5113), 1, 'Vérifier les modifications apportées', 'sudo cat /etc/sudoers', 'debutant'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5113), 2, 'Restaurer depuis une sauvegarde si suspect', 'sudo cp /etc/sudoers.bak /etc/sudoers', 'intermediaire'),
((SELECT id FROM regles WHERE wazuh_rule_id = 5113), 3, 'Auditer tous les utilisateurs sudo', 'sudo grep -Po "^sudo.+:\K.*$" /etc/group', 'intermediaire');

-- ============================================================================
-- TABLE: ALERTES_LOG (Historique des alertes reçues)
-- ============================================================================
CREATE TABLE alertes_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wazuh_alert_id TEXT,
    wazuh_rule_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    agent_id TEXT,
    agent_name TEXT,
    agent_ip TEXT,
    source_ip TEXT,
    source_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocole TEXT,
    utilisateur TEXT,
    description_wazuh TEXT,
    raw_log TEXT,
    statut TEXT CHECK(statut IN ('nouveau', 'vu', 'en_cours', 'traite', 'ignore', 'faux_positif')) DEFAULT 'nouveau',
    traite_par TEXT,
    notes TEXT,
    FOREIGN KEY (wazuh_rule_id) REFERENCES regles(wazuh_rule_id)
);

-- ============================================================================
-- INDEX pour améliorer les performances
-- ============================================================================
CREATE INDEX idx_regles_wazuh_id ON regles(wazuh_rule_id);
CREATE INDEX idx_regles_gravite ON regles(gravite);
CREATE INDEX idx_regles_categorie ON regles(categorie_id);
CREATE INDEX idx_alertes_timestamp ON alertes_log(timestamp);
CREATE INDEX idx_alertes_statut ON alertes_log(statut);
CREATE INDEX idx_alertes_rule ON alertes_log(wazuh_rule_id);
CREATE INDEX idx_recommandations_regle ON recommandations(regle_id);

-- ============================================================================
-- VUE: Alertes avec informations complètes
-- ============================================================================
CREATE VIEW vue_alertes_completes AS
SELECT 
    a.id AS alerte_id,
    a.timestamp,
    a.agent_name,
    a.source_ip,
    a.statut,
    r.wazuh_rule_id,
    r.nom_fr AS nom_alerte,
    r.description,
    r.gravite,
    r.impact,
    r.cause_probable,
    c.nom AS categorie,
    c.icone,
    c.couleur
FROM alertes_log a
LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
LEFT JOIN categories c ON r.categorie_id = c.id
ORDER BY a.timestamp DESC;

-- ============================================================================
-- VUE: Statistiques par gravité
-- ============================================================================
CREATE VIEW vue_stats_gravite AS
SELECT 
    gravite,
    COUNT(*) AS total
FROM alertes_log a
JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
WHERE a.statut NOT IN ('traite', 'ignore', 'faux_positif')
GROUP BY gravite;

-- ============================================================================
-- VUE: Statistiques par catégorie
-- ============================================================================
CREATE VIEW vue_stats_categorie AS
SELECT 
    c.nom AS categorie,
    c.icone,
    COUNT(*) AS total
FROM alertes_log a
JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
JOIN categories c ON r.categorie_id = c.id
WHERE a.statut NOT IN ('traite', 'ignore', 'faux_positif')
GROUP BY c.id
ORDER BY total DESC;

-- ============================================================================
-- FONCTION: Obtenir la règle ou retourner "non identifié"
-- (Note: SQLite n'a pas de fonctions, ceci est géré dans l'application)
-- ============================================================================

-- Message de confirmation
SELECT '✅ Base de données SIEM Africa créée avec succès!' AS message;
SELECT COUNT(*) || ' règles insérées' AS info FROM regles;
SELECT COUNT(*) || ' catégories créées' AS info FROM categories;
SELECT COUNT(*) || ' recommandations ajoutées' AS info FROM recommandations;

#!/bin/bash

# =============================================================================
# SIEM AFRICA - Installation Dashboard v2.1 (CORRIGÉ)
# =============================================================================
# Installation intelligente avec:
# - Détection des composants existants
# - HTTPS avec certificat auto-signé
# - Authentification obligatoire
# - Mise à jour automatique
# - Détection automatique des credentials Wazuh
# - CORRECTION: Installation Flask robuste avec fallback
# =============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/opt/siem-africa"
DB_DIR="$INSTALL_DIR/database"
DASHBOARD_DIR="$INSTALL_DIR/dashboard"
TEMPLATES_DIR="$DASHBOARD_DIR/templates"
SSL_DIR="$INSTALL_DIR/ssl"
LOG_DIR="/var/log/siem-africa"
VENV_DIR="$INSTALL_DIR/venv"
GITHUB_BASE="https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main"
CRIDS_FILE="/root/SIEM_AFRICA_CRIDS.txt"

# Mot de passe par défaut Dashboard
DEFAULT_PASSWORD="SiemAfrica2026!"

# Variable pour savoir si on utilise venv ou système
USE_VENV=true
PYTHON_CMD=""

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

print_banner() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║     🛡️  SIEM AFRICA - Dashboard Installation v2.1           ║${NC}"
    echo -e "${GREEN}║         Solution de Cybersécurité pour l'Afrique            ║${NC}"
    echo -e "${GREEN}║                   (Version Corrigée)                         ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Ce script doit être exécuté en tant que root (sudo)"
        exit 1
    fi
}

check_wazuh() {
    if ! systemctl is-active --quiet wazuh-manager; then
        log_warning "Wazuh Manager n'est pas actif"
        log_info "Tentative de démarrage..."
        systemctl start wazuh-manager || true
        sleep 3
        
        if ! systemctl is-active --quiet wazuh-manager; then
            log_error "Impossible de démarrer Wazuh Manager"
            log_info "Installez d'abord Wazuh avec install_siem_v3.sh"
            exit 1
        fi
    fi
    log_success "Wazuh Manager est actif"
}

# =============================================================================
# INSTALLATION DES DÉPENDANCES
# =============================================================================

install_dependencies() {
    log_info "Installation des dépendances système..."
    
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv sqlite3 curl openssl > /dev/null 2>&1
    
    log_success "Dépendances système installées"
}

# =============================================================================
# CRÉATION DES RÉPERTOIRES
# =============================================================================

create_directories() {
    log_info "Création des répertoires..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DB_DIR"
    mkdir -p "$DASHBOARD_DIR"
    mkdir -p "$TEMPLATES_DIR"
    mkdir -p "$SSL_DIR"
    mkdir -p "$LOG_DIR"
    
    log_success "Répertoires créés"
}

# =============================================================================
# GÉNÉRATION CERTIFICAT SSL
# =============================================================================

generate_ssl_certificate() {
    if [ -f "$SSL_DIR/cert.pem" ] && [ -f "$SSL_DIR/key.pem" ]; then
        log_warning "Certificat SSL existant détecté"
        return
    fi
    
    log_info "Génération du certificat SSL auto-signé..."
    
    openssl req -x509 -newkey rsa:4096 -keyout "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" \
        -days 365 -nodes -subj "/C=CM/ST=Littoral/L=Douala/O=SIEM Africa/OU=Security/CN=siem-africa.local" \
        > /dev/null 2>&1
    
    chmod 600 "$SSL_DIR/key.pem"
    chmod 644 "$SSL_DIR/cert.pem"
    
    log_success "Certificat SSL généré (valide 1 an)"
}

# =============================================================================
# TÉLÉCHARGEMENT DES FICHIERS
# =============================================================================

download_files() {
    log_info "Téléchargement des fichiers depuis GitHub..."
    
    # Base de données SQL
    log_info "  → Base de données..."
    curl -sL "$GITHUB_BASE/database/siem_africa_db.sql" -o "$DB_DIR/siem_africa_db.sql"
    
    # Application Flask
    log_info "  → Application Flask..."
    curl -sL "$GITHUB_BASE/dashboard/app.py" -o "$DASHBOARD_DIR/app.py"
    
    # Agent
    log_info "  → Agent d'interprétation..."
    curl -sL "$GITHUB_BASE/dashboard/agent.py" -o "$DASHBOARD_DIR/agent.py"
    
    # Templates
    log_info "  → Templates HTML..."
    curl -sL "$GITHUB_BASE/dashboard/templates/login.html" -o "$TEMPLATES_DIR/login.html"
    curl -sL "$GITHUB_BASE/dashboard/templates/change_password.html" -o "$TEMPLATES_DIR/change_password.html"
    curl -sL "$GITHUB_BASE/dashboard/templates/index.html" -o "$TEMPLATES_DIR/index.html"
    curl -sL "$GITHUB_BASE/dashboard/templates/detail.html" -o "$TEMPLATES_DIR/detail.html"
    curl -sL "$GITHUB_BASE/dashboard/templates/alertes.html" -o "$TEMPLATES_DIR/alertes.html"
    
    log_success "Fichiers téléchargés"
}

# =============================================================================
# CRÉATION DE LA BASE DE DONNÉES (CORRIGÉE)
# =============================================================================

setup_database() {
    if [ -f "$DB_DIR/siem_africa.db" ]; then
        log_warning "Base de données existante détectée"
        log_info "Mise à jour de la structure..."
        
        # Ajouter les nouvelles tables si elles n'existent pas
        sqlite3 "$DB_DIR/siem_africa.db" <<EOF
-- Table utilisateurs (si n'existe pas)
CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER DEFAULT 1,
    password_created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    password_expires_at DATETIME,
    last_login DATETIME,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    password_history TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Table sessions
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES utilisateurs(id)
);

-- Table audit_log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    username TEXT,
    action TEXT,
    ip_address TEXT,
    details TEXT,
    success INTEGER
);

-- Index
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
EOF

        # =====================================================================
        # CORRECTION: Ajouter la colonne password_history si elle n'existe pas
        # =====================================================================
        log_info "Vérification de la colonne password_history..."
        
        # Vérifier si la colonne existe
        COL_EXISTS=$(sqlite3 "$DB_DIR/siem_africa.db" "PRAGMA table_info(utilisateurs);" | grep -c "password_history" || true)
        
        if [ "$COL_EXISTS" -eq 0 ]; then
            log_info "Ajout de la colonne password_history..."
            sqlite3 "$DB_DIR/siem_africa.db" "ALTER TABLE utilisateurs ADD COLUMN password_history TEXT DEFAULT '';" 2>/dev/null || true
            log_success "Colonne password_history ajoutée"
        else
            log_success "Colonne password_history déjà présente"
        fi

        log_success "Structure de la base mise à jour"
    else
        log_info "Création de la base de données..."
        sqlite3 "$DB_DIR/siem_africa.db" < "$DB_DIR/siem_africa_db.sql"
        
        # S'assurer que password_history existe
        sqlite3 "$DB_DIR/siem_africa.db" "ALTER TABLE utilisateurs ADD COLUMN password_history TEXT DEFAULT '';" 2>/dev/null || true
        
        log_success "Base de données créée (207 règles)"
    fi
    
    # Créer l'utilisateur admin par défaut si n'existe pas
    log_info "Vérification de l'utilisateur admin..."
    
    # Hash du mot de passe par défaut (SHA256 avec sel)
    PASS_HASH=$(echo -n "${DEFAULT_PASSWORD}siem_africa_2026" | sha256sum | cut -d' ' -f1)
    
    sqlite3 "$DB_DIR/siem_africa.db" <<EOF
INSERT OR IGNORE INTO utilisateurs (
    username, 
    password_hash, 
    must_change_password, 
    password_expires_at,
    password_history
) VALUES (
    'admin',
    '$PASS_HASH',
    1,
    datetime('now', '+90 days'),
    ''
);
EOF
    
    log_success "Utilisateur admin configuré"
}

# =============================================================================
# ENVIRONNEMENT VIRTUEL PYTHON (CORRIGÉ AVEC FALLBACK)
# =============================================================================

setup_python_env() {
    log_info "Configuration de l'environnement Python..."
    
    # =========================================================================
    # MÉTHODE 1: Essayer avec virtualenv
    # =========================================================================
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Création de l'environnement virtuel Python..."
        if python3 -m venv "$VENV_DIR" 2>/dev/null; then
            log_success "Environnement virtuel créé"
        else
            log_warning "Impossible de créer l'environnement virtuel"
            USE_VENV=false
        fi
    fi
    
    # =========================================================================
    # MÉTHODE 2: Installer Flask dans le venv
    # =========================================================================
    if [ "$USE_VENV" = true ] && [ -f "$VENV_DIR/bin/pip" ]; then
        log_info "Installation des packages Python dans venv..."
        
        if "$VENV_DIR/bin/pip" install --upgrade pip -q 2>/dev/null && \
           "$VENV_DIR/bin/pip" install flask requests urllib3 -q 2>/dev/null; then
            PYTHON_CMD="$VENV_DIR/bin/python3"
            log_success "Flask installé dans l'environnement virtuel"
            
            # Vérifier que Flask fonctionne
            if "$PYTHON_CMD" -c "import flask" 2>/dev/null; then
                log_success "Flask vérifié et fonctionnel (venv)"
                return
            else
                log_warning "Flask installé mais non fonctionnel dans venv"
                USE_VENV=false
            fi
        else
            log_warning "Échec de l'installation dans venv"
            USE_VENV=false
        fi
    fi
    
    # =========================================================================
    # MÉTHODE 3: Fallback - Installation système
    # =========================================================================
    if [ "$USE_VENV" = false ]; then
        log_warning "Utilisation du fallback: installation système"
        
        # Essayer pip3 avec différentes options
        if pip3 install flask requests urllib3 2>/dev/null; then
            log_success "Flask installé via pip3 (système)"
        elif pip3 install flask requests urllib3 --break-system-packages 2>/dev/null; then
            log_success "Flask installé via pip3 --break-system-packages"
        elif apt-get install -y python3-flask python3-requests 2>/dev/null; then
            log_success "Flask installé via apt-get"
        else
            log_error "ÉCHEC: Impossible d'installer Flask"
            log_error "Essayez manuellement: sudo pip3 install flask"
            exit 1
        fi
        
        PYTHON_CMD="/usr/bin/python3"
        
        # Vérifier que Flask fonctionne
        if "$PYTHON_CMD" -c "import flask" 2>/dev/null; then
            log_success "Flask vérifié et fonctionnel (système)"
        else
            log_error "Flask n'est pas fonctionnel"
            log_error "Essayez: sudo pip3 install flask"
            exit 1
        fi
    fi
}

# =============================================================================
# CONFIGURATION WAZUH - DÉTECTION AUTOMATIQUE
# =============================================================================

get_wazuh_credentials() {
    log_info "Récupération des identifiants Wazuh API..."
    
    WAZUH_USER="wazuh"
    WAZUH_PASS=""
    
    # MÉTHODE 1: Format "WAZUH : wazuh / wazuh123 (sudo)"
    if [ -z "$WAZUH_PASS" ] && [ -f "/root/siem_credentials.txt" ]; then
        WAZUH_PASS=$(grep -i "^WAZUH" /root/siem_credentials.txt 2>/dev/null | awk -F'/' '{print $2}' | awk '{print $1}' | tr -d ' ' || true)
        if [ -n "$WAZUH_PASS" ]; then
            log_success "Mot de passe trouvé dans siem_credentials.txt (format WAZUH)"
        fi
    fi
    
    # MÉTHODE 2: Format "API Password: xxxxx"
    if [ -z "$WAZUH_PASS" ] && [ -f "/root/siem_credentials.txt" ]; then
        WAZUH_PASS=$(grep -i "API Password" /root/siem_credentials.txt 2>/dev/null | cut -d':' -f2 | tr -d ' ' || true)
        if [ -n "$WAZUH_PASS" ]; then
            log_success "Mot de passe trouvé dans siem_credentials.txt (format API Password)"
        fi
    fi
    
    # MÉTHODE 3: Fichier wazuh-passwords.txt format "wazuh xxxxx"
    if [ -z "$WAZUH_PASS" ] && [ -f "/root/wazuh-install-files/wazuh-passwords.txt" ]; then
        WAZUH_PASS=$(grep -E "^wazuh " /root/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | awk '{print $NF}' || true)
        if [ -n "$WAZUH_PASS" ]; then
            log_success "Mot de passe trouvé dans wazuh-passwords.txt"
        fi
    fi
    
    # MÉTHODE 4: Fichier wazuh-passwords.txt format "  wazuh: xxxxx"
    if [ -z "$WAZUH_PASS" ] && [ -f "/root/wazuh-install-files/wazuh-passwords.txt" ]; then
        WAZUH_PASS=$(grep -E "wazuh:" /root/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | awk -F':' '{print $2}' | tr -d ' ' || true)
        if [ -n "$WAZUH_PASS" ]; then
            log_success "Mot de passe trouvé dans wazuh-passwords.txt (format wazuh:)"
        fi
    fi
    
    # MÉTHODE 5: Chercher dans /var/ossec/etc/
    if [ -z "$WAZUH_PASS" ] && [ -f "/var/ossec/etc/wazuh-api.conf" ]; then
        WAZUH_PASS=$(grep -i "password" /var/ossec/etc/wazuh-api.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' "' || true)
        if [ -n "$WAZUH_PASS" ]; then
            log_success "Mot de passe trouvé dans wazuh-api.conf"
        fi
    fi
    
    # MÉTHODE 6: Mot de passe par défaut wazuh123
    if [ -z "$WAZUH_PASS" ]; then
        log_warning "Mot de passe non trouvé automatiquement"
        log_info "Utilisation du mot de passe par défaut: wazuh123"
        WAZUH_PASS="wazuh123"
    fi
    
    # Créer le fichier de configuration
    cat > "$INSTALL_DIR/config.json" <<EOF
{
    "wazuh_host": "127.0.0.1",
    "wazuh_port": 55000,
    "wazuh_user": "$WAZUH_USER",
    "wazuh_password": "$WAZUH_PASS",
    "db_path": "$DB_DIR/siem_africa.db",
    "check_interval": 30
}
EOF
    
    chmod 600 "$INSTALL_DIR/config.json"
    log_success "Configuration Wazuh enregistrée"
}

# =============================================================================
# SERVICES SYSTEMD (CORRIGÉ)
# =============================================================================

create_services() {
    log_info "Création des services systemd..."
    
    # Déterminer la commande Python à utiliser
    if [ "$USE_VENV" = true ] && [ -f "$VENV_DIR/bin/python3" ]; then
        PYTHON_EXEC="$VENV_DIR/bin/python3"
        log_info "Services utiliseront: venv Python"
    else
        PYTHON_EXEC="/usr/bin/python3"
        log_info "Services utiliseront: système Python"
    fi
    
    # Service Agent
    cat > /etc/systemd/system/siem-africa-agent.service <<EOF
[Unit]
Description=SIEM Africa - Agent d'Interprétation
After=network.target wazuh-manager.service
Wants=wazuh-manager.service

[Service]
Type=simple
User=root
WorkingDirectory=$DASHBOARD_DIR
Environment="SIEM_CONFIG_PATH=$INSTALL_DIR/config.json"
Environment="SIEM_DB_PATH=$DB_DIR/siem_africa.db"
ExecStart=$PYTHON_EXEC $DASHBOARD_DIR/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Service Dashboard
    cat > /etc/systemd/system/siem-africa-dashboard.service <<EOF
[Unit]
Description=SIEM Africa - Dashboard Web Sécurisé
After=network.target siem-africa-agent.service

[Service]
Type=simple
User=root
WorkingDirectory=$DASHBOARD_DIR
Environment="SIEM_DB_PATH=$DB_DIR/siem_africa.db"
Environment="SECRET_KEY=$(openssl rand -hex 32)"
ExecStart=$PYTHON_EXEC $DASHBOARD_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Recharger et activer
    systemctl daemon-reload
    systemctl enable siem-africa-agent.service > /dev/null 2>&1
    systemctl enable siem-africa-dashboard.service > /dev/null 2>&1
    
    log_success "Services systemd créés et activés"
}

# =============================================================================
# DÉMARRAGE DES SERVICES (CORRIGÉ)
# =============================================================================

start_services() {
    log_info "Démarrage des services..."
    
    # Arrêter si déjà en cours
    systemctl stop siem-africa-dashboard.service > /dev/null 2>&1 || true
    systemctl stop siem-africa-agent.service > /dev/null 2>&1 || true
    
    sleep 2
    
    # Démarrer l'agent
    log_info "Démarrage de l'agent..."
    if systemctl start siem-africa-agent.service 2>/dev/null; then
        sleep 3
        if systemctl is-active --quiet siem-africa-agent.service; then
            log_success "Agent SIEM Africa démarré"
        else
            log_warning "Agent démarré mais statut incertain"
            journalctl -u siem-africa-agent.service -n 5 --no-pager 2>/dev/null || true
        fi
    else
        log_error "Échec du démarrage de l'agent"
        journalctl -u siem-africa-agent.service -n 10 --no-pager 2>/dev/null || true
    fi
    
    # Démarrer le dashboard
    log_info "Démarrage du dashboard..."
    if systemctl start siem-africa-dashboard.service 2>/dev/null; then
        sleep 3
        if systemctl is-active --quiet siem-africa-dashboard.service; then
            log_success "Dashboard SIEM Africa démarré"
        else
            log_warning "Dashboard démarré mais statut incertain"
            log_info "Vérification des erreurs..."
            journalctl -u siem-africa-dashboard.service -n 10 --no-pager 2>/dev/null || true
        fi
    else
        log_error "Échec du démarrage du dashboard"
        journalctl -u siem-africa-dashboard.service -n 10 --no-pager 2>/dev/null || true
    fi
}

# =============================================================================
# CONFIGURATION PARE-FEU
# =============================================================================

configure_firewall() {
    log_info "Configuration du pare-feu..."
    
    if command -v ufw > /dev/null 2>&1; then
        ufw allow 5000/tcp > /dev/null 2>&1 || true
        log_success "Port 5000 ouvert (UFW)"
    elif command -v firewall-cmd > /dev/null 2>&1; then
        firewall-cmd --permanent --add-port=5000/tcp > /dev/null 2>&1 || true
        firewall-cmd --reload > /dev/null 2>&1 || true
        log_success "Port 5000 ouvert (firewalld)"
    else
        log_warning "Aucun pare-feu détecté - assurez-vous que le port 5000 est accessible"
    fi
}

# =============================================================================
# CRÉATION DU FICHIER CRIDS
# =============================================================================

create_crids_file() {
    log_info "Création du fichier CRIDS..."
    
    # Obtenir l'IP
    IP_ADDR=$(hostname -I | awk '{print $1}')
    DATE_INSTALL=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Déterminer quel Python est utilisé
    if [ "$USE_VENV" = true ]; then
        PYTHON_INFO="venv ($VENV_DIR/bin/python3)"
    else
        PYTHON_INFO="système (/usr/bin/python3)"
    fi
    
    cat > "$CRIDS_FILE" <<EOF
================================================================================
                    🛡️  SIEM AFRICA - FICHIER CRIDS
              (Credentials, Ressources, Informations, Diagnostics, Services)
================================================================================
                    Date d'installation: $DATE_INSTALL
                    Version: 2.1 (Corrigée)
================================================================================

╔══════════════════════════════════════════════════════════════════════════════╗
║                         INFORMATIONS DE CONNEXION                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

  🌐 URL Dashboard:        https://$IP_ADDR:5000
  
  👤 Utilisateur:          admin
  🔒 Mot de passe:         $DEFAULT_PASSWORD
  
  ⚠️  IMPORTANT: Vous devez changer le mot de passe à la première connexion !
  
  📅 Validité mot de passe: 90 jours
  🔐 Verrouillage compte:   Après 5 tentatives échouées (15 min)
  
  🐍 Python utilisé:       $PYTHON_INFO


╔══════════════════════════════════════════════════════════════════════════════╗
║                            COMMANDES RAPIDES                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

  systemctl status siem-africa-agent       → Statut agent
  systemctl status siem-africa-dashboard   → Statut web
  tail -f /var/log/siem-africa/agent.log   → Voir logs
  cat /root/SIEM_AFRICA_CRIDS.txt          → Voir CRIDS


╔══════════════════════════════════════════════════════════════════════════════╗
║                         COMMANDES DE DÉPANNAGE                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

  # -------- SI LE DASHBOARD NE DÉMARRE PAS --------
  journalctl -u siem-africa-dashboard -n 50
  
  # -------- TESTER FLASK MANUELLEMENT --------
  cd $DASHBOARD_DIR && python3 app.py
  
  # -------- RÉINSTALLER FLASK SI NÉCESSAIRE --------
  pip3 install flask requests urllib3
  
  # -------- REDÉMARRER LES SERVICES --------
  systemctl restart siem-africa-agent
  systemctl restart siem-africa-dashboard

  # -------- VÉRIFIER LA BASE DE DONNÉES --------
  sqlite3 $DB_DIR/siem_africa.db ".tables"
  sqlite3 $DB_DIR/siem_africa.db "SELECT COUNT(*) FROM regles;"


╔══════════════════════════════════════════════════════════════════════════════╗
║                            FICHIERS INSTALLÉS                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

  📂 $INSTALL_DIR/
     ├── config.json              (Configuration Wazuh API)
     ├── database/
     │   ├── siem_africa_db.sql   (Script SQL)
     │   └── siem_africa.db       (Base de données SQLite)
     ├── dashboard/
     │   ├── app.py               (Application Flask)
     │   ├── agent.py             (Agent d'interprétation)
     │   └── templates/           (Templates HTML)
     ├── ssl/
     │   ├── cert.pem             (Certificat SSL)
     │   └── key.pem              (Clé privée)
     └── venv/                    (Environnement Python)

  📄 /etc/systemd/system/
     ├── siem-africa-agent.service
     └── siem-africa-dashboard.service


================================================================================
  📝 Note: Le navigateur affichera un avertissement car le certificat SSL est
     auto-signé. Cliquez sur 'Avancé' puis 'Continuer vers le site'.
================================================================================
EOF

    chmod 600 "$CRIDS_FILE"
    log_success "Fichier CRIDS créé: $CRIDS_FILE"
}

# =============================================================================
# AFFICHAGE FINAL
# =============================================================================

show_summary() {
    IP_ADDR=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║        ✅ INSTALLATION TERMINÉE AVEC SUCCÈS !               ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  Toutes les informations et commandes ont été sauvegardées  ║${NC}"
    echo -e "${YELLOW}║  dans le fichier:                                           ║${NC}"
    echo -e "${YELLOW}║                                                              ║${NC}"
    echo -e "${YELLOW}║    ${CYAN}/root/SIEM_AFRICA_CRIDS.txt${YELLOW}                              ║${NC}"
    echo -e "${YELLOW}║                                                              ║${NC}"
    echo -e "${YELLOW}║  Pour consulter ce fichier:                                 ║${NC}"
    echo -e "${YELLOW}║    ${CYAN}cat /root/SIEM_AFRICA_CRIDS.txt${YELLOW}                          ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      COMMANDES RAPIDES                       ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}systemctl status siem-africa-agent${NC}       → Statut agent     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}systemctl status siem-africa-dashboard${NC}   → Statut web       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}tail -f /var/log/siem-africa/agent.log${NC}   → Voir logs        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}cat /root/SIEM_AFRICA_CRIDS.txt${NC}          → Voir CRIDS       ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}📝 Note: Le navigateur affichera un avertissement car le${NC}"
    echo -e "${BLUE}   certificat SSL est auto-signé. Cliquez sur 'Avancé'${NC}"
    echo -e "${BLUE}   puis 'Continuer vers le site'.${NC}"
    echo ""
    echo -e "${GREEN}🚀 Installation terminée ! Accédez au dashboard :${NC}"
    echo -e "   ${CYAN}https://$IP_ADDR:5000${NC}"
    echo ""
}

# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

main() {
    print_banner
    check_root
    
    log_info "Début de l'installation..."
    echo ""
    
    # Vérifications
    check_wazuh
    
    # Installation
    install_dependencies
    create_directories
    generate_ssl_certificate
    download_files
    setup_database
    setup_python_env       # CORRIGÉ avec fallback
    get_wazuh_credentials
    create_services        # CORRIGÉ avec bon Python
    configure_firewall
    start_services         # CORRIGÉ avec meilleur diagnostic
    create_crids_file
    
    # Résumé
    show_summary
}

# Exécuter
main "$@"

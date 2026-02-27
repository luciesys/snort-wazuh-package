#!/bin/bash
# =============================================================================
# SIEM AFRICA - Script d'Installation du Dashboard
# =============================================================================
# Ce script installe le dashboard web et l'agent d'interprétation
# Prérequis: Snort + Wazuh déjà installés (via install_siem_v3.sh)
# =============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/opt/siem-africa"
GITHUB_RAW="https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main"
LOG_FILE="/var/log/siem-africa-install.log"

# =============================================================================
# FONCTIONS
# =============================================================================

log() {
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

log_step() {
    echo ""
    echo -e "${BLUE}[ÉTAPE]${NC} $1"
    echo "=============================================" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ÉTAPE: $1" >> "$LOG_FILE"
}

abort() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     ✗ INSTALLATION ARRÊTÉE                                      ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo -e "  Raison: $1"
    echo -e "  Log: $LOG_FILE"
    exit 1
}

# =============================================================================
# VÉRIFICATIONS
# =============================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        abort "Ce script doit être exécuté en tant que root (sudo)"
    fi
    log "Exécution en tant que root"
}

check_wazuh() {
    if ! systemctl is-active --quiet wazuh-manager; then
        abort "Wazuh Manager n'est pas actif. Installez d'abord Snort+Wazuh avec install_siem_v3.sh"
    fi
    log "Wazuh Manager détecté et actif"
}

# =============================================================================
# INSTALLATION
# =============================================================================

show_banner() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║   🛡️  SIEM AFRICA - Installation du Dashboard                    ║"
    echo "║                                                                  ║"
    echo "║   Dashboard Web + Agent d'Interprétation                        ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

install_dependencies() {
    log_step "Installation des dépendances Python"
    
    apt-get update -qq
    apt-get install -y python3 python3-pip python3-venv sqlite3 >> "$LOG_FILE" 2>&1
    
    log "Python3 et SQLite3 installés"
}

create_directories() {
    log_step "Création des répertoires"
    
    mkdir -p "$INSTALL_DIR"/{dashboard,database,logs}
    mkdir -p "$INSTALL_DIR/dashboard/templates"
    mkdir -p "$INSTALL_DIR/dashboard/static"
    mkdir -p /var/log/siem-africa
    
    log "Répertoires créés dans $INSTALL_DIR"
}

download_files() {
    log_step "Téléchargement des fichiers"
    
    # Base de données SQL
    curl -sL "$GITHUB_RAW/database/siem_africa_db.sql" -o "$INSTALL_DIR/database/siem_africa_db.sql"
    log "Base de données SQL téléchargée"
    
    # Agent
    curl -sL "$GITHUB_RAW/dashboard/agent.py" -o "$INSTALL_DIR/dashboard/agent.py"
    log "Agent téléchargé"
    
    # Application Flask
    curl -sL "$GITHUB_RAW/dashboard/app.py" -o "$INSTALL_DIR/dashboard/app.py"
    log "Application Flask téléchargée"
    
    # Templates
    curl -sL "$GITHUB_RAW/dashboard/templates/index.html" -o "$INSTALL_DIR/dashboard/templates/index.html"
    curl -sL "$GITHUB_RAW/dashboard/templates/detail.html" -o "$INSTALL_DIR/dashboard/templates/detail.html"
    curl -sL "$GITHUB_RAW/dashboard/templates/alertes.html" -o "$INSTALL_DIR/dashboard/templates/alertes.html"
    log "Templates HTML téléchargés"
}

setup_database() {
    log_step "Configuration de la base de données"
    
    # Créer la base de données SQLite
    sqlite3 "$INSTALL_DIR/database/siem_africa.db" < "$INSTALL_DIR/database/siem_africa_db.sql"
    
    # Permissions
    chmod 644 "$INSTALL_DIR/database/siem_africa.db"
    
    # Compter les règles
    RULES_COUNT=$(sqlite3 "$INSTALL_DIR/database/siem_africa.db" "SELECT COUNT(*) FROM regles;")
    log "Base de données créée avec $RULES_COUNT règles"
}

setup_python_env() {
    log_step "Configuration de l'environnement Python"
    
    # Créer un environnement virtuel
    python3 -m venv "$INSTALL_DIR/venv"
    
    # Installer les dépendances
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip >> "$LOG_FILE" 2>&1
    "$INSTALL_DIR/venv/bin/pip" install flask requests >> "$LOG_FILE" 2>&1
    
    log "Environnement Python configuré"
}

get_wazuh_password() {
    log_step "Récupération du mot de passe Wazuh API"
    
    # Essayer de lire depuis le fichier credentials
    if [ -f "/root/siem_credentials.txt" ]; then
        WAZUH_PASS=$(grep -i "wazuh.*api\|admin" /root/siem_credentials.txt | grep -oP ':\s*\K.*' | head -1)
    fi
    
    # Si pas trouvé, essayer wazuh-passwords
    if [ -z "$WAZUH_PASS" ] && [ -f "/root/wazuh-install-files/wazuh-passwords.txt" ]; then
        WAZUH_PASS=$(grep "api" /root/wazuh-install-files/wazuh-passwords.txt | grep -oP ':\s*\K.*' | head -1)
    fi
    
    # Valeur par défaut
    if [ -z "$WAZUH_PASS" ]; then
        WAZUH_PASS="wazuh"
        log_warning "Mot de passe Wazuh API non trouvé, utilisation de 'wazuh'"
    else
        log "Mot de passe Wazuh API récupéré"
    fi
}

create_config() {
    log_step "Création du fichier de configuration"
    
    cat > "$INSTALL_DIR/config.json" << EOF
{
    "wazuh_host": "localhost",
    "wazuh_port": 55000,
    "wazuh_user": "wazuh",
    "wazuh_password": "$WAZUH_PASS",
    "db_path": "$INSTALL_DIR/database/siem_africa.db",
    "log_path": "/var/log/siem-africa/agent.log",
    "check_interval": 30,
    "alerts_limit": 100
}
EOF
    
    chmod 600 "$INSTALL_DIR/config.json"
    log "Configuration créée"
}

create_systemd_services() {
    log_step "Création des services systemd"
    
    # Service Agent
    cat > /etc/systemd/system/siem-africa-agent.service << EOF
[Unit]
Description=SIEM Africa - Agent d'Interprétation
After=network.target wazuh-manager.service
Wants=wazuh-manager.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/dashboard
Environment="SIEM_DB_PATH=$INSTALL_DIR/database/siem_africa.db"
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/dashboard/agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Service Dashboard
    cat > /etc/systemd/system/siem-africa-dashboard.service << EOF
[Unit]
Description=SIEM Africa - Dashboard Web
After=network.target siem-africa-agent.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR/dashboard
Environment="SIEM_DB_PATH=$INSTALL_DIR/database/siem_africa.db"
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/dashboard/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Recharger systemd
    systemctl daemon-reload
    
    log "Services systemd créés"
}

start_services() {
    log_step "Démarrage des services"
    
    # Activer et démarrer l'agent
    systemctl enable siem-africa-agent >> "$LOG_FILE" 2>&1
    systemctl start siem-africa-agent
    sleep 2
    
    if systemctl is-active --quiet siem-africa-agent; then
        log "Agent SIEM Africa démarré"
    else
        log_warning "L'agent n'a pas démarré correctement"
    fi
    
    # Activer et démarrer le dashboard
    systemctl enable siem-africa-dashboard >> "$LOG_FILE" 2>&1
    systemctl start siem-africa-dashboard
    sleep 2
    
    if systemctl is-active --quiet siem-africa-dashboard; then
        log "Dashboard SIEM Africa démarré"
    else
        log_warning "Le dashboard n'a pas démarré correctement"
    fi
}

show_summary() {
    # Récupérer l'IP
    IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     ✓ INSTALLATION TERMINÉE AVEC SUCCÈS !                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}ACCÈS AU DASHBOARD${NC}"
    echo -e "  URL         : ${GREEN}http://$IP:5000${NC}"
    echo ""
    echo -e "${BLUE}SERVICES${NC}"
    echo -e "  Agent       : systemctl status siem-africa-agent"
    echo -e "  Dashboard   : systemctl status siem-africa-dashboard"
    echo ""
    echo -e "${BLUE}FICHIERS${NC}"
    echo -e "  Installation: $INSTALL_DIR"
    echo -e "  Base données: $INSTALL_DIR/database/siem_africa.db"
    echo -e "  Config      : $INSTALL_DIR/config.json"
    echo -e "  Logs agent  : /var/log/siem-africa/agent.log"
    echo ""
    echo -e "${BLUE}COMMANDES UTILES${NC}"
    echo -e "  Voir les logs : tail -f /var/log/siem-africa/agent.log"
    echo -e "  Redémarrer    : sudo systemctl restart siem-africa-agent siem-africa-dashboard"
    echo ""
    echo -e "${YELLOW}📊 L'agent analyse les alertes Wazuh toutes les 30 secondes${NC}"
    echo -e "${YELLOW}🌐 Ouvrez votre navigateur sur http://$IP:5000${NC}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Créer le fichier de log
    mkdir -p /var/log
    touch "$LOG_FILE"
    
    show_banner
    
    check_root
    check_wazuh
    
    install_dependencies
    create_directories
    download_files
    setup_database
    setup_python_env
    get_wazuh_password
    create_config
    create_systemd_services
    start_services
    
    show_summary
}

main "$@"

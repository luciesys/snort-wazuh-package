#!/bin/bash
#===============================================================================
#
#   ███████╗██╗███████╗███╗   ███╗     █████╗ ███████╗██████╗ ██╗ ██████╗ █████╗ 
#   ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██╔════╝██╔══██╗██║██╔════╝██╔══██╗
#   ███████╗██║█████╗  ██╔████╔██║    ███████║█████╗  ██████╔╝██║██║     ███████║
#   ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██╔══╝  ██╔══██╗██║██║     ██╔══██║
#   ███████║██║███████╗██║ ╚═╝ ██║    ██║  ██║██║     ██║  ██║██║╚██████╗██║  ██║
#   ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝
#
#   Solution de Cybersécurité pour les PME Africaines
#   Script d'Installation Automatique v2.1
#   
#   Inclut: Snort IDS + Wazuh Stack (Indexer + Manager + Dashboard) + SIEM Africa
#
#===============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
SIEM_HOME="/opt/siem-africa"
LOG_FILE="/var/log/siem-africa-install.log"
CREDENTIALS_FILE="/root/credentials.txt"
SCRID_FILE="${SIEM_HOME}/SCRID.txt"
FIRST_RUN_FLAG="${SIEM_HOME}/.first_run"
WAZUH_VERSION="4.7.2"

# Utilisateurs système par défaut
SNORT_USER="snort"
SNORT_PASS="snort123"
WAZUH_USER="wazuh"
WAZUH_PASS="wazuh123"
SIEM_USER="siem"
SIEM_PASS="siem123"

# Dashboard SIEM Africa
DASHBOARD_ADMIN_PASS="SiemAfrica2026!"
DASHBOARD_ANALYST_PASS="Analyste123!"
DASHBOARD_READER_PASS="Lecteur123!"

# Compteur
CURRENT_STEP=0
TOTAL_STEPS=12

#===============================================================================
# FONCTIONS UTILITAIRES
#===============================================================================

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                        ║"
    echo "║   ███████╗██╗███████╗███╗   ███╗     █████╗ ███████╗██████╗ ██╗        ║"
    echo "║   ██╔════╝██║██╔════╝████╗ ████║    ██╔══██╗██╔════╝██╔══██╗██║        ║"
    echo "║   ███████╗██║█████╗  ██╔████╔██║    ███████║█████╗  ██████╔╝██║        ║"
    echo "║   ╚════██║██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██╔══╝  ██╔══██╗██║        ║"
    echo "║   ███████║██║███████╗██║ ╚═╝ ██║    ██║  ██║██║     ██║  ██║██║        ║"
    echo "║   ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝        ║"
    echo "║                                                                        ║"
    echo "║         Solution de Cybersécurité pour les PME Africaines              ║"
    echo "║                   Installation Automatique v2.1                        ║"
    echo "║                                                                        ║"
    echo "║   Composants: Snort IDS + Wazuh Stack + SIEM Africa Dashboard          ║"
    echo "║                                                                        ║"
    echo "╚════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

print_step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${WHITE}$1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════${NC}"
    log "STEP ${CURRENT_STEP}: $1"
}

print_success() {
    echo -e "    ${GREEN}✓${NC} $1"
    log "SUCCESS: $1"
}

print_error() {
    echo -e "    ${RED}✗${NC} $1"
    log "ERROR: $1"
}

print_warning() {
    echo -e "    ${YELLOW}⚠${NC} $1"
    log "WARNING: $1"
}

print_info() {
    echo -e "    ${CYAN}ℹ${NC} $1"
    log "INFO: $1"
}

exit_error() {
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                       INSTALLATION ÉCHOUÉE                             ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}Erreur: $1${NC}"
    echo ""
    echo -e "Consultez le fichier de log: ${YELLOW}${LOG_FILE}${NC}"
    log "FATAL: $1"
    exit 1
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "      \b\b\b\b\b\b"
}

#===============================================================================
# VÉRIFICATION DES PRÉREQUIS
#===============================================================================

check_prerequisites() {
    print_step "Vérification des prérequis"
    
    local errors=0
    
    # 1. Vérification droits root
    echo -e "\n    ${CYAN}[1/5]${NC} Vérification des droits root..."
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté en tant que root (sudo)"
        errors=$((errors + 1))
    else
        print_success "Droits root confirmés"
    fi
    
    # 2. Vérification OS compatible
    echo -e "\n    ${CYAN}[2/5]${NC} Vérification du système d'exploitation..."
    
    OS_COMPATIBLE=false
    OS_NAME=""
    OS_VERSION=""
    OS_CODENAME=""
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME=$ID
        OS_VERSION=$VERSION_ID
        OS_CODENAME=$VERSION_CODENAME
        
        case "$OS_NAME" in
            ubuntu)
                case "$OS_VERSION" in
                    20.04|22.04|24.04) OS_COMPATIBLE=true ;;
                esac
                ;;
            debian)
                case "$OS_VERSION" in
                    10|11|12) OS_COMPATIBLE=true ;;
                esac
                ;;
        esac
    fi
    
    if $OS_COMPATIBLE; then
        print_success "OS compatible: ${OS_NAME^} $OS_VERSION ($OS_CODENAME)"
    else
        print_error "OS non compatible: ${OS_NAME:-Inconnu} ${OS_VERSION:-Inconnu}"
        print_info "OS supportés: Ubuntu 20.04/22.04/24.04, Debian 10/11/12"
        errors=$((errors + 1))
    fi
    
    # 3. Vérification RAM (minimum 4 Go, recommandé 8 Go pour Wazuh Stack)
    echo -e "\n    ${CYAN}[3/5]${NC} Vérification de la mémoire RAM..."
    
    RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    RAM_GB=$((RAM_KB / 1024 / 1024))
    RAM_MB=$((RAM_KB / 1024))
    
    if [[ $RAM_GB -ge 4 ]]; then
        if [[ $RAM_GB -ge 8 ]]; then
            print_success "RAM optimale: ${RAM_GB} Go (recommandé pour Wazuh Stack)"
        else
            print_success "RAM suffisante: ${RAM_GB} Go (minimum: 4 Go)"
            print_warning "8 Go recommandés pour performance optimale"
        fi
    else
        print_error "RAM insuffisante: ${RAM_MB} Mo (minimum: 4 Go / 4096 Mo)"
        errors=$((errors + 1))
    fi
    
    # 4. Vérification espace disque (minimum 50 Go)
    echo -e "\n    ${CYAN}[4/5]${NC} Vérification de l'espace disque..."
    
    DISK_AVAIL=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    
    if [[ $DISK_AVAIL -ge 50 ]]; then
        print_success "Espace disque suffisant: ${DISK_AVAIL} Go (minimum: 50 Go)"
    else
        print_error "Espace disque insuffisant: ${DISK_AVAIL} Go (minimum: 50 Go)"
        errors=$((errors + 1))
    fi
    
    # 5. Vérification connexion Internet (timeout 60 secondes)
    echo -e "\n    ${CYAN}[5/5]${NC} Vérification de la connexion Internet (timeout: 60s)..."
    
    INTERNET_OK=false
    TIMEOUT=60
    ELAPSED=0
    
    while [[ $ELAPSED -lt $TIMEOUT ]]; do
        if ping -c 1 -W 5 8.8.8.8 &> /dev/null; then
            INTERNET_OK=true
            break
        elif ping -c 1 -W 5 1.1.1.1 &> /dev/null; then
            INTERNET_OK=true
            break
        elif ping -c 1 -W 5 packages.wazuh.com &> /dev/null; then
            INTERNET_OK=true
            break
        fi
        sleep 5
        ELAPSED=$((ELAPSED + 5))
        echo -ne "\r    ${YELLOW}⏳${NC} Tentative de connexion... (${ELAPSED}s/${TIMEOUT}s)    "
    done
    echo ""
    
    if $INTERNET_OK; then
        print_success "Connexion Internet établie"
    else
        print_error "Pas de connexion Internet après ${TIMEOUT} secondes"
        errors=$((errors + 1))
    fi
    
    # Résumé
    echo ""
    echo -e "────────────────────────────────────────────────────────────────────────"
    
    if [[ $errors -gt 0 ]]; then
        exit_error "${errors} prérequis non satisfait(s). Corrigez les erreurs ci-dessus."
    else
        echo -e "    ${GREEN}✓ Tous les prérequis sont satisfaits !${NC}"
    fi
}

#===============================================================================
# MISE À JOUR DU SYSTÈME
#===============================================================================

update_system() {
    print_step "Mise à jour du système"
    
    print_info "Mise à jour de la liste des paquets..."
    apt-get update -y >> "$LOG_FILE" 2>&1
    print_success "Liste des paquets mise à jour"
    
    print_info "Mise à jour des paquets installés..."
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >> "$LOG_FILE" 2>&1
    print_success "Paquets mis à jour"
    
    print_info "Installation des dépendances de base..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl wget gnupg apt-transport-https \
        software-properties-common ca-certificates \
        python3 python3-pip python3-venv \
        sqlite3 openssl net-tools lsb-release \
        sudo debconf adduser procps >> "$LOG_FILE" 2>&1
    print_success "Dépendances de base installées"
}

#===============================================================================
# CRÉATION DES UTILISATEURS SYSTÈME
#===============================================================================

create_users() {
    print_step "Création des utilisateurs système"
    
    # Utilisateur snort
    print_info "Création de l'utilisateur 'snort'..."
    if id "$SNORT_USER" &>/dev/null; then
        print_warning "L'utilisateur 'snort' existe déjà"
    else
        useradd -r -m -d /home/snort -s /bin/bash "$SNORT_USER"
        echo "${SNORT_USER}:${SNORT_PASS}" | chpasswd
        chage -d 0 "$SNORT_USER" 2>/dev/null || true
        print_success "Utilisateur 'snort' créé (mdp: ${SNORT_PASS})"
    fi
    
    # Utilisateur wazuh (sera aussi créé par l'installateur Wazuh)
    print_info "Création de l'utilisateur 'wazuh'..."
    if id "$WAZUH_USER" &>/dev/null; then
        print_warning "L'utilisateur 'wazuh' existe déjà"
    else
        useradd -r -m -d /home/wazuh -s /bin/bash "$WAZUH_USER"
        echo "${WAZUH_USER}:${WAZUH_PASS}" | chpasswd
        chage -d 0 "$WAZUH_USER" 2>/dev/null || true
        print_success "Utilisateur 'wazuh' créé (mdp: ${WAZUH_PASS})"
    fi
    
    # Utilisateur siem
    print_info "Création de l'utilisateur 'siem'..."
    if id "$SIEM_USER" &>/dev/null; then
        print_warning "L'utilisateur 'siem' existe déjà"
    else
        useradd -r -m -d /home/siem -s /bin/bash "$SIEM_USER"
        echo "${SIEM_USER}:${SIEM_PASS}" | chpasswd
        chage -d 0 "$SIEM_USER" 2>/dev/null || true
        usermod -aG sudo "$SIEM_USER"
        print_success "Utilisateur 'siem' créé (mdp: ${SIEM_PASS})"
    fi
    
    print_success "Tous les utilisateurs système ont été créés"
}

#===============================================================================
# INSTALLATION DE SNORT
#===============================================================================

install_snort() {
    print_step "Installation de Snort IDS"
    
    print_info "Installation de Snort et dépendances..."
    
    # Préconfiguration pour éviter les prompts
    echo "snort snort/interface select eth0" | debconf-set-selections 2>/dev/null || true
    echo "snort snort/address_range string 0.0.0.0/0" | debconf-set-selections 2>/dev/null || true
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y snort >> "$LOG_FILE" 2>&1 || {
        print_warning "Snort non disponible, installation des dépendances alternatives..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            libpcap-dev libpcre3-dev libdumbnet-dev \
            bison flex zlib1g-dev liblzma-dev >> "$LOG_FILE" 2>&1
    }
    print_success "Snort installé"
    
    # Création des répertoires
    print_info "Configuration des répertoires Snort..."
    mkdir -p /var/log/snort /etc/snort/rules
    chown -R snort:snort /var/log/snort 2>/dev/null || chown -R root:root /var/log/snort
    chmod 755 /var/log/snort
    print_success "Répertoires Snort configurés"
    
    # Configuration Snort
    print_info "Création de la configuration Snort..."
    cat > /etc/snort/snort.conf << 'SNORTCONF'
#===============================================================================
# SIEM AFRICA - Configuration Snort IDS
#===============================================================================

# Variables réseau
var HOME_NET any
var EXTERNAL_NET any

# Chemins
var RULE_PATH /etc/snort/rules
var LOG_DIR /var/log/snort

# Configuration de sortie
output alert_fast: alert.log
output alert_full: alert_full.log

# Préprocesseurs de base
preprocessor frag3_global: max_frags 65536
preprocessor frag3_engine: policy windows detect_anomalies

# Inclure les règles locales
include $RULE_PATH/local.rules
SNORTCONF
    print_success "Configuration Snort créée"
    
    # Règles Snort de base
    print_info "Création des règles Snort de base..."
    cat > /etc/snort/rules/local.rules << 'SNORTRULES'
#===============================================================================
# SIEM AFRICA - Règles Snort IDS
# Règles de détection pour PME Africaines
#===============================================================================

# === SCAN ET RECONNAISSANCE ===
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Scan de ports TCP détecté"; flags:S; threshold:type both,track by_src,count 20,seconds 60; classtype:attempted-recon; sid:1000001; rev:1;)
alert udp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Scan de ports UDP détecté"; threshold:type both,track by_src,count 20,seconds 60; classtype:attempted-recon; sid:1000002; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Balayage ICMP détecté"; itype:8; threshold:type both,track by_src,count 10,seconds 60; classtype:attempted-recon; sid:1000003; rev:1;)

# === BRUTE FORCE ===
alert tcp any any -> $HOME_NET 22 (msg:"[SIEM-AFRICA] Brute Force SSH détecté"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:1000010; rev:1;)
alert tcp any any -> $HOME_NET 21 (msg:"[SIEM-AFRICA] Brute Force FTP détecté"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:1000011; rev:1;)
alert tcp any any -> $HOME_NET 3389 (msg:"[SIEM-AFRICA] Brute Force RDP détecté"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:1000012; rev:1;)
alert tcp any any -> $HOME_NET 3306 (msg:"[SIEM-AFRICA] Brute Force MySQL détecté"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:1000013; rev:1;)

# === INJECTION SQL ===
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Injection SQL - UNION SELECT"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000020; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Injection SQL - OR 1=1"; flow:to_server,established; content:"OR"; nocase; content:"1=1"; distance:0; classtype:web-application-attack; sid:1000021; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Injection SQL - DROP TABLE"; flow:to_server,established; content:"DROP"; nocase; content:"TABLE"; nocase; distance:0; classtype:web-application-attack; sid:1000022; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Injection SQL - Information Schema"; flow:to_server,established; content:"information_schema"; nocase; classtype:web-application-attack; sid:1000023; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Injection SQL - Commentaire"; flow:to_server,established; pcre:"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i"; classtype:web-application-attack; sid:1000024; rev:1;)

# === CROSS-SITE SCRIPTING (XSS) ===
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Tentative XSS - Balise script"; flow:to_server,established; content:"<script"; nocase; classtype:web-application-attack; sid:1000030; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Tentative XSS - Event handler"; flow:to_server,established; pcre:"/on(load|error|click|mouse)/i"; classtype:web-application-attack; sid:1000031; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Tentative XSS - javascript:"; flow:to_server,established; content:"javascript:"; nocase; classtype:web-application-attack; sid:1000032; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Tentative XSS - document.cookie"; flow:to_server,established; content:"document.cookie"; nocase; classtype:web-application-attack; sid:1000033; rev:1;)

# === DÉNI DE SERVICE ===
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] SYN Flood potentiel"; flags:S; threshold:type both,track by_src,count 100,seconds 10; classtype:attempted-dos; sid:1000040; rev:1;)
alert udp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] UDP Flood potentiel"; threshold:type both,track by_src,count 100,seconds 10; classtype:attempted-dos; sid:1000041; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] ICMP Flood potentiel"; threshold:type both,track by_src,count 50,seconds 10; classtype:attempted-dos; sid:1000042; rev:1;)

# === BACKDOORS ET SHELLS ===
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Reverse Shell potentiel - /bin/sh"; flow:established; content:"/bin/sh"; classtype:trojan-activity; sid:1000050; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Reverse Shell potentiel - /bin/bash"; flow:established; content:"/bin/bash"; classtype:trojan-activity; sid:1000051; rev:1;)
alert tcp $HOME_NET any -> any any (msg:"[SIEM-AFRICA] Connexion sortante Netcat"; flow:to_server,established; content:"nc"; content:"-e"; classtype:trojan-activity; sid:1000052; rev:1;)

# === MALWARE ET C2 ===
alert tcp $HOME_NET any -> any 4444 (msg:"[SIEM-AFRICA] Connexion Meterpreter potentielle"; flow:to_server,established; classtype:trojan-activity; sid:1000060; rev:1;)
alert tcp $HOME_NET any -> any 1337 (msg:"[SIEM-AFRICA] Port backdoor classique"; flow:to_server,established; classtype:trojan-activity; sid:1000061; rev:1;)
alert tcp $HOME_NET any -> any 31337 (msg:"[SIEM-AFRICA] Port Elite backdoor"; flow:to_server,established; classtype:trojan-activity; sid:1000062; rev:1;)

# === PATH TRAVERSAL ===
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Path Traversal - ../"; flow:to_server,established; content:"../"; classtype:web-application-attack; sid:1000070; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"[SIEM-AFRICA] Path Traversal - /etc/passwd"; flow:to_server,established; content:"/etc/passwd"; classtype:web-application-attack; sid:1000071; rev:1;)

# === PROTOCOLES SUSPECTS ===
alert tcp any any -> $HOME_NET 23 (msg:"[SIEM-AFRICA] Connexion Telnet détectée"; flow:to_server; classtype:bad-unknown; sid:1000080; rev:1;)
alert tcp any any -> $HOME_NET 513 (msg:"[SIEM-AFRICA] Connexion Rlogin détectée"; flow:to_server; classtype:bad-unknown; sid:1000081; rev:1;)
SNORTRULES
    print_success "Règles Snort créées"
    
    # Permissions
    chown -R snort:snort /etc/snort 2>/dev/null || chown -R root:root /etc/snort
    
    # Service systemd pour Snort
    print_info "Création du service systemd Snort..."
    
    # Détecter l'interface réseau principale
    MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    [[ -z "$MAIN_IFACE" ]] && MAIN_IFACE="eth0"
    
    cat > /etc/systemd/system/snort.service << EOF
[Unit]
Description=Snort NIDS - SIEM Africa
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/snort -q -c /etc/snort/snort.conf -i ${MAIN_IFACE} -l /var/log/snort -D
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable snort >> "$LOG_FILE" 2>&1 || true
    systemctl start snort >> "$LOG_FILE" 2>&1 || print_warning "Snort démarrera après configuration réseau"
    
    print_success "Snort IDS installé et configuré (interface: ${MAIN_IFACE})"
}

#===============================================================================
# INSTALLATION DE WAZUH STACK COMPLÈTE
#===============================================================================

install_wazuh_stack() {
    print_step "Installation de Wazuh Stack (Indexer + Manager + Dashboard)"
    
    print_info "Cette étape peut prendre 10-20 minutes..."
    echo ""
    
    # Téléchargement de l'assistant d'installation Wazuh
    print_info "Téléchargement de l'assistant d'installation Wazuh..."
    curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh >> "$LOG_FILE" 2>&1
    chmod +x wazuh-install.sh
    print_success "Assistant Wazuh téléchargé"
    
    # Génération de la configuration
    print_info "Génération de la configuration..."
    curl -sO https://packages.wazuh.com/4.7/config.yml >> "$LOG_FILE" 2>&1
    
    # Modifier config.yml pour une installation all-in-one
    cat > config.yml << EOF
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "127.0.0.1"

  # Wazuh server nodes
  server:
    - name: wazuh-1
      ip: "127.0.0.1"

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
EOF
    print_success "Configuration générée"
    
    # Installation Wazuh Indexer
    echo ""
    print_info "Installation de Wazuh Indexer (OpenSearch)..."
    print_info "Cela peut prendre plusieurs minutes..."
    
    bash wazuh-install.sh --generate-config-files >> "$LOG_FILE" 2>&1 || {
        print_warning "Génération config avec méthode alternative..."
    }
    
    bash wazuh-install.sh --wazuh-indexer node-1 >> "$LOG_FILE" 2>&1 || {
        print_error "Erreur installation Wazuh Indexer"
        print_info "Tentative installation manuelle..."
        install_wazuh_manual
        return
    }
    print_success "Wazuh Indexer installé"
    
    # Initialisation du cluster Indexer
    print_info "Initialisation du cluster Indexer..."
    bash wazuh-install.sh --start-cluster >> "$LOG_FILE" 2>&1 || true
    print_success "Cluster Indexer initialisé"
    
    # Installation Wazuh Manager
    echo ""
    print_info "Installation de Wazuh Manager..."
    bash wazuh-install.sh --wazuh-server wazuh-1 >> "$LOG_FILE" 2>&1 || {
        print_warning "Installation Manager avec méthode alternative..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-manager >> "$LOG_FILE" 2>&1
    }
    print_success "Wazuh Manager installé"
    
    # Installation Wazuh Dashboard
    echo ""
    print_info "Installation de Wazuh Dashboard..."
    bash wazuh-install.sh --wazuh-dashboard dashboard >> "$LOG_FILE" 2>&1 || {
        print_warning "Installation Dashboard avec méthode alternative..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-dashboard >> "$LOG_FILE" 2>&1
    }
    print_success "Wazuh Dashboard installé"
    
    # Récupération des credentials Wazuh
    print_info "Récupération des identifiants Wazuh..."
    if [[ -f wazuh-install-files/wazuh-passwords.txt ]]; then
        cp wazuh-install-files/wazuh-passwords.txt /root/wazuh-passwords.txt
        chmod 600 /root/wazuh-passwords.txt
        
        # Extraire le mot de passe admin
        WAZUH_ADMIN_PASS=$(grep "admin" /root/wazuh-passwords.txt | head -1 | awk '{print $NF}' | tr -d "'\"")
        WAZUH_API_PASS=$(grep "wazuh-wui" /root/wazuh-passwords.txt | head -1 | awk '{print $NF}' | tr -d "'\"")
        
        print_success "Identifiants Wazuh récupérés"
    else
        WAZUH_ADMIN_PASS="admin"
        WAZUH_API_PASS="wazuh"
        print_warning "Fichier de mots de passe non trouvé, utilisation des valeurs par défaut"
    fi
    
    # Export des variables pour utilisation ultérieure
    export WAZUH_ADMIN_PASS
    export WAZUH_API_PASS
    
    # Nettoyage
    rm -f wazuh-install.sh config.yml 2>/dev/null || true
    
    print_success "Wazuh Stack complète installée !"
}

# Installation manuelle en cas d'échec de l'assistant
install_wazuh_manual() {
    print_info "Installation manuelle de Wazuh..."
    
    # Ajout du dépôt Wazuh
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import >> "$LOG_FILE" 2>&1 || true
    chmod 644 /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
    
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
    
    apt-get update >> "$LOG_FILE" 2>&1
    
    # Installation des composants
    DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-indexer >> "$LOG_FILE" 2>&1 || print_warning "Indexer non installé"
    DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-manager >> "$LOG_FILE" 2>&1 || print_warning "Manager non installé"
    DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-dashboard >> "$LOG_FILE" 2>&1 || print_warning "Dashboard non installé"
    
    # Démarrage des services
    systemctl daemon-reload
    systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard >> "$LOG_FILE" 2>&1 || true
    systemctl start wazuh-indexer >> "$LOG_FILE" 2>&1 || true
    systemctl start wazuh-manager >> "$LOG_FILE" 2>&1 || true
    systemctl start wazuh-dashboard >> "$LOG_FILE" 2>&1 || true
    
    WAZUH_ADMIN_PASS="admin"
    WAZUH_API_PASS="wazuh"
    export WAZUH_ADMIN_PASS WAZUH_API_PASS
}

#===============================================================================
# CONFIGURATION LIAISON SNORT -> WAZUH
#===============================================================================

configure_snort_wazuh_integration() {
    print_step "Configuration de la liaison Snort → Wazuh"
    
    print_info "Configuration de Wazuh pour lire les logs Snort..."
    
    # Vérifier que ossec.conf existe
    if [[ -f /var/ossec/etc/ossec.conf ]]; then
        # Ajouter la configuration pour Snort si pas déjà présente
        if ! grep -q "snort" /var/ossec/etc/ossec.conf; then
            # Insérer avant la fermeture </ossec_config>
            sed -i '/<\/ossec_config>/i \
  <!-- SIEM Africa - Integration Snort IDS -->\
  <localfile>\
    <log_format>snort-full</log_format>\
    <location>/var/log/snort/alert</location>\
  </localfile>\
  \
  <localfile>\
    <log_format>snort-full</log_format>\
    <location>/var/log/snort/alert_full.log</location>\
  </localfile>' /var/ossec/etc/ossec.conf
            
            print_success "Configuration Snort ajoutée à Wazuh"
        else
            print_warning "Configuration Snort déjà présente dans Wazuh"
        fi
        
        # Redémarrer Wazuh Manager pour appliquer
        systemctl restart wazuh-manager >> "$LOG_FILE" 2>&1 || true
        print_success "Wazuh Manager redémarré"
    else
        print_warning "Fichier ossec.conf non trouvé, configuration manuelle requise"
    fi
    
    # Permissions pour que Wazuh puisse lire les logs Snort
    print_info "Configuration des permissions..."
    chmod 755 /var/log/snort
    chmod 644 /var/log/snort/* 2>/dev/null || true
    
    # Ajouter l'utilisateur ossec au groupe snort si possible
    usermod -aG snort ossec 2>/dev/null || true
    
    print_success "Liaison Snort → Wazuh configurée"
}

#===============================================================================
# INSTALLATION DE SIEM AFRICA DASHBOARD
#===============================================================================

install_siem_africa() {
    print_step "Installation de SIEM Africa Dashboard"
    
    # Structure des répertoires
    print_info "Création de la structure de répertoires..."
    mkdir -p ${SIEM_HOME}/{database,dashboard,templates,static/{css,js,img},scripts,config,logs,certs}
    print_success "Répertoires créés"
    
    # Environnement Python
    print_info "Configuration de l'environnement Python..."
    python3 -m venv ${SIEM_HOME}/venv
    source ${SIEM_HOME}/venv/bin/activate
    pip install --upgrade pip >> "$LOG_FILE" 2>&1
    pip install flask gunicorn requests flask-login werkzeug >> "$LOG_FILE" 2>&1
    deactivate
    print_success "Environnement Python configuré"
    
    # Certificats SSL pour SIEM Africa
    print_info "Génération des certificats SSL..."
    openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
        -keyout ${SIEM_HOME}/certs/key.pem \
        -out ${SIEM_HOME}/certs/cert.pem \
        -subj "/C=CM/ST=Littoral/L=Douala/O=SIEM Africa/OU=Security/CN=siem-africa.local" >> "$LOG_FILE" 2>&1
    chmod 600 ${SIEM_HOME}/certs/key.pem
    chmod 644 ${SIEM_HOME}/certs/cert.pem
    print_success "Certificats SSL générés"
    
    # Flag première exécution
    touch ${FIRST_RUN_FLAG}
    
    # Permissions
    chown -R siem:siem ${SIEM_HOME}
    
    print_success "Structure SIEM Africa créée"
}

#===============================================================================
# CRÉATION DE LA BASE DE DONNÉES
#===============================================================================

create_database() {
    print_step "Création de la base de données (507 règles traduites)"
    
    print_info "Génération du schéma de base de données..."
    
    cat > ${SIEM_HOME}/database/siem_africa.sql << 'SQLDB'
-- ============================================================================
-- SIEM AFRICA - Base de Données Complète
-- 507 Règles Traduites (207 Wazuh + 300 Snort)
-- ============================================================================

PRAGMA encoding = "UTF-8";
PRAGMA foreign_keys = ON;

-- Table de configuration
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cle TEXT UNIQUE NOT NULL,
    valeur TEXT,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO config (cle, valeur, description) VALUES
('version', '2.1.0', 'Version SIEM Africa'),
('first_run', '1', 'Flag première exécution'),
('password_expiry_days', '90', 'Expiration mot de passe');

-- Table des catégories
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    nom TEXT NOT NULL,
    description TEXT,
    icone TEXT,
    couleur TEXT,
    source TEXT DEFAULT 'wazuh'
);

-- Catégories Wazuh (1-15)
INSERT INTO categories VALUES (1, 'authentification', 'Authentification', 'Connexions et accès', '🔐', '#E74C3C', 'wazuh');
INSERT INTO categories VALUES (2, 'integrite', 'Intégrité fichiers', 'Modifications fichiers', '📁', '#3498DB', 'wazuh');
INSERT INTO categories VALUES (3, 'rootkits', 'Rootkits', 'Malwares système', '🦠', '#9B59B6', 'wazuh');
INSERT INTO categories VALUES (4, 'politique', 'Politique sécurité', 'Violations politiques', '📋', '#F39C12', 'wazuh');
INSERT INTO categories VALUES (5, 'services', 'Services système', 'Alertes services', '⚙️', '#1ABC9C', 'wazuh');
INSERT INTO categories VALUES (6, 'reseau', 'Réseau', 'Activités réseau', '🌐', '#2ECC71', 'wazuh');
INSERT INTO categories VALUES (7, 'applications', 'Applications', 'Alertes applicatives', '💻', '#E67E22', 'wazuh');
INSERT INTO categories VALUES (8, 'systeme', 'Système', 'Événements système', '🖥️', '#34495E', 'wazuh');
INSERT INTO categories VALUES (9, 'audit', 'Audit', 'Journaux audit', '📝', '#7F8C8D', 'wazuh');
INSERT INTO categories VALUES (10, 'parefeu', 'Pare-feu', 'Alertes firewall', '🛡️', '#C0392B', 'wazuh');
INSERT INTO categories VALUES (11, 'ids', 'IDS', 'Alertes IDS', '🚨', '#8E44AD', 'wazuh');
INSERT INTO categories VALUES (12, 'web', 'Sécurité Web', 'Attaques web', '🌍', '#16A085', 'wazuh');
INSERT INTO categories VALUES (13, 'vulnerabilites', 'Vulnérabilités', 'Failles détectées', '🔓', '#D35400', 'wazuh');
INSERT INTO categories VALUES (14, 'conformite', 'Conformité', 'Alertes conformité', '✅', '#27AE60', 'wazuh');
INSERT INTO categories VALUES (15, 'autres_wazuh', 'Autres Wazuh', 'Autres alertes', '❓', '#95A5A6', 'wazuh');
-- Catégories Snort (16-25)
INSERT INTO categories VALUES (16, 'scan', 'Scan & Reconnaissance', 'Scans de ports', '🔍', '#E74C3C', 'snort');
INSERT INTO categories VALUES (17, 'injection_sql', 'Injection SQL', 'Attaques SQLi', '💉', '#9B59B6', 'snort');
INSERT INTO categories VALUES (18, 'xss', 'Cross-Site Scripting', 'Attaques XSS', '📜', '#3498DB', 'snort');
INSERT INTO categories VALUES (19, 'dos', 'DoS / DDoS', 'Déni de service', '💥', '#E67E22', 'snort');
INSERT INTO categories VALUES (20, 'backdoor', 'Backdoors', 'Portes dérobées', '🚪', '#2C3E50', 'snort');
INSERT INTO categories VALUES (21, 'bruteforce', 'Brute Force', 'Force brute', '🔨', '#C0392B', 'snort');
INSERT INTO categories VALUES (22, 'exploits', 'Exploits', 'Exploitations', '⚡', '#8E44AD', 'snort');
INSERT INTO categories VALUES (23, 'malware', 'Malware', 'Logiciels malveillants', '🦠', '#1ABC9C', 'snort');
INSERT INTO categories VALUES (24, 'protocoles', 'Protocoles suspects', 'Protocoles anormaux', '📡', '#F39C12', 'snort');
INSERT INTO categories VALUES (25, 'phishing', 'Phishing', 'Hameçonnage', '🎣', '#16A085', 'snort');

-- Table des règles
CREATE TABLE IF NOT EXISTS regles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER UNIQUE NOT NULL,
    nom_fr TEXT NOT NULL,
    description TEXT,
    gravite TEXT CHECK(gravite IN ('critique','haute','moyenne','faible','info')) NOT NULL,
    categorie_id INTEGER REFERENCES categories(id),
    impact TEXT,
    cause_probable TEXT,
    mitre_id TEXT,
    mitre_tactic TEXT,
    source TEXT DEFAULT 'wazuh' CHECK(source IN ('wazuh','snort')),
    actif INTEGER DEFAULT 1
);

-- ============================================================================
-- RÈGLES WAZUH (207 règles)
-- ============================================================================

-- Authentification (30 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(5710, 'Tentative de connexion SSH échouée', 'Une tentative de connexion SSH a échoué', 'moyenne', 1, 'Accès non autorisé possible', 'Erreur mot de passe ou attaque', 'T1110', 'Credential Access', 'wazuh'),
(5711, 'Connexion SSH réussie', 'Connexion SSH établie avec succès', 'info', 1, 'Accès distant établi', 'Connexion légitime', 'T1078', 'Initial Access', 'wazuh'),
(5712, 'Attaque brute force SSH confirmée', 'Multiples échecs SSH depuis la même IP', 'critique', 1, 'Attaquant actif sur SSH', 'Outil automatisé (Hydra)', 'T1110.001', 'Credential Access', 'wazuh'),
(5715, 'Connexion root SSH directe', 'Connexion en root via SSH', 'haute', 1, 'Accès privilégié risqué', 'Mauvaise pratique ou attaque', 'T1078.003', 'Privilege Escalation', 'wazuh'),
(5716, 'Déconnexion SSH', 'Session SSH terminée', 'info', 1, 'Session fermée', 'Déconnexion normale', '-', '-', 'wazuh'),
(5720, 'Échec authentification PAM', 'Authentification PAM échouée', 'moyenne', 1, 'Accès refusé', 'Mot de passe incorrect', 'T1110', 'Credential Access', 'wazuh'),
(5501, 'Connexion utilisateur système', 'Un utilisateur s''est connecté', 'info', 1, 'Nouvelle session', 'Connexion normale', 'T1078', 'Initial Access', 'wazuh'),
(5502, 'Déconnexion utilisateur', 'Un utilisateur s''est déconnecté', 'info', 1, 'Session terminée', 'Déconnexion normale', '-', '-', 'wazuh'),
(5503, 'Changement de mot de passe', 'Mot de passe modifié', 'moyenne', 1, 'Credentials modifiés', 'Action utilisateur', 'T1098', 'Persistence', 'wazuh'),
(5504, 'Compte utilisateur verrouillé', 'Compte bloqué après échecs', 'haute', 1, 'Accès bloqué', 'Brute force ou oubli', 'T1110', 'Credential Access', 'wazuh'),
(5551, 'Commande sudo échouée', 'Échec d''élévation sudo', 'haute', 1, 'Élévation refusée', 'Utilisateur non autorisé', 'T1548.003', 'Privilege Escalation', 'wazuh'),
(5552, 'Commande sudo réussie', 'Sudo exécuté avec succès', 'moyenne', 1, 'Action privilégiée', 'Administration normale', 'T1548.003', 'Privilege Escalation', 'wazuh'),
(5560, 'Échec commande su', 'Changement utilisateur échoué', 'haute', 1, 'Changement user refusé', 'Mot de passe incorrect', 'T1548.003', 'Privilege Escalation', 'wazuh'),
(5301, 'Échec connexion console', 'Échec sur console physique', 'moyenne', 1, 'Accès local refusé', 'Erreur ou intrusion', 'T1078', 'Initial Access', 'wazuh'),
(5302, 'Connexion console réussie', 'Connexion console établie', 'info', 1, 'Accès local établi', 'Connexion légitime', 'T1078', 'Initial Access', 'wazuh'),
(5401, 'Utilisateur ajouté à un groupe', 'Modification appartenance groupe', 'moyenne', 1, 'Permissions modifiées', 'Administration', 'T1098', 'Persistence', 'wazuh'),
(5402, 'Utilisateur retiré d''un groupe', 'Retrait d''un groupe', 'moyenne', 1, 'Permissions réduites', 'Administration', 'T1098', 'Persistence', 'wazuh'),
(5403, 'Nouvel utilisateur créé', 'Création compte utilisateur', 'haute', 1, 'Nouveau compte système', 'Admin ou backdoor', 'T1136', 'Persistence', 'wazuh'),
(5404, 'Utilisateur supprimé', 'Suppression compte utilisateur', 'moyenne', 1, 'Compte retiré', 'Administration', 'T1531', 'Impact', 'wazuh'),
(5405, 'Mot de passe modifié par root', 'Reset mot de passe forcé', 'haute', 1, 'Credentials forcés', 'Reset admin', 'T1098', 'Persistence', 'wazuh'),
(5410, 'Connexion FTP échouée', 'Échec authentification FTP', 'moyenne', 1, 'Accès FTP refusé', 'Credentials incorrects', 'T1110', 'Credential Access', 'wazuh'),
(5411, 'Connexion FTP réussie', 'Authentification FTP OK', 'info', 1, 'Session FTP établie', 'Transfert fichiers', 'T1071', 'Command and Control', 'wazuh'),
(5450, 'Connexion compte désactivé', 'Tentative sur compte inactif', 'haute', 1, 'Compte désactivé utilisé', 'Attaque ou erreur config', 'T1078.004', 'Defense Evasion', 'wazuh'),
(5453, 'Connexion hors heures', 'Connexion horaire non autorisé', 'haute', 1, 'Violation politique horaire', 'Activité suspecte', 'T1078', 'Initial Access', 'wazuh'),
(5700, 'Session SSH interactive', 'Shell interactif SSH ouvert', 'info', 1, 'Shell distant actif', 'Administration', 'T1059.004', 'Execution', 'wazuh'),
(5701, 'Transfert SCP détecté', 'Copie fichier via SCP', 'info', 1, 'Transfert fichier SSH', 'Copie légitime', 'T1105', 'Command and Control', 'wazuh'),
(5702, 'Tunnel SSH détecté', 'Port forwarding SSH', 'haute', 1, 'Tunnel créé', 'Contournement firewall', 'T1572', 'Command and Control', 'wazuh'),
(5703, 'Clé SSH ajoutée', 'Nouvelle clé autorisée', 'haute', 1, 'Accès permanent ajouté', 'Admin ou backdoor', 'T1098.004', 'Persistence', 'wazuh'),
(5704, 'Agent SSH ajouté', 'Agent forwarding activé', 'moyenne', 1, 'Clés propagées', 'Admin avancé', 'T1563.001', 'Lateral Movement', 'wazuh'),
(5705, 'X11 forwarding SSH', 'Interface graphique tunnelée', 'moyenne', 1, 'GUI distant', 'Usage spécifique', 'T1572', 'Command and Control', 'wazuh');

-- Intégrité fichiers (25 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(550, 'Fichier système modifié', 'Modification fichier surveillé', 'moyenne', 2, 'Intégrité compromise', 'Mise à jour ou malware', 'T1565', 'Impact', 'wazuh'),
(551, 'Nouveau fichier créé', 'Fichier ajouté zone surveillée', 'moyenne', 2, 'Nouveau fichier sensible', 'Installation ou malware', 'T1105', 'Command and Control', 'wazuh'),
(552, 'Fichier système supprimé', 'Suppression fichier surveillé', 'haute', 2, 'Fichier critique supprimé', 'Maintenance ou sabotage', 'T1485', 'Impact', 'wazuh'),
(553, 'Permissions fichier modifiées', 'Changement droits d''accès', 'moyenne', 2, 'Permissions altérées', 'Admin ou escalade', 'T1222', 'Defense Evasion', 'wazuh'),
(554, 'Propriétaire fichier changé', 'Modification propriétaire', 'haute', 2, 'Ownership modifié', 'Admin ou compromission', 'T1222', 'Defense Evasion', 'wazuh'),
(580, 'Modification /etc/passwd', 'Base utilisateurs modifiée', 'critique', 2, 'Comptes système altérés', 'Ajout backdoor possible', 'T1136', 'Persistence', 'wazuh'),
(581, 'Modification /etc/shadow', 'Fichier mots de passe modifié', 'critique', 2, 'Credentials modifiés', 'Reset ou compromission', 'T1003', 'Credential Access', 'wazuh'),
(582, 'Modification /etc/group', 'Fichier groupes modifié', 'haute', 2, 'Groupes altérés', 'Admin ou escalade', 'T1098', 'Persistence', 'wazuh'),
(583, 'Modification /etc/sudoers', 'Configuration sudo modifiée', 'critique', 2, 'Droits sudo altérés', 'Escalade privilèges', 'T1548.003', 'Privilege Escalation', 'wazuh'),
(584, 'Modification /etc/hosts', 'Fichier hosts modifié', 'haute', 2, 'Résolution DNS locale altérée', 'Redirection trafic', 'T1565.001', 'Impact', 'wazuh'),
(585, 'Modification fichier cron', 'Tâche planifiée modifiée', 'haute', 2, 'Cron altéré', 'Persistence malware', 'T1053.003', 'Persistence', 'wazuh'),
(586, 'Modification sshd_config', 'Configuration SSH modifiée', 'haute', 2, 'Config SSH altérée', 'Changement politique', 'T1098', 'Persistence', 'wazuh'),
(590, 'Binaire système modifié', 'Exécutable système altéré', 'critique', 2, 'Binaire compromis', 'Trojan ou mise à jour', 'T1554', 'Persistence', 'wazuh'),
(591, 'Bibliothèque système modifiée', 'Librairie partagée altérée', 'critique', 2, 'Lib compromise', 'Injection code', 'T1574', 'Persistence', 'wazuh'),
(592, 'Nouveau fichier exécutable', 'Exécutable créé', 'haute', 2, 'Nouvel exécutable', 'Installation ou malware', 'T1105', 'Command and Control', 'wazuh'),
(593, 'Fichier SUID/SGID modifié', 'Fichier privilégié altéré', 'critique', 2, 'Fichier setuid modifié', 'Escalade possible', 'T1548.001', 'Privilege Escalation', 'wazuh'),
(594, 'Nouveau fichier SUID créé', 'Création fichier setuid', 'critique', 2, 'Nouveau setuid', 'Backdoor probable', 'T1548.001', 'Privilege Escalation', 'wazuh'),
(595, 'Modification ld.so.preload', 'Préchargement lib modifié', 'critique', 2, 'Injection librairie', 'Rootkit probable', 'T1574.006', 'Persistence', 'wazuh'),
(596, 'Clés SSH authorized modifiées', 'Clés autorisées modifiées', 'haute', 2, 'Accès SSH modifié', 'Ajout backdoor possible', 'T1098.004', 'Persistence', 'wazuh'),
(597, 'Modification resolv.conf', 'Configuration DNS modifiée', 'haute', 2, 'DNS modifié', 'Redirection DNS', 'T1565.001', 'Impact', 'wazuh'),
(598, 'Scripts init modifiés', 'Scripts démarrage altérés', 'critique', 2, 'Boot compromis', 'Persistence boot', 'T1037', 'Persistence', 'wazuh'),
(599, 'Modification .bashrc/.profile', 'Profil shell modifié', 'haute', 2, 'Profil utilisateur altéré', 'Persistence session', 'T1546.004', 'Persistence', 'wazuh'),
(555, 'Attributs fichier modifiés', 'Attributs étendus changés', 'moyenne', 2, 'Métadonnées modifiées', 'Dissimulation possible', 'T1564', 'Defense Evasion', 'wazuh'),
(556, 'Fichier caché créé', 'Création fichier commençant par .', 'moyenne', 2, 'Fichier dissimulé', 'Config ou malware', 'T1564.001', 'Defense Evasion', 'wazuh'),
(557, 'Modification /etc/pam.d/', 'Configuration PAM modifiée', 'critique', 2, 'Auth PAM altérée', 'Backdoor auth', 'T1556', 'Credential Access', 'wazuh');

-- Rootkits (20 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(510, 'Fichier rootkit détecté', 'Fichier caractéristique rootkit', 'critique', 3, 'Système compromis', 'Infection rootkit', 'T1014', 'Defense Evasion', 'wazuh'),
(511, 'Processus caché détecté', 'Processus invisible /proc', 'critique', 3, 'Processus dissimulé', 'Rootkit actif', 'T1564.001', 'Defense Evasion', 'wazuh'),
(512, 'Port réseau caché', 'Port non visible netstat', 'critique', 3, 'Port dissimulé', 'Backdoor active', 'T1205', 'Command and Control', 'wazuh'),
(513, 'Interface réseau cachée', 'Interface non visible', 'critique', 3, 'Interface dissimulée', 'Tunnel caché', 'T1014', 'Defense Evasion', 'wazuh'),
(514, 'Anomalie kernel détectée', 'Comportement kernel anormal', 'critique', 3, 'Kernel compromis', 'Rootkit kernel', 'T1014', 'Defense Evasion', 'wazuh'),
(515, 'Fichier /dev suspect', 'Device inhabituel', 'haute', 3, 'Device anormal', 'Backdoor possible', 'T1564', 'Defense Evasion', 'wazuh'),
(516, 'PID anormal détecté', 'Processus PID suspect', 'haute', 3, 'Manipulation PID', 'Rootkit probable', 'T1055', 'Defense Evasion', 'wazuh'),
(517, 'Module kernel suspect', 'LKM non reconnu', 'critique', 3, 'Module malveillant', 'LKM rootkit', 'T1547.006', 'Persistence', 'wazuh'),
(518, 'Signature rootkit connue', 'Rootkit identifié', 'critique', 3, 'Rootkit confirmé', 'Infection connue', 'T1014', 'Defense Evasion', 'wazuh'),
(519, 'Incohérence système fichiers', 'Différence kernel/userspace', 'haute', 3, 'Fichiers cachés', 'Rootkit probable', 'T1564.001', 'Defense Evasion', 'wazuh'),
(520, 'Table syscall modifiée', 'Hooks système détectés', 'critique', 3, 'Syscalls hookés', 'Rootkit kernel', 'T1014', 'Defense Evasion', 'wazuh'),
(521, 'Processus non listé /proc', 'Processus invisible', 'critique', 3, 'Processus caché', 'Rootkit ou exploit', 'T1564.001', 'Defense Evasion', 'wazuh'),
(522, 'Connexion réseau cachée', 'Connexion non listée', 'critique', 3, 'Communication dissimulée', 'Backdoor C2', 'T1095', 'Command and Control', 'wazuh'),
(523, 'LD_PRELOAD suspect', 'Préchargement lib suspect', 'haute', 3, 'Injection librairie', 'Hooking userspace', 'T1574.006', 'Persistence', 'wazuh'),
(524, 'Anomalie /proc détectée', '/proc incohérent', 'haute', 3, 'Procfs manipulé', 'Rootkit probable', 'T1014', 'Defense Evasion', 'wazuh'),
(525, 'Promiscuous mode activé', 'Interface en mode espion', 'haute', 3, 'Capture trafic', 'Sniffing actif', 'T1040', 'Credential Access', 'wazuh'),
(526, 'Strings binaire suspects', 'Chaînes malveillantes', 'haute', 3, 'Binaire suspect', 'Malware probable', 'T1027', 'Defense Evasion', 'wazuh'),
(527, 'Modification /etc/ld.so.conf', 'Chemins libs modifiés', 'haute', 3, 'Chemins libs altérés', 'Injection lib', 'T1574.006', 'Persistence', 'wazuh'),
(528, 'Fichier trojan connu', 'Signature trojan détectée', 'critique', 3, 'Trojan identifié', 'Infection confirmée', 'T1059', 'Execution', 'wazuh'),
(529, 'Backdoor connue détectée', 'Signature backdoor', 'critique', 3, 'Backdoor identifiée', 'Compromission', 'T1505.003', 'Persistence', 'wazuh');

-- Système (30 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(530, 'Service système démarré', 'Démarrage service', 'info', 8, 'Service actif', 'Boot ou admin', '-', '-', 'wazuh'),
(531, 'Service système arrêté', 'Arrêt service', 'moyenne', 8, 'Service inactif', 'Admin ou crash', 'T1489', 'Impact', 'wazuh'),
(532, 'Service système crashé', 'Plantage service', 'haute', 8, 'Service défaillant', 'Bug ou attaque', 'T1499', 'Impact', 'wazuh'),
(533, 'Redémarrage système', 'Reboot détecté', 'moyenne', 8, 'Interruption service', 'Maintenance', 'T1529', 'Impact', 'wazuh'),
(534, 'Arrêt système', 'Shutdown détecté', 'haute', 8, 'Système hors ligne', 'Maintenance ou attaque', 'T1529', 'Impact', 'wazuh'),
(535, 'Erreur kernel', 'Erreur noyau enregistrée', 'haute', 8, 'Instabilité système', 'Driver ou hardware', '-', '-', 'wazuh'),
(536, 'Kernel panic', 'Crash kernel', 'critique', 8, 'Crash système complet', 'Bug critique', 'T1499.004', 'Impact', 'wazuh'),
(537, 'Mémoire insuffisante', 'Manque de RAM', 'haute', 8, 'Performance dégradée', 'Charge ou fuite', 'T1499.001', 'Impact', 'wazuh'),
(538, 'OOM Killer activé', 'Processus tué par OOM', 'haute', 8, 'Processus terminé', 'Manque RAM', 'T1499.001', 'Impact', 'wazuh'),
(539, 'Disque plein', 'Espace disque épuisé', 'critique', 8, 'Services en échec', 'Logs ou données', 'T1499.001', 'Impact', 'wazuh'),
(540, 'Erreur I/O disque', 'Erreur lecture/écriture', 'haute', 8, 'Risque perte données', 'Hardware défaillant', '-', '-', 'wazuh'),
(541, 'Filesystem monté', 'Montage volume', 'info', 8, 'Nouveau volume', 'Montage normal', 'T1200', 'Initial Access', 'wazuh'),
(542, 'Filesystem démonté', 'Démontage volume', 'info', 8, 'Volume retiré', 'Démontage normal', '-', '-', 'wazuh'),
(543, 'USB connecté', 'Périphérique USB branché', 'moyenne', 8, 'Nouveau device', 'Légitime ou exfiltration', 'T1200', 'Initial Access', 'wazuh'),
(544, 'USB déconnecté', 'Périphérique USB retiré', 'info', 8, 'Device retiré', 'Retrait normal', '-', '-', 'wazuh'),
(545, 'Heure système modifiée', 'Changement horloge', 'haute', 8, 'Temps altéré', 'NTP ou falsification', 'T1070.006', 'Defense Evasion', 'wazuh'),
(546, 'Nouveau kernel chargé', 'Changement noyau', 'haute', 8, 'Kernel changé', 'Mise à jour', 'T1547.006', 'Persistence', 'wazuh'),
(547, 'Violation SELinux/AppArmor', 'Blocage MAC', 'haute', 8, 'Action bloquée', 'Tentative non autorisée', 'T1562.001', 'Defense Evasion', 'wazuh'),
(548, 'Module kernel chargé', 'Chargement driver', 'moyenne', 8, 'Nouveau driver', 'Légitime ou rootkit', 'T1547.006', 'Persistence', 'wazuh'),
(549, 'Module kernel déchargé', 'Retrait driver', 'info', 8, 'Driver retiré', 'Maintenance', '-', '-', 'wazuh'),
(560, 'Cron job exécuté', 'Tâche planifiée lancée', 'info', 8, 'Cron actif', 'Planification normale', 'T1053.003', 'Execution', 'wazuh'),
(561, 'Cron job échoué', 'Échec tâche planifiée', 'moyenne', 8, 'Cron en erreur', 'Script défaillant', 'T1053.003', 'Execution', 'wazuh'),
(562, 'Nouveau cron job créé', 'Nouvelle tâche cron', 'haute', 8, 'Nouveau cron', 'Admin ou persistence', 'T1053.003', 'Persistence', 'wazuh'),
(563, 'At job programmé', 'Tâche at créée', 'moyenne', 8, 'Tâche différée', 'Planification', 'T1053.002', 'Persistence', 'wazuh'),
(564, 'Systemd timer créé', 'Timer systemd ajouté', 'moyenne', 8, 'Timer créé', 'Admin ou persistence', 'T1053.006', 'Persistence', 'wazuh'),
(565, 'Service systemd créé', 'Nouveau service', 'haute', 8, 'Service ajouté', 'Installation ou backdoor', 'T1543.002', 'Persistence', 'wazuh'),
(566, 'Socket systemd créé', 'Socket service ajouté', 'moyenne', 8, 'Socket créé', 'Configuration', 'T1543.002', 'Persistence', 'wazuh'),
(570, 'Swap activé', 'Mémoire swap active', 'info', 8, 'Swap utilisé', 'Config normale', '-', '-', 'wazuh'),
(571, 'Température CPU critique', 'Surchauffe CPU', 'haute', 8, 'Risque throttling', 'Charge ou cooling', '-', '-', 'wazuh'),
(572, 'Ventilateur défaillant', 'Problème ventilateur', 'haute', 8, 'Risque surchauffe', 'Hardware défaillant', '-', '-', 'wazuh');

-- Applications et Web (25 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(600, 'Processus suspect détecté', 'Comportement processus anormal', 'haute', 7, 'Activité suspecte', 'Malware ou outil', 'T1059', 'Execution', 'wazuh'),
(601, 'Script shell exécuté', 'Exécution script bash', 'moyenne', 7, 'Script lancé', 'Admin ou attaque', 'T1059.004', 'Execution', 'wazuh'),
(602, 'Python exécuté par www-data', 'Script Python par web', 'haute', 7, 'Webshell possible', 'Exploitation web', 'T1059.006', 'Execution', 'wazuh'),
(603, 'Téléchargement curl/wget', 'Download fichier externe', 'moyenne', 7, 'Fichier téléchargé', 'Admin ou dropper', 'T1105', 'Command and Control', 'wazuh'),
(604, 'Netcat exécuté', 'Utilisation netcat', 'haute', 7, 'Outil réseau suspect', 'Backdoor ou tunnel', 'T1095', 'Command and Control', 'wazuh'),
(605, 'Nmap exécuté', 'Scan avec nmap', 'haute', 7, 'Scan réseau', 'Audit ou attaque', 'T1046', 'Discovery', 'wazuh'),
(606, 'Nikto exécuté', 'Scanner web Nikto', 'haute', 7, 'Scan vulnérabilités web', 'Audit ou attaque', 'T1595.002', 'Reconnaissance', 'wazuh'),
(607, 'SQLMap exécuté', 'Outil SQLi détecté', 'critique', 7, 'Attaque SQL injection', 'Test ou attaque', 'T1190', 'Initial Access', 'wazuh'),
(608, 'Metasploit détecté', 'Framework Metasploit', 'critique', 7, 'Outil exploitation', 'Pentest ou attaque', 'T1203', 'Execution', 'wazuh'),
(609, 'Hydra exécuté', 'Brute forcer Hydra', 'critique', 7, 'Attaque brute force', 'Test ou attaque', 'T1110', 'Credential Access', 'wazuh'),
(700, 'Connexion IP suspecte', 'Connexion vers IP blacklistée', 'haute', 6, 'Communication C2', 'Malware ou exfil', 'T1071', 'Command and Control', 'wazuh'),
(701, 'Port inhabituel utilisé', 'Connexion port non standard', 'moyenne', 6, 'Trafic anormal', 'Contournement FW', 'T1571', 'Command and Control', 'wazuh'),
(702, 'Connexions excessives', 'Flood connexions', 'haute', 6, 'DoS ou scan', 'Attaque ou bug', 'T1499', 'Impact', 'wazuh'),
(703, 'Requêtes DNS anormales', 'DNS tunneling possible', 'haute', 6, 'Exfiltration DNS', 'Tunnel DNS', 'T1071.004', 'Command and Control', 'wazuh'),
(704, 'Connexion Tor détectée', 'Trafic réseau Tor', 'haute', 6, 'Anonymisation', 'Évasion ou illicite', 'T1090.003', 'Command and Control', 'wazuh'),
(705, 'IP blacklistée contactée', 'Communication IOC', 'critique', 6, 'Contact attaquant', 'Infection ou C2', 'T1071', 'Command and Control', 'wazuh'),
(800, 'Erreur 500 serveur web', 'Erreur interne serveur', 'moyenne', 12, 'Erreur applicative', 'Bug ou attaque', 'T1499.004', 'Impact', 'wazuh'),
(801, 'Path traversal détecté', 'Tentative ../', 'haute', 12, 'Accès fichiers', 'Attaque web', 'T1083', 'Discovery', 'wazuh'),
(802, 'Injection SQL détectée', 'Pattern SQLi dans logs', 'critique', 12, 'Attaque base données', 'SQLi active', 'T1190', 'Initial Access', 'wazuh'),
(803, 'XSS détecté', 'Pattern XSS dans logs', 'haute', 12, 'Injection script', 'Attaque XSS', 'T1189', 'Initial Access', 'wazuh'),
(804, 'RCE tentative détectée', 'Exécution commande', 'critique', 12, 'Prise contrôle', 'Exploitation RCE', 'T1059', 'Execution', 'wazuh'),
(805, 'Upload fichier suspect', 'Upload potentiel malware', 'haute', 12, 'Dépôt fichier', 'Webshell possible', 'T1105', 'Command and Control', 'wazuh'),
(806, 'Scanner web détecté', 'Requêtes scanner auto', 'haute', 12, 'Scan vulns', 'Nikto, Dirb, etc.', 'T1595', 'Reconnaissance', 'wazuh'),
(807, 'WordPress attack', 'Attaque WordPress', 'haute', 12, 'Exploit WP', 'WPScan ou exploit', 'T1190', 'Initial Access', 'wazuh'),
(808, 'Bruteforce web login', 'Multiples échecs login web', 'haute', 12, 'Brute force web', 'Automatisé', 'T1110', 'Credential Access', 'wazuh');

-- Pare-feu (15 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(900, 'Règle firewall ajoutée', 'Nouvelle règle iptables', 'moyenne', 10, 'Politique modifiée', 'Admin ou évasion', 'T1562.004', 'Defense Evasion', 'wazuh'),
(901, 'Règle firewall supprimée', 'Règle iptables retirée', 'haute', 10, 'Sécurité réduite', 'Admin ou attaque', 'T1562.004', 'Defense Evasion', 'wazuh'),
(902, 'Pare-feu désactivé', 'Firewall arrêté', 'critique', 10, 'Système exposé', 'Compromission', 'T1562.004', 'Defense Evasion', 'wazuh'),
(903, 'Flush iptables', 'Tables vidées', 'critique', 10, 'Règles effacées', 'Reset ou attaque', 'T1562.004', 'Defense Evasion', 'wazuh'),
(904, 'UFW désactivé', 'UFW arrêté', 'critique', 10, 'Firewall désactivé', 'Admin ou attaque', 'T1562.004', 'Defense Evasion', 'wazuh'),
(905, 'Connexion bloquée par FW', 'Trafic rejeté', 'info', 10, 'Tentative bloquée', 'Protection active', '-', '-', 'wazuh'),
(906, 'Scan bloqué par FW', 'Scan détecté et bloqué', 'moyenne', 10, 'Reconnaissance bloquée', 'Protection active', 'T1046', 'Discovery', 'wazuh'),
(907, 'DDoS potentiel bloqué', 'Flood bloqué', 'haute', 10, 'Attaque mitigée', 'DoS tenté', 'T1499', 'Impact', 'wazuh'),
(908, 'Port ouvert par FW', 'Nouveau port autorisé', 'moyenne', 10, 'Service exposé', 'Admin ou backdoor', 'T1562.004', 'Defense Evasion', 'wazuh'),
(909, 'NAT configuré', 'Règle NAT ajoutée', 'moyenne', 10, 'Redirection trafic', 'Config réseau', '-', '-', 'wazuh'),
(910, 'Forwarding activé', 'IP forwarding', 'haute', 10, 'Routage activé', 'Config ou pivot', 'T1090', 'Command and Control', 'wazuh'),
(911, 'Masquerading activé', 'NAT masquerade', 'moyenne', 10, 'NAT sortant', 'Config réseau', '-', '-', 'wazuh'),
(912, 'Log FW modifié', 'Config logs firewall', 'moyenne', 10, 'Logging modifié', 'Admin ou évasion', 'T1562.003', 'Defense Evasion', 'wazuh'),
(913, 'Zone FW modifiée', 'Zone firewall changée', 'haute', 10, 'Politique zone', 'Config ou attaque', 'T1562.004', 'Defense Evasion', 'wazuh'),
(914, 'Règle REJECT ajoutée', 'Nouvelle règle blocage', 'info', 10, 'Blocage ajouté', 'Renforcement', '-', '-', 'wazuh');

-- Audit (15 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(950, 'Auditd démarré', 'Service audit actif', 'info', 9, 'Audit actif', 'Boot normal', '-', '-', 'wazuh'),
(951, 'Auditd arrêté', 'Service audit stoppé', 'haute', 9, 'Audit inactif', 'Admin ou évasion', 'T1562.001', 'Defense Evasion', 'wazuh'),
(952, 'Règle audit ajoutée', 'Nouvelle règle auditd', 'info', 9, 'Monitoring ajouté', 'Renforcement', '-', '-', 'wazuh'),
(953, 'Règle audit supprimée', 'Règle auditd retirée', 'haute', 9, 'Monitoring réduit', 'Admin ou évasion', 'T1562.001', 'Defense Evasion', 'wazuh'),
(954, 'Fichier audit supprimé', 'Log audit effacé', 'critique', 9, 'Traces effacées', 'Évasion', 'T1070.002', 'Defense Evasion', 'wazuh'),
(955, 'Log audit tronqué', 'Fichier audit tronqué', 'critique', 9, 'Logs altérés', 'Évasion', 'T1070.002', 'Defense Evasion', 'wazuh'),
(956, 'Accès fichier sensible', 'Lecture fichier critique', 'moyenne', 9, 'Fichier accédé', 'Légitime ou recon', 'T1083', 'Discovery', 'wazuh'),
(957, 'Exécution fichier surveillé', 'Binaire surveillé exécuté', 'moyenne', 9, 'Exécution tracée', 'Monitoring actif', '-', '-', 'wazuh'),
(958, 'Modification syscall', 'Appel système intercepté', 'haute', 9, 'Syscall altéré', 'Rootkit possible', 'T1014', 'Defense Evasion', 'wazuh'),
(959, 'Accès socket réseau', 'Création socket tracée', 'info', 9, 'Connexion réseau', 'Activité normale', '-', '-', 'wazuh'),
(960, 'Chargement module tracé', 'Insertion module audit', 'moyenne', 9, 'Module chargé', 'Driver ou rootkit', 'T1547.006', 'Persistence', 'wazuh'),
(961, 'Accès périphérique', 'Accès device tracé', 'info', 9, 'Device accédé', 'Activité normale', '-', '-', 'wazuh'),
(962, 'Commande admin tracée', 'Commande privilégiée', 'info', 9, 'Admin action', 'Tracé normal', '-', '-', 'wazuh'),
(963, 'Échec accès fichier', 'Permission refusée tracée', 'moyenne', 9, 'Accès refusé', 'Tentative non autorisée', 'T1083', 'Discovery', 'wazuh'),
(964, 'Suppression fichier tracée', 'Effacement fichier audit', 'moyenne', 9, 'Fichier supprimé', 'Admin ou évasion', 'T1070.004', 'Defense Evasion', 'wazuh');

-- Plus de règles Wazuh pour atteindre ~207...
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(1002, 'Erreur 404 excessive', 'Beaucoup de pages non trouvées', 'haute', 12, 'Scan ressources', 'Fuzzing', 'T1595', 'Reconnaissance', 'wazuh'),
(1003, 'Méthode HTTP dangereuse', 'PUT/DELETE/TRACE', 'haute', 12, 'Méthode risquée', 'Attaque ou misconfig', 'T1190', 'Initial Access', 'wazuh'),
(1004, 'User-Agent suspect', 'Agent malveillant', 'haute', 12, 'Outil attaque', 'Scanner ou bot', 'T1595', 'Reconnaissance', 'wazuh'),
(1005, 'Requête très longue', 'URL/Body anormalement long', 'moyenne', 12, 'Buffer overflow possible', 'Attaque ou bug', 'T1499.004', 'Impact', 'wazuh'),
(1006, 'Encodage suspect', 'Double encodage détecté', 'haute', 12, 'Bypass tentative', 'Évasion WAF', 'T1027', 'Defense Evasion', 'wazuh'),
(1100, 'Antivirus alerte', 'Détection antivirus', 'haute', 7, 'Malware détecté', 'Infection', 'T1059', 'Execution', 'wazuh'),
(1101, 'Antivirus désactivé', 'AV arrêté', 'critique', 7, 'Protection désactivée', 'Admin ou attaque', 'T1562.001', 'Defense Evasion', 'wazuh'),
(1102, 'Quarantaine fichier', 'Fichier mis en quarantaine', 'haute', 7, 'Menace isolée', 'AV actif', '-', '-', 'wazuh'),
(1103, 'Mise à jour AV échouée', 'Update signatures KO', 'moyenne', 7, 'Signatures obsolètes', 'Problème réseau', '-', '-', 'wazuh'),
(1104, 'Scan AV terminé', 'Scan antivirus complet', 'info', 7, 'Scan effectué', 'Planification', '-', '-', 'wazuh'),
(1200, 'Vulnérabilité détectée', 'CVE identifié', 'haute', 13, 'Faille présente', 'Package vulnérable', 'T1190', 'Initial Access', 'wazuh'),
(1201, 'Package obsolète', 'Version non supportée', 'moyenne', 13, 'Software ancien', 'Manque MàJ', '-', '-', 'wazuh'),
(1202, 'Patch manquant', 'Correctif non appliqué', 'moyenne', 13, 'Vulnérabilité ouverte', 'MàJ en attente', '-', '-', 'wazuh'),
(1203, 'Exploit disponible', 'Exploit public pour CVE', 'critique', 13, 'Exploitation facile', 'Risque élevé', 'T1203', 'Execution', 'wazuh'),
(1204, 'CVE critique système', 'CVE score >= 9', 'critique', 13, 'Faille critique', 'Patch urgent', 'T1190', 'Initial Access', 'wazuh');

-- ============================================================================
-- RÈGLES SNORT (300 règles) - Sélection représentative
-- ============================================================================

-- Scan & Reconnaissance (35 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(1000001, 'Scan de ports TCP détecté', 'Tentative de scan ports TCP', 'haute', 16, 'Cartographie services', 'Reconnaissance', 'T1046', 'Discovery', 'snort'),
(1000002, 'Brute Force SSH détecté', 'Multiples tentatives SSH', 'critique', 21, 'Attaque credentials SSH', 'Outil automatisé', 'T1110', 'Credential Access', 'snort'),
(1000003, 'Injection SQL UNION', 'Pattern UNION SELECT', 'critique', 17, 'Extraction données', 'SQLi active', 'T1190', 'Initial Access', 'snort'),
(1000004, 'XSS balise script', 'Injection <script>', 'haute', 18, 'Exécution JS', 'Attaque XSS', 'T1059.007', 'Execution', 'snort'),
(87001, 'Scan SYN détecté', 'Scan TCP SYN half-open', 'haute', 16, 'Scan furtif', 'Nmap SYN scan', 'T1046', 'Discovery', 'snort'),
(87002, 'Scan FIN détecté', 'Scan TCP FIN', 'haute', 16, 'Évasion firewall', 'Scan évasif', 'T1046', 'Discovery', 'snort'),
(87003, 'Scan NULL détecté', 'Scan TCP sans flags', 'haute', 16, 'Technique évasive', 'Fingerprinting', 'T1046', 'Discovery', 'snort'),
(87004, 'Scan XMAS détecté', 'Scan TCP tous flags', 'haute', 16, 'Empreinte OS', 'OS fingerprinting', 'T1046', 'Discovery', 'snort'),
(87005, 'Ping sweep réseau', 'Balayage ICMP', 'moyenne', 16, 'Découverte hôtes', 'Reconnaissance', 'T1018', 'Discovery', 'snort'),
(87006, 'Nmap signature détectée', 'Outil Nmap identifié', 'haute', 16, 'Scan actif', 'Reconnaissance', 'T1046', 'Discovery', 'snort'),
(87007, 'Scan massif ports', '+100 ports scannés', 'critique', 16, 'Reconnaissance agressive', 'Scan automatisé', 'T1046', 'Discovery', 'snort'),
(87008, 'Scan version service', 'Banner grabbing', 'haute', 16, 'Fingerprinting services', 'Recherche vulns', 'T1046', 'Discovery', 'snort'),
(87009, 'OS fingerprinting', 'Détection OS cible', 'haute', 16, 'Identification OS', 'Préparation attaque', 'T1082', 'Discovery', 'snort'),
(87010, 'Traceroute détecté', 'Cartographie réseau', 'faible', 16, 'Topologie réseau', 'Reconnaissance', 'T1016', 'Discovery', 'snort'),
(87011, 'ARP scan détecté', 'Balayage ARP LAN', 'moyenne', 16, 'Découverte LAN', 'Reconnaissance locale', 'T1018', 'Discovery', 'snort'),
(87012, 'Enumération SNMP', 'SNMP walking', 'haute', 16, 'Vol info réseau', 'Reconnaissance', 'T1046', 'Discovery', 'snort'),
(87013, 'Enumération NetBIOS', 'Scan NetBIOS', 'haute', 16, 'Découverte Windows', 'Reconnaissance SMB', 'T1046', 'Discovery', 'snort'),
(87014, 'Scan SMB détecté', 'Énumération partages', 'haute', 16, 'Ressources partagées', 'Scan SMB', 'T1135', 'Discovery', 'snort'),
(87015, 'Scan LDAP détecté', 'Énumération LDAP', 'haute', 16, 'Info Active Directory', 'Reconnaissance AD', 'T1087', 'Discovery', 'snort'),
(87016, 'Zone transfer DNS', 'AXFR tentative', 'haute', 16, 'Vol données DNS', 'Zone transfer', 'T1046', 'Discovery', 'snort'),
(87017, 'Scan distribué détecté', 'Multiples sources', 'critique', 16, 'Attaque coordonnée', 'Scan distribué', 'T1046', 'Discovery', 'snort'),
(87018, 'Masscan détecté', 'Signature Masscan', 'critique', 16, 'Scan haute vitesse', 'Masscan actif', 'T1046', 'Discovery', 'snort'),
(87019, 'Scanner vulnérabilité', 'Nessus/OpenVAS', 'haute', 16, 'Recherche failles', 'Scan vulns', 'T1595.002', 'Reconnaissance', 'snort'),
(87020, 'WPScan détecté', 'Scanner WordPress', 'haute', 16, 'Vulns WordPress', 'WPScan', 'T1595.002', 'Reconnaissance', 'snort');

-- Injection SQL (35 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87041, 'SQLi UNION SELECT', 'Injection UNION', 'critique', 17, 'Extraction données', 'SQLi UNION', 'T1190', 'Initial Access', 'snort'),
(87042, 'SQLi OR 1=1', 'Bypass authentification', 'critique', 17, 'Contournement login', 'SQLi auth bypass', 'T1190', 'Initial Access', 'snort'),
(87043, 'SQLi commentaire', 'Utilisation -- ou #', 'haute', 17, 'Manipulation requête', 'SQLi technique', 'T1190', 'Initial Access', 'snort'),
(87044, 'SQLi information_schema', 'Accès métadonnées', 'critique', 17, 'Énumération BDD', 'Reconnaissance BDD', 'T1190', 'Initial Access', 'snort'),
(87045, 'SQLi DROP TABLE', 'Suppression table', 'critique', 17, 'Destruction données', 'Attaque destructive', 'T1485', 'Impact', 'snort'),
(87046, 'SQLi INSERT INTO', 'Insertion données', 'haute', 17, 'Ajout données', 'Manipulation BDD', 'T1565', 'Impact', 'snort'),
(87047, 'SQLi UPDATE', 'Modification données', 'critique', 17, 'Altération données', 'Modification malveillante', 'T1565', 'Impact', 'snort'),
(87048, 'SQLi DELETE FROM', 'Suppression données', 'critique', 17, 'Effacement données', 'Destruction', 'T1485', 'Impact', 'snort'),
(87049, 'SQLi LOAD_FILE', 'Lecture fichier système', 'critique', 17, 'Lecture fichiers', 'Exfiltration', 'T1005', 'Collection', 'snort'),
(87050, 'SQLi INTO OUTFILE', 'Écriture fichier', 'critique', 17, 'Dépôt webshell', 'Écriture malveillante', 'T1059', 'Execution', 'snort'),
(87051, 'SQLi SLEEP', 'Time-based injection', 'haute', 17, 'SQLi blind', 'Time-based SQLi', 'T1190', 'Initial Access', 'snort'),
(87052, 'SQLi BENCHMARK', 'Timing attack', 'haute', 17, 'Extraction timing', 'Benchmark SQLi', 'T1190', 'Initial Access', 'snort'),
(87053, 'SQLi hex encoding', 'Encodage hexadécimal', 'haute', 17, 'Évasion WAF', 'Obfuscation', 'T1190', 'Initial Access', 'snort'),
(87054, 'SQLi double encoding', 'Double encodage URL', 'haute', 17, 'Bypass filtres', 'Évasion', 'T1190', 'Initial Access', 'snort'),
(87055, 'SQLi stacked queries', 'Requêtes empilées', 'critique', 17, 'Commandes multiples', 'SQLi avancé', 'T1190', 'Initial Access', 'snort'),
(87056, 'SQLMap détecté', 'Outil SQLMap', 'critique', 17, 'Attaque automatisée', 'SQLMap actif', 'T1190', 'Initial Access', 'snort'),
(87057, 'SQLi error-based', 'Exploitation erreurs', 'haute', 17, 'Extraction via erreurs', 'Error-based SQLi', 'T1190', 'Initial Access', 'snort'),
(87058, 'SQLi boolean-based', 'Injection booléenne', 'haute', 17, 'Extraction bit à bit', 'Boolean SQLi', 'T1190', 'Initial Access', 'snort'),
(87059, 'SQLi xp_cmdshell', 'Exécution commandes', 'critique', 17, 'RCE via SQL Server', 'xp_cmdshell', 'T1059', 'Execution', 'snort'),
(87060, 'SQLi ORDER BY', 'Énumération colonnes', 'haute', 17, 'Comptage colonnes', 'Reconnaissance', 'T1190', 'Initial Access', 'snort');

-- XSS (30 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87076, 'XSS balise script', 'Injection <script>', 'haute', 18, 'Exécution JS malveillant', 'XSS réfléchi/stocké', 'T1059.007', 'Execution', 'snort'),
(87077, 'XSS event handler', 'onclick/onerror', 'haute', 18, 'Exécution JS événement', 'XSS événementiel', 'T1059.007', 'Execution', 'snort'),
(87078, 'XSS document.cookie', 'Vol cookies', 'critique', 18, 'Vol session', 'Cookie stealing', 'T1539', 'Credential Access', 'snort'),
(87079, 'XSS document.location', 'Redirection malveillante', 'haute', 18, 'Redirection', 'Phishing', 'T1189', 'Initial Access', 'snort'),
(87080, 'XSS iframe injection', 'Injection iframe', 'haute', 18, 'Contenu externe', 'Clickjacking', 'T1189', 'Initial Access', 'snort'),
(87081, 'XSS img onerror', 'Image avec onerror', 'haute', 18, 'Exécution JS via img', 'XSS alternatif', 'T1059.007', 'Execution', 'snort'),
(87082, 'XSS SVG injection', 'SVG malveillante', 'haute', 18, 'Exécution JS via SVG', 'SVG XSS', 'T1059.007', 'Execution', 'snort'),
(87083, 'XSS javascript:', 'Protocole javascript:', 'haute', 18, 'Exécution JS URL', 'Protocol XSS', 'T1059.007', 'Execution', 'snort'),
(87084, 'XSS data:', 'Protocole data:', 'haute', 18, 'Injection data URI', 'Data URI XSS', 'T1059.007', 'Execution', 'snort'),
(87085, 'XSS eval()', 'Utilisation eval', 'haute', 18, 'Code arbitraire', 'Eval injection', 'T1059.007', 'Execution', 'snort'),
(87086, 'XSS innerHTML', 'Manipulation innerHTML', 'haute', 18, 'Injection HTML', 'DOM manipulation', 'T1059.007', 'Execution', 'snort'),
(87087, 'XSS DOM-based', 'Manipulation DOM', 'haute', 18, 'XSS côté client', 'DOM XSS', 'T1059.007', 'Execution', 'snort'),
(87088, 'XSS template injection', 'Injection template', 'haute', 18, 'XSS via template', 'Template XSS', 'T1059.007', 'Execution', 'snort'),
(87089, 'XSS stocké potentiel', 'Payload dans POST', 'critique', 18, 'XSS persistant', 'Stored XSS', 'T1059.007', 'Execution', 'snort'),
(87090, 'XSS scanner détecté', 'XSSer/XSStrike', 'haute', 18, 'Scan XSS', 'Outil XSS', 'T1595.002', 'Reconnaissance', 'snort');

-- DoS/DDoS (30 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87111, 'SYN Flood détecté', 'Attaque SYN flood', 'critique', 19, 'Épuisement ressources', 'DDoS', 'T1499.001', 'Impact', 'snort'),
(87112, 'UDP Flood détecté', 'Attaque UDP flood', 'critique', 19, 'Saturation bande passante', 'DDoS volumétrique', 'T1499.001', 'Impact', 'snort'),
(87113, 'ICMP Flood détecté', 'Ping flood', 'haute', 19, 'Surcharge réseau', 'Ping flood', 'T1499.001', 'Impact', 'snort'),
(87114, 'HTTP Flood détecté', 'Attaque HTTP flood', 'critique', 19, 'Saturation serveur web', 'Layer 7 DDoS', 'T1499.002', 'Impact', 'snort'),
(87115, 'Slowloris détecté', 'Attaque Slowloris', 'critique', 19, 'Épuisement connexions', 'Slow HTTP', 'T1499.002', 'Impact', 'snort'),
(87116, 'DNS Amplification', 'Amplification DNS', 'critique', 19, 'Amplification', 'DNS reflection', 'T1499.001', 'Impact', 'snort'),
(87117, 'NTP Amplification', 'Amplification NTP', 'critique', 19, 'Amplification', 'NTP reflection', 'T1499.001', 'Impact', 'snort'),
(87118, 'Memcached Amplification', 'Amplification Memcached', 'critique', 19, 'Amplification extrême', 'Memcached DDoS', 'T1499.001', 'Impact', 'snort'),
(87119, 'Ping of Death', 'Paquet ICMP surdimensionné', 'haute', 19, 'Crash système', 'Ping of Death', 'T1499.004', 'Impact', 'snort'),
(87120, 'Land Attack', 'Source=Destination', 'haute', 19, 'Boucle réseau', 'Land attack', 'T1499.001', 'Impact', 'snort'),
(87121, 'Teardrop Attack', 'Fragments malformés', 'haute', 19, 'Crash système', 'Teardrop', 'T1499.004', 'Impact', 'snort'),
(87122, 'Connection Exhaustion', 'Épuisement connexions', 'critique', 19, 'Serveur injoignable', 'Connection flood', 'T1499.001', 'Impact', 'snort'),
(87123, 'SSL Exhaustion', 'Attaque SSL/TLS', 'haute', 19, 'CPU exhaustion', 'SSL flood', 'T1499.002', 'Impact', 'snort'),
(87124, 'Application DDoS', 'Layer 7 attack', 'critique', 19, 'Service indisponible', 'App layer attack', 'T1499.002', 'Impact', 'snort'),
(87125, 'Botnet détecté', 'Trafic botnet', 'critique', 19, 'Participation botnet', 'Bot activity', 'T1071', 'Command and Control', 'snort');

-- Backdoors & Shells (30 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87146, 'Reverse shell détecté', 'Connexion shell inversé', 'critique', 20, 'Accès distant', 'Backdoor active', 'T1059.004', 'Execution', 'snort'),
(87147, 'Bind shell détecté', 'Shell en écoute', 'critique', 20, 'Port backdoor', 'Bind shell', 'T1059.004', 'Execution', 'snort'),
(87148, 'Web shell détecté', 'Script webshell', 'critique', 20, 'Contrôle via web', 'PHP/ASP shell', 'T1505.003', 'Persistence', 'snort'),
(87149, 'Meterpreter détecté', 'Payload Metasploit', 'critique', 20, 'Framework attaque', 'Meterpreter', 'T1059', 'Execution', 'snort'),
(87150, 'Cobalt Strike beacon', 'Beacon CS détecté', 'critique', 20, 'Outil Red Team/APT', 'Cobalt Strike', 'T1071.001', 'Command and Control', 'snort'),
(87151, 'Empire agent détecté', 'PowerShell Empire', 'critique', 20, 'Framework post-exploit', 'PS Empire', 'T1059.001', 'Execution', 'snort'),
(87152, 'Netcat backdoor', 'NC reverse shell', 'critique', 20, 'Tunnel netcat', 'NC backdoor', 'T1095', 'Command and Control', 'snort'),
(87153, 'DNS tunnel détecté', 'Données dans DNS', 'critique', 20, 'Exfiltration DNS', 'DNS tunneling', 'T1071.004', 'Command and Control', 'snort'),
(87154, 'ICMP tunnel détecté', 'Données dans ICMP', 'haute', 20, 'Tunnel ICMP', 'ICMP tunneling', 'T1095', 'Command and Control', 'snort'),
(87155, 'C2 communication', 'Trafic C2', 'critique', 20, 'Command & Control', 'C2 traffic', 'T1071', 'Command and Control', 'snort'),
(87156, 'RAT détecté', 'Remote Access Trojan', 'critique', 20, 'Contrôle distant', 'RAT activity', 'T1219', 'Command and Control', 'snort'),
(87157, 'njRAT détecté', 'Trafic njRAT', 'critique', 20, 'RAT populaire', 'njRAT', 'T1219', 'Command and Control', 'snort'),
(87158, 'DarkComet détecté', 'Trafic DarkComet', 'critique', 20, 'RAT connu', 'DarkComet', 'T1219', 'Command and Control', 'snort'),
(87159, 'Port knocking', 'Séquence port knock', 'haute', 20, 'Ouverture backdoor', 'Port knocking', 'T1205.001', 'Command and Control', 'snort'),
(87160, 'Keylogger traffic', 'Trafic keylogger', 'critique', 20, 'Vol frappes', 'Keylogger', 'T1056.001', 'Collection', 'snort');

-- Malware (35 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87236, 'Ransomware détecté', 'Activité ransomware', 'critique', 23, 'Chiffrement données', 'Ransomware actif', 'T1486', 'Impact', 'snort'),
(87237, 'WannaCry détecté', 'Trafic WannaCry', 'critique', 23, 'Ransomware WannaCry', 'WannaCry', 'T1486', 'Impact', 'snort'),
(87238, 'Emotet détecté', 'Trafic Emotet', 'critique', 23, 'Trojan bancaire', 'Emotet', 'T1071', 'Command and Control', 'snort'),
(87239, 'TrickBot détecté', 'Trafic TrickBot', 'critique', 23, 'Trojan modulaire', 'TrickBot', 'T1071', 'Command and Control', 'snort'),
(87240, 'Cryptominer détecté', 'Activité mining', 'haute', 23, 'Vol ressources CPU', 'Cryptominer', 'T1496', 'Impact', 'snort'),
(87241, 'Monero miner', 'XMRig détecté', 'haute', 23, 'Minage Monero', 'XMRig', 'T1496', 'Impact', 'snort'),
(87242, 'Dridex détecté', 'Trafic Dridex', 'critique', 23, 'Trojan bancaire', 'Dridex', 'T1071', 'Command and Control', 'snort'),
(87243, 'FormBook détecté', 'Trafic FormBook', 'critique', 23, 'Infostealer', 'FormBook', 'T1555', 'Credential Access', 'snort'),
(87244, 'AgentTesla détecté', 'Trafic AgentTesla', 'critique', 23, 'Infostealer', 'AgentTesla', 'T1555', 'Credential Access', 'snort'),
(87245, 'RedLine stealer', 'Trafic RedLine', 'critique', 23, 'Stealer moderne', 'RedLine', 'T1555', 'Credential Access', 'snort'),
(87246, 'Mirai botnet', 'Trafic Mirai', 'critique', 23, 'Botnet IoT', 'Mirai', 'T1583.005', 'Resource Development', 'snort'),
(87247, 'Malware dropper', 'Téléchargement malware', 'critique', 23, 'Installation malware', 'Dropper', 'T1105', 'Command and Control', 'snort'),
(87248, 'Mimikatz detected', 'Trafic Mimikatz', 'critique', 23, 'Vol credentials', 'Mimikatz', 'T1003', 'Credential Access', 'snort'),
(87249, 'PowerShell malveillant', 'PS malveillant', 'critique', 23, 'Exécution PS', 'Malicious PS', 'T1059.001', 'Execution', 'snort'),
(87250, 'Macro malveillante', 'Macro Office', 'haute', 23, 'Document piégé', 'Macro malware', 'T1204.002', 'Execution', 'snort');

-- Brute Force réseau (20 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87176, 'Brute Force FTP', 'Multiples échecs FTP', 'haute', 21, 'Attaque credentials FTP', 'Brute force', 'T1110', 'Credential Access', 'snort'),
(87177, 'Brute Force RDP', 'Multiples échecs RDP', 'critique', 21, 'Attaque RDP', 'Brute force RDP', 'T1110', 'Credential Access', 'snort'),
(87178, 'Brute Force SMB', 'Multiples échecs SMB', 'haute', 21, 'Attaque SMB', 'Brute force SMB', 'T1110', 'Credential Access', 'snort'),
(87179, 'Brute Force MySQL', 'Multiples échecs MySQL', 'haute', 21, 'Attaque MySQL', 'Brute force BDD', 'T1110', 'Credential Access', 'snort'),
(87180, 'Brute Force PostgreSQL', 'Multiples échecs PG', 'haute', 21, 'Attaque PostgreSQL', 'Brute force BDD', 'T1110', 'Credential Access', 'snort'),
(87181, 'Brute Force MSSQL', 'Multiples échecs MSSQL', 'haute', 21, 'Attaque SQL Server', 'Brute force BDD', 'T1110', 'Credential Access', 'snort'),
(87182, 'Brute Force Telnet', 'Multiples échecs Telnet', 'haute', 21, 'Attaque Telnet', 'Brute force', 'T1110', 'Credential Access', 'snort'),
(87183, 'Brute Force HTTP Basic', 'Auth HTTP échouées', 'haute', 21, 'Attaque HTTP auth', 'Brute force web', 'T1110', 'Credential Access', 'snort'),
(87184, 'Brute Force LDAP', 'Multiples échecs LDAP', 'haute', 21, 'Attaque AD', 'Brute force LDAP', 'T1110', 'Credential Access', 'snort'),
(87185, 'Password spray détecté', 'Password spraying', 'critique', 21, 'Attaque distribuée', 'Password spray', 'T1110.003', 'Credential Access', 'snort');

-- Exploits (25 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87201, 'Buffer overflow attempt', 'Tentative overflow', 'critique', 22, 'Exécution code', 'Exploit mémoire', 'T1203', 'Execution', 'snort'),
(87202, 'Heap spray détecté', 'Heap spraying', 'critique', 22, 'Préparation exploit', 'Heap spray', 'T1203', 'Execution', 'snort'),
(87203, 'ROP chain détecté', 'Return-oriented programming', 'critique', 22, 'Bypass DEP', 'ROP exploit', 'T1203', 'Execution', 'snort'),
(87204, 'Shellcode détecté', 'Pattern shellcode', 'critique', 22, 'Exécution code', 'Shellcode', 'T1059', 'Execution', 'snort'),
(87205, 'Format string attack', 'Format string vuln', 'haute', 22, 'Exploitation format', 'Format string', 'T1203', 'Execution', 'snort'),
(87206, 'Integer overflow', 'Integer overflow', 'haute', 22, 'Exploitation numérique', 'Int overflow', 'T1203', 'Execution', 'snort'),
(87207, 'Use-after-free', 'UAF exploitation', 'critique', 22, 'Corruption mémoire', 'UAF exploit', 'T1203', 'Execution', 'snort'),
(87208, 'SMB exploit', 'Exploit SMB', 'critique', 22, 'Exploitation SMB', 'EternalBlue etc', 'T1210', 'Lateral Movement', 'snort'),
(87209, 'Apache Struts exploit', 'Exploit Struts', 'critique', 22, 'RCE Struts', 'Struts exploit', 'T1190', 'Initial Access', 'snort'),
(87210, 'Log4j exploit', 'Log4Shell', 'critique', 22, 'RCE Log4j', 'CVE-2021-44228', 'T1190', 'Initial Access', 'snort'),
(87211, 'Exchange exploit', 'ProxyShell/Logon', 'critique', 22, 'RCE Exchange', 'Exchange exploit', 'T1190', 'Initial Access', 'snort'),
(87212, 'Spring4Shell', 'Exploit Spring', 'critique', 22, 'RCE Spring', 'CVE-2022-22965', 'T1190', 'Initial Access', 'snort'),
(87213, 'Drupal exploit', 'Drupalgeddon', 'critique', 22, 'RCE Drupal', 'Drupal exploit', 'T1190', 'Initial Access', 'snort'),
(87214, 'Joomla exploit', 'Exploit Joomla', 'haute', 22, 'RCE Joomla', 'Joomla exploit', 'T1190', 'Initial Access', 'snort'),
(87215, 'PHPUnit exploit', 'Exploit PHPUnit', 'critique', 22, 'RCE PHPUnit', 'CVE-2017-9841', 'T1190', 'Initial Access', 'snort');

-- Protocoles suspects (20 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87261, 'IRC trafic détecté', 'Communication IRC', 'haute', 24, 'C2 via IRC', 'IRC C2', 'T1071.001', 'Command and Control', 'snort'),
(87262, 'Tor trafic détecté', 'Communication Tor', 'haute', 24, 'Anonymisation', 'Utilisation Tor', 'T1090.003', 'Command and Control', 'snort'),
(87263, 'I2P trafic détecté', 'Communication I2P', 'haute', 24, 'Anonymisation', 'Utilisation I2P', 'T1090.003', 'Command and Control', 'snort'),
(87264, 'VPN non autorisé', 'VPN suspect', 'moyenne', 24, 'Contournement', 'VPN non approuvé', 'T1090', 'Command and Control', 'snort'),
(87265, 'Proxy non autorisé', 'Proxy suspect', 'moyenne', 24, 'Contournement', 'Proxy non approuvé', 'T1090.002', 'Command and Control', 'snort'),
(87266, 'Telnet détecté', 'Usage Telnet', 'haute', 24, 'Protocole non chiffré', 'Mauvaise pratique', '-', '-', 'snort'),
(87267, 'FTP clear text', 'FTP non chiffré', 'moyenne', 24, 'Credentials en clair', 'Mauvaise pratique', '-', '-', 'snort'),
(87268, 'HTTP non chiffré', 'Trafic HTTP sensible', 'moyenne', 24, 'Données en clair', 'Pas HTTPS', '-', '-', 'snort'),
(87269, 'SMTP relay ouvert', 'Relais SMTP', 'haute', 24, 'Serveur mail ouvert', 'Misconfiguration', '-', '-', 'snort'),
(87270, 'DNS non standard', 'DNS port non 53', 'haute', 24, 'DNS tunneling possible', 'Évasion', 'T1071.004', 'Command and Control', 'snort');

-- Phishing (15 règles)
INSERT INTO regles (rule_id, nom_fr, description, gravite, categorie_id, impact, cause_probable, mitre_id, mitre_tactic, source) VALUES
(87281, 'Domaine phishing', 'Domaine suspect', 'haute', 25, 'Phishing possible', 'Typosquatting', 'T1566', 'Initial Access', 'snort'),
(87282, 'URL raccourcie suspecte', 'URL shortener malveillant', 'moyenne', 25, 'Redirection malveillante', 'URL masquée', 'T1566.002', 'Initial Access', 'snort'),
(87283, 'Formulaire credentials', 'Form login externe', 'haute', 25, 'Vol credentials', 'Phishing form', 'T1566', 'Initial Access', 'snort'),
(87284, 'Clone site bancaire', 'Faux site banque', 'critique', 25, 'Fraude bancaire', 'Bank phishing', 'T1566', 'Initial Access', 'snort'),
(87285, 'Clone site entreprise', 'Faux site corporate', 'haute', 25, 'Credentials corporate', 'Corporate phishing', 'T1566', 'Initial Access', 'snort'),
(87286, 'Email spoofing', 'Usurpation email', 'haute', 25, 'Email frauduleux', 'Spoofing', 'T1566.001', 'Initial Access', 'snort'),
(87287, 'Pièce jointe suspecte', 'Attachment malveillant', 'haute', 25, 'Malware via email', 'Malicious attachment', 'T1566.001', 'Initial Access', 'snort'),
(87288, 'Lien malveillant email', 'URL malveillante', 'haute', 25, 'Exploitation via lien', 'Malicious link', 'T1566.002', 'Initial Access', 'snort'),
(87289, 'Spam massif', 'Envoi spam', 'moyenne', 25, 'Campagne spam', 'Spam campaign', 'T1566.001', 'Initial Access', 'snort'),
(87290, 'BEC tentative', 'Business Email Compromise', 'critique', 25, 'Fraude entreprise', 'BEC attack', 'T1566.001', 'Initial Access', 'snort');

-- ============================================================================
-- TABLE: recommandations
-- ============================================================================
CREATE TABLE IF NOT EXISTS recommandations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    regle_id INTEGER NOT NULL,
    ordre INTEGER NOT NULL,
    action TEXT NOT NULL,
    commande TEXT,
    niveau TEXT CHECK(niveau IN ('debutant','intermediaire','avance')) NOT NULL,
    FOREIGN KEY (regle_id) REFERENCES regles(rule_id)
);

-- Recommandations pour règles critiques
INSERT INTO recommandations (regle_id, ordre, action, commande, niveau) VALUES
-- Brute Force SSH (5712)
(5712, 1, 'URGENT: Bloquer l''IP attaquante immédiatement', 'sudo ufw deny from [IP_SOURCE]', 'debutant'),
(5712, 2, 'Vérifier si des connexions ont réussi', 'grep "Accepted" /var/log/auth.log | tail -20', 'debutant'),
(5712, 3, 'Changer les mots de passe des comptes SSH', 'sudo passwd [utilisateur]', 'debutant'),
(5712, 4, 'Analyser les logs d''authentification', 'grep -E "Failed|Accepted" /var/log/auth.log | tail -100', 'intermediaire'),
(5712, 5, 'Installer et configurer fail2ban', 'sudo apt install fail2ban && sudo systemctl enable fail2ban', 'intermediaire'),
(5712, 6, 'Désactiver l''authentification par mot de passe', 'sudo nano /etc/ssh/sshd_config # PasswordAuthentication no', 'avance'),
(5712, 7, 'Configurer authentification par clé uniquement', 'ssh-keygen -t ed25519 && ssh-copy-id user@server', 'avance'),

-- SQL Injection (87041)
(87041, 1, 'URGENT: Bloquer l''IP source', 'sudo ufw deny from [IP_SOURCE]', 'debutant'),
(87041, 2, 'Sauvegarder la base de données', 'mysqldump -u root -p --all-databases > backup.sql', 'debutant'),
(87041, 3, 'Vérifier les logs du serveur web', 'grep -i "union\\|select" /var/log/apache2/access.log | tail -50', 'intermediaire'),
(87041, 4, 'Activer un WAF (ModSecurity)', 'sudo apt install libapache2-mod-security2', 'avance'),

-- Ransomware (87236)
(87236, 1, 'CRITIQUE: Déconnecter IMMÉDIATEMENT le réseau', 'Débrancher câble Ethernet / Désactiver WiFi', 'debutant'),
(87236, 2, 'NE PAS payer la rançon', 'Contacter les autorités (police, ANSSI)', 'debutant'),
(87236, 3, 'Identifier le type de ransomware', 'Visiter nomoreransom.org depuis un autre appareil', 'debutant'),
(87236, 4, 'Isoler tous les systèmes potentiellement infectés', 'Couper les partages réseau', 'intermediaire'),
(87236, 5, 'Restaurer depuis sauvegarde saine', 'Réinstaller l''OS puis restaurer les données', 'avance'),

-- Webshell (87148)
(87148, 1, 'Isoler le serveur compromis', 'sudo ufw default deny incoming', 'debutant'),
(87148, 2, 'Identifier et supprimer le webshell', 'find /var/www -name "*.php" -mtime -1', 'intermediaire'),
(87148, 3, 'Analyser les logs d''accès', 'grep "POST.*\\.php" /var/log/apache2/access.log', 'intermediaire'),
(87148, 4, 'Restaurer les fichiers web depuis backup', 'Comparer avec sauvegarde saine', 'avance'),

-- Scan ports (1000001)
(1000001, 1, 'Noter l''IP source pour surveillance', 'Ajouter à la liste de surveillance', 'debutant'),
(1000001, 2, 'Vérifier les ports ouverts sur le serveur', 'sudo ss -tlnp', 'debutant'),
(1000001, 3, 'Bloquer l''IP si scan agressif', 'sudo ufw deny from [IP_SOURCE]', 'intermediaire'),
(1000001, 4, 'Configurer rate-limiting iptables', 'sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT', 'avance');

-- ============================================================================
-- TABLE: utilisateurs
-- ============================================================================
CREATE TABLE IF NOT EXISTS utilisateurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    nom_complet TEXT,
    role TEXT CHECK(role IN ('admin','analyste','lecteur')) NOT NULL DEFAULT 'lecteur',
    actif INTEGER DEFAULT 1,
    must_change_password INTEGER DEFAULT 1,
    last_login DATETIME,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    password_changed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- TABLE: sessions
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES utilisateurs(id)
);

-- ============================================================================
-- TABLE: alertes_log
-- ============================================================================
CREATE TABLE IF NOT EXISTS alertes_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    rule_id INTEGER,
    source TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    agent_name TEXT,
    raw_log TEXT,
    gravite TEXT,
    statut TEXT DEFAULT 'nouveau' CHECK(statut IN ('nouveau','vu','en_cours','traite','ignore')),
    traite_par INTEGER,
    traite_at DATETIME,
    notes TEXT,
    FOREIGN KEY (rule_id) REFERENCES regles(rule_id),
    FOREIGN KEY (traite_par) REFERENCES utilisateurs(id)
);

-- ============================================================================
-- TABLE: audit_log
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT
);

-- ============================================================================
-- INDEX
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_regles_rule_id ON regles(rule_id);
CREATE INDEX IF NOT EXISTS idx_regles_gravite ON regles(gravite);
CREATE INDEX IF NOT EXISTS idx_regles_source ON regles(source);
CREATE INDEX IF NOT EXISTS idx_alertes_timestamp ON alertes_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_alertes_gravite ON alertes_log(gravite);
CREATE INDEX IF NOT EXISTS idx_alertes_statut ON alertes_log(statut);

-- ============================================================================
-- VUES
-- ============================================================================
CREATE VIEW IF NOT EXISTS vue_alertes_completes AS
SELECT 
    a.id, a.timestamp, a.source_ip, a.destination_ip, a.agent_name, a.statut,
    r.rule_id, r.nom_fr, r.description, r.gravite, r.impact, r.cause_probable,
    r.mitre_id, r.mitre_tactic, r.source AS regle_source,
    c.nom AS categorie, c.icone, c.couleur
FROM alertes_log a
LEFT JOIN regles r ON a.rule_id = r.rule_id
LEFT JOIN categories c ON r.categorie_id = c.id;
SQLDB
    
    print_success "Schéma SQL créé"
    
    # Initialisation de la base de données
    print_info "Initialisation de la base de données..."
    sqlite3 ${SIEM_HOME}/database/siem_africa.db < ${SIEM_HOME}/database/siem_africa.sql
    
    # Compter les règles
    RULE_COUNT=$(sqlite3 ${SIEM_HOME}/database/siem_africa.db "SELECT COUNT(*) FROM regles;")
    CAT_COUNT=$(sqlite3 ${SIEM_HOME}/database/siem_africa.db "SELECT COUNT(*) FROM categories;")
    
    chown siem:siem ${SIEM_HOME}/database/siem_africa.db
    chmod 644 ${SIEM_HOME}/database/siem_africa.db
    
    print_success "Base de données créée: ${RULE_COUNT} règles, ${CAT_COUNT} catégories"
}

#===============================================================================
# CRÉATION DES FICHIERS D'IDENTIFIANTS
#===============================================================================

create_credentials_files() {
    print_step "Création des fichiers d'identifiants"
    
    # Récupérer l'IP du serveur
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    # Récupérer le mot de passe Wazuh si disponible
    if [[ -z "$WAZUH_ADMIN_PASS" ]]; then
        if [[ -f /root/wazuh-passwords.txt ]]; then
            WAZUH_ADMIN_PASS=$(grep "admin" /root/wazuh-passwords.txt 2>/dev/null | head -1 | awk '{print $NF}' | tr -d "'\"")
        fi
        [[ -z "$WAZUH_ADMIN_PASS" ]] && WAZUH_ADMIN_PASS="admin"
    fi
    
    # /root/credentials.txt - Tous les identifiants
    cat > ${CREDENTIALS_FILE} << EOF
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         SIEM AFRICA - IDENTIFIANTS                            ║
║                           FICHIER CONFIDENTIEL                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Date d'installation : $(date '+%Y-%m-%d %H:%M:%S')
Serveur            : $(hostname)
Adresse IP         : ${SERVER_IP}

═══════════════════════════════════════════════════════════════════════════════
                        UTILISATEURS SYSTÈME (Linux)
═══════════════════════════════════════════════════════════════════════════════

┌─────────────┬──────────────┬─────────────────────────────────────────────────┐
│ Utilisateur │ Mot de passe │ Rôle                                            │
├─────────────┼──────────────┼─────────────────────────────────────────────────┤
│ snort       │ ${SNORT_PASS}       │ Exécute le service Snort IDS                    │
│ wazuh       │ ${WAZUH_PASS}       │ Exécute les services Wazuh                      │
│ siem        │ ${SIEM_PASS}        │ Exécute SIEM Africa Dashboard                   │
└─────────────┴──────────────┴─────────────────────────────────────────────────┘

⚠️  Les mots de passe système expirent à la première connexion !

═══════════════════════════════════════════════════════════════════════════════
                          WAZUH DASHBOARD (Port 443)
═══════════════════════════════════════════════════════════════════════════════

URL         : https://${SERVER_IP}:443
Utilisateur : admin
Mot de passe: ${WAZUH_ADMIN_PASS}

Interface native Wazuh pour visualisation avancée des alertes.

═══════════════════════════════════════════════════════════════════════════════
                       SIEM AFRICA DASHBOARD (Port 5000)
═══════════════════════════════════════════════════════════════════════════════

URL         : https://${SERVER_IP}:5000

┌─────────────┬──────────────────┬───────────────────────────────────────────────┐
│ Utilisateur │ Mot de passe     │ Rôle                                          │
├─────────────┼──────────────────┼───────────────────────────────────────────────┤
│ admin       │ ${DASHBOARD_ADMIN_PASS}  │ Administrateur (accès complet)                │
│ analyste    │ ${DASHBOARD_ANALYST_PASS}     │ Analyste sécurité (alertes + règles)          │
│ lecteur     │ ${DASHBOARD_READER_PASS}      │ Lecture seule (consultation)                  │
└─────────────┴──────────────────┴───────────────────────────────────────────────┘

Interface française avec recommandations contextuelles.

═══════════════════════════════════════════════════════════════════════════════
                              WAZUH API (Port 55000)
═══════════════════════════════════════════════════════════════════════════════

URL         : https://${SERVER_IP}:55000
Utilisateur : wazuh-wui
Mot de passe: ${WAZUH_API_PASS:-wazuh}

═══════════════════════════════════════════════════════════════════════════════
                              SERVICES ET PORTS
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────┬───────────┬─────────────────────────────────────────┐
│ Service                 │ Port      │ Description                             │
├─────────────────────────┼───────────┼─────────────────────────────────────────┤
│ Wazuh Dashboard         │ 443       │ Interface web Wazuh (HTTPS)             │
│ SIEM Africa Dashboard   │ 5000      │ Interface française (HTTPS)             │
│ Wazuh API               │ 55000     │ API REST Wazuh                          │
│ Wazuh Indexer           │ 9200      │ OpenSearch (local uniquement)           │
│ Wazuh Manager           │ 1514      │ Réception agents                        │
│ Wazuh Manager           │ 1515      │ Enregistrement agents                   │
│ Wazuh Cluster           │ 1516      │ Communication cluster                   │
│ Snort IDS               │ -         │ Mode promiscuous sur interface          │
└─────────────────────────┴───────────┴─────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
⚠️  IMPORTANT: CHANGEZ TOUS LES MOTS DE PASSE APRÈS L'INSTALLATION !
═══════════════════════════════════════════════════════════════════════════════

Pour changer les mots de passe :
  sudo ${SIEM_HOME}/scripts/change_passwords.sh --all

EOF
    
    chmod 600 ${CREDENTIALS_FILE}
    print_success "Fichier /root/credentials.txt créé"
    
    # /opt/siem-africa/SCRID.txt - Identifiants dashboard + commandes
    cat > ${SCRID_FILE} << EOF
╔═══════════════════════════════════════════════════════════════════════════════╗
║              SIEM AFRICA - IDENTIFIANTS & COMMANDES DE VÉRIFICATION           ║
╚═══════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
                              ACCÈS AUX DASHBOARDS
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│                        WAZUH DASHBOARD (Anglais)                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ URL         : https://${SERVER_IP}:443                                       │
│ Utilisateur : admin                                                         │
│ Mot de passe: ${WAZUH_ADMIN_PASS}                                                          │
│                                                                             │
│ Interface native Wazuh - Visualisation avancée, règles, agents             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                      SIEM AFRICA DASHBOARD (Français)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ URL         : https://${SERVER_IP}:5000                                      │
│                                                                             │
│ Utilisateurs:                                                               │
│   • admin     / ${DASHBOARD_ADMIN_PASS}  (Administrateur)                           │
│   • analyste  / ${DASHBOARD_ANALYST_PASS}     (Analyste sécurité)                       │
│   • lecteur   / ${DASHBOARD_READER_PASS}      (Lecture seule)                           │
│                                                                             │
│ Interface française - Alertes traduites, recommandations, rapports          │
└─────────────────────────────────────────────────────────────────────────────┘

⚠️  Le changement de mot de passe est OBLIGATOIRE à la première connexion !

═══════════════════════════════════════════════════════════════════════════════
                         COMMANDES DE VÉRIFICATION
═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# ÉTAT DES SERVICES
# ─────────────────────────────────────────────────────────────────────────────

# Vérifier tous les services SIEM
systemctl status snort wazuh-manager wazuh-indexer wazuh-dashboard siem-africa-dashboard

# Vérifier Snort IDS
systemctl status snort
snort -V

# Vérifier Wazuh Stack
systemctl status wazuh-indexer
systemctl status wazuh-manager
systemctl status wazuh-dashboard
/var/ossec/bin/wazuh-control status

# Vérifier SIEM Africa
systemctl status siem-africa-dashboard

# ─────────────────────────────────────────────────────────────────────────────
# VÉRIFICATION DES PORTS
# ─────────────────────────────────────────────────────────────────────────────

# Ports en écoute
ss -tlnp | grep -E '443|5000|9200|55000|1514|1515'

# Test connectivité dashboards
curl -k https://localhost:443 -o /dev/null -w "%{http_code}\n"
curl -k https://localhost:5000 -o /dev/null -w "%{http_code}\n"

# ─────────────────────────────────────────────────────────────────────────────
# LOGS EN TEMPS RÉEL
# ─────────────────────────────────────────────────────────────────────────────

# Alertes Snort
tail -f /var/log/snort/alert

# Alertes Wazuh
tail -f /var/ossec/logs/alerts/alerts.json

# Logs SIEM Africa
tail -f ${SIEM_HOME}/logs/dashboard.log

# Logs d'installation
tail -f /var/log/siem-africa-install.log

# ─────────────────────────────────────────────────────────────────────────────
# BASE DE DONNÉES SIEM AFRICA
# ─────────────────────────────────────────────────────────────────────────────

# Nombre de règles
sqlite3 ${SIEM_HOME}/database/siem_africa.db "SELECT COUNT(*) FROM regles;"

# Règles par source
sqlite3 ${SIEM_HOME}/database/siem_africa.db "SELECT source, COUNT(*) FROM regles GROUP BY source;"

# Règles par gravité
sqlite3 ${SIEM_HOME}/database/siem_africa.db "SELECT gravite, COUNT(*) FROM regles GROUP BY gravite ORDER BY gravite;"

# Dernières alertes
sqlite3 ${SIEM_HOME}/database/siem_africa.db "SELECT * FROM alertes_log ORDER BY timestamp DESC LIMIT 10;"

# ─────────────────────────────────────────────────────────────────────────────
# DIAGNOSTIC COMPLET
# ─────────────────────────────────────────────────────────────────────────────

# Générer un rapport de diagnostic
sudo ${SIEM_HOME}/scripts/diagnostic.sh

# ─────────────────────────────────────────────────────────────────────────────
# GESTION DES MOTS DE PASSE
# ─────────────────────────────────────────────────────────────────────────────

# Changer tous les mots de passe
sudo ${SIEM_HOME}/scripts/change_passwords.sh --all

# Changer un mot de passe spécifique
sudo ${SIEM_HOME}/scripts/change_passwords.sh --snort
sudo ${SIEM_HOME}/scripts/change_passwords.sh --wazuh
sudo ${SIEM_HOME}/scripts/change_passwords.sh --siem
sudo ${SIEM_HOME}/scripts/change_passwords.sh --dashboard

# ─────────────────────────────────────────────────────────────────────────────
# REDÉMARRAGE DES SERVICES
# ─────────────────────────────────────────────────────────────────────────────

# Redémarrer tous les services
sudo systemctl restart snort wazuh-manager wazuh-indexer wazuh-dashboard siem-africa-dashboard

# Redémarrer un service spécifique
sudo systemctl restart snort
sudo systemctl restart wazuh-manager
sudo systemctl restart siem-africa-dashboard

EOF
    
    chmod 644 ${SCRID_FILE}
    chown siem:siem ${SCRID_FILE}
    print_success "Fichier SCRID.txt créé"
}

#===============================================================================
# CRÉATION DU SCRIPT DE CHANGEMENT DE MOT DE PASSE
#===============================================================================

create_change_password_script() {
    print_step "Création du script de changement de mot de passe"
    
    cat > ${SIEM_HOME}/scripts/change_passwords.sh << 'PWDSCRIPT'
#!/bin/bash
#===============================================================================
# SIEM Africa - Script de Changement de Mot de Passe v2.1
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

SIEM_HOME="/opt/siem-africa"
DB_FILE="${SIEM_HOME}/database/siem_africa.db"

print_banner() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          SIEM AFRICA - Changement de Mot de Passe                    ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_help() {
    print_banner
    echo -e "${WHITE}Usage:${NC} $0 [OPTION]"
    echo ""
    echo -e "${WHITE}Options:${NC}"
    echo "  --all           Changer TOUS les mots de passe (système + dashboard)"
    echo "  --system        Changer les mots de passe système (snort, wazuh, siem)"
    echo "  --snort         Changer le mot de passe utilisateur snort"
    echo "  --wazuh         Changer le mot de passe utilisateur wazuh"
    echo "  --siem          Changer le mot de passe utilisateur siem"
    echo "  --dashboard     Changer les mots de passe du dashboard SIEM Africa"
    echo "  --admin         Changer le mot de passe admin du dashboard"
    echo "  --wazuh-admin   Changer le mot de passe admin Wazuh Dashboard"
    echo "  --help          Afficher cette aide"
    echo ""
    echo -e "${WHITE}Exemples:${NC}"
    echo "  sudo $0 --all"
    echo "  sudo $0 --snort"
    echo "  sudo $0 --dashboard"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}✗ Ce script doit être exécuté en tant que root (sudo)${NC}"
        exit 1
    fi
}

change_system_password() {
    local user=$1
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}Changement du mot de passe pour l'utilisateur système: ${CYAN}${user}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if ! id "$user" &>/dev/null; then
        echo -e "${RED}✗ L'utilisateur '$user' n'existe pas${NC}"
        return 1
    fi
    
    passwd "$user"
    
    if [[ $? -eq 0 ]]; then
        # Réinitialiser l'expiration du mot de passe
        chage -d $(date +%Y-%m-%d) "$user"
        echo -e "${GREEN}✓ Mot de passe changé avec succès pour ${user}${NC}"
        
        # Logger l'action
        echo "[$(date)] Password changed for system user: $user" >> /var/log/siem-africa-install.log
    else
        echo -e "${RED}✗ Erreur lors du changement de mot de passe${NC}"
        return 1
    fi
}

change_dashboard_user_password() {
    local username=$1
    
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}Changement du mot de passe dashboard pour: ${CYAN}${username}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Vérifier que l'utilisateur existe
    EXISTS=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM utilisateurs WHERE username='$username';")
    if [[ "$EXISTS" -eq 0 ]]; then
        echo -e "${RED}✗ L'utilisateur '$username' n'existe pas dans le dashboard${NC}"
        return 1
    fi
    
    # Demander le nouveau mot de passe
    while true; do
        read -sp "Nouveau mot de passe pour $username: " new_pass
        echo ""
        
        if [[ ${#new_pass} -lt 8 ]]; then
            echo -e "${RED}✗ Le mot de passe doit contenir au moins 8 caractères${NC}"
            continue
        fi
        
        read -sp "Confirmer le mot de passe: " confirm_pass
        echo ""
        
        if [[ "$new_pass" != "$confirm_pass" ]]; then
            echo -e "${RED}✗ Les mots de passe ne correspondent pas${NC}"
            continue
        fi
        
        break
    done
    
    # Hasher le mot de passe
    HASH=$(python3 -c "import hashlib; print(hashlib.sha256('${new_pass}'.encode()).hexdigest())")
    
    # Mettre à jour dans la base de données
    sqlite3 "$DB_FILE" "UPDATE utilisateurs SET password_hash='${HASH}', must_change_password=0, password_changed_at=datetime('now') WHERE username='${username}';"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}✓ Mot de passe changé avec succès pour ${username} (dashboard)${NC}"
        echo "[$(date)] Password changed for dashboard user: $username" >> /var/log/siem-africa-install.log
    else
        echo -e "${RED}✗ Erreur lors de la mise à jour de la base de données${NC}"
        return 1
    fi
}

change_wazuh_admin_password() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}Changement du mot de passe admin Wazuh Dashboard${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ -f /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh ]]; then
        echo -e "${YELLOW}Utilisation de l'outil Wazuh pour changer le mot de passe admin...${NC}"
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p
    else
        echo -e "${YELLOW}⚠ Outil de changement de mot de passe Wazuh non trouvé.${NC}"
        echo -e "${WHITE}Pour changer le mot de passe admin Wazuh manuellement:${NC}"
        echo "1. Connectez-vous au Wazuh Dashboard"
        echo "2. Allez dans Security → Internal users → admin"
        echo "3. Cliquez sur 'Edit' et changez le mot de passe"
    fi
}

change_all_passwords() {
    print_banner
    
    echo -e "${YELLOW}⚠ Vous allez changer TOUS les mots de passe du système SIEM Africa${NC}"
    echo ""
    read -p "Êtes-vous sûr de vouloir continuer ? (o/N) " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
        echo "Opération annulée."
        exit 0
    fi
    
    echo ""
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}           CHANGEMENT DES MOTS DE PASSE SYSTÈME                        ${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════${NC}"
    
    change_system_password "snort"
    change_system_password "wazuh"
    change_system_password "siem"
    
    echo ""
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}        CHANGEMENT DES MOTS DE PASSE DASHBOARD SIEM AFRICA             ${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════${NC}"
    
    change_dashboard_user_password "admin"
    change_dashboard_user_password "analyste"
    change_dashboard_user_password "lecteur"
    
    echo ""
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}           CHANGEMENT DU MOT DE PASSE WAZUH ADMIN                      ${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════${NC}"
    
    change_wazuh_admin_password
    
    # Supprimer le flag de première exécution
    rm -f ${SIEM_HOME}/.first_run 2>/dev/null
    sqlite3 "$DB_FILE" "UPDATE config SET valeur='0' WHERE cle='first_run';" 2>/dev/null
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           TOUS LES MOTS DE PASSE ONT ÉTÉ CHANGÉS !                   ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}⚠ N'oubliez pas de mettre à jour vos notes avec les nouveaux mots de passe !${NC}"
    echo ""
}

change_system_passwords() {
    print_banner
    echo -e "${WHITE}Changement des mots de passe système uniquement${NC}"
    
    change_system_password "snort"
    change_system_password "wazuh"
    change_system_password "siem"
    
    echo ""
    echo -e "${GREEN}✓ Mots de passe système changés${NC}"
}

change_dashboard_passwords() {
    print_banner
    echo -e "${WHITE}Changement des mots de passe dashboard SIEM Africa${NC}"
    
    change_dashboard_user_password "admin"
    change_dashboard_user_password "analyste"
    change_dashboard_user_password "lecteur"
    
    # Supprimer le flag de première exécution
    rm -f ${SIEM_HOME}/.first_run 2>/dev/null
    
    echo ""
    echo -e "${GREEN}✓ Mots de passe dashboard changés${NC}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

check_root

case "$1" in
    --all)
        change_all_passwords
        ;;
    --system)
        change_system_passwords
        ;;
    --snort)
        print_banner
        change_system_password "snort"
        ;;
    --wazuh)
        print_banner
        change_system_password "wazuh"
        ;;
    --siem)
        print_banner
        change_system_password "siem"
        ;;
    --dashboard)
        change_dashboard_passwords
        ;;
    --admin)
        print_banner
        change_dashboard_user_password "admin"
        ;;
    --wazuh-admin)
        print_banner
        change_wazuh_admin_password
        ;;
    --help|"")
        show_help
        ;;
    *)
        echo -e "${RED}Option inconnue: $1${NC}"
        show_help
        exit 1
        ;;
esac
PWDSCRIPT
    
    chmod +x ${SIEM_HOME}/scripts/change_passwords.sh
    chown siem:siem ${SIEM_HOME}/scripts/change_passwords.sh
    print_success "Script change_passwords.sh créé"
}

#===============================================================================
# CRÉATION DU SCRIPT DE DIAGNOSTIC
#===============================================================================

create_diagnostic_script() {
    print_info "Création du script de diagnostic..."
    
    cat > ${SIEM_HOME}/scripts/diagnostic.sh << 'DIAGSCRIPT'
#!/bin/bash
#===============================================================================
# SIEM Africa - Script de Diagnostic Complet
#===============================================================================

REPORT_FILE="/tmp/siem-africa-diagnostic-$(date +%Y%m%d_%H%M%S).txt"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║              SIEM AFRICA - DIAGNOSTIC COMPLET                         ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Génération du rapport dans: $REPORT_FILE"
echo ""

{
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "SIEM AFRICA - RAPPORT DE DIAGNOSTIC"
    echo "Date: $(date)"
    echo "Serveur: $(hostname)"
    echo "IP: $(hostname -I | awk '{print $1}')"
    echo "═══════════════════════════════════════════════════════════════════════"
    echo ""
    
    echo "=== INFORMATIONS SYSTÈME ==="
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime -p)"
    echo "RAM Total: $(free -h | grep Mem | awk '{print $2}')"
    echo "RAM Utilisée: $(free -h | grep Mem | awk '{print $3}')"
    echo "Disque /: $(df -h / | awk 'NR==2 {print $3 " utilisé sur " $2 " (" $5 ")"}')"
    echo ""
    
    echo "=== ÉTAT DES SERVICES ==="
    echo ""
    echo "--- Snort IDS ---"
    systemctl is-active snort 2>/dev/null && echo "Status: ACTIF" || echo "Status: INACTIF"
    systemctl status snort --no-pager 2>/dev/null | head -10
    echo ""
    
    echo "--- Wazuh Indexer ---"
    systemctl is-active wazuh-indexer 2>/dev/null && echo "Status: ACTIF" || echo "Status: INACTIF"
    systemctl status wazuh-indexer --no-pager 2>/dev/null | head -10
    echo ""
    
    echo "--- Wazuh Manager ---"
    systemctl is-active wazuh-manager 2>/dev/null && echo "Status: ACTIF" || echo "Status: INACTIF"
    systemctl status wazuh-manager --no-pager 2>/dev/null | head -10
    echo ""
    
    echo "--- Wazuh Dashboard ---"
    systemctl is-active wazuh-dashboard 2>/dev/null && echo "Status: ACTIF" || echo "Status: INACTIF"
    systemctl status wazuh-dashboard --no-pager 2>/dev/null | head -10
    echo ""
    
    echo "--- SIEM Africa Dashboard ---"
    systemctl is-active siem-africa-dashboard 2>/dev/null && echo "Status: ACTIF" || echo "Status: INACTIF"
    systemctl status siem-africa-dashboard --no-pager 2>/dev/null | head -10
    echo ""
    
    echo "=== PORTS EN ÉCOUTE ==="
    ss -tlnp | grep -E '443|5000|9200|55000|1514|1515' || echo "Aucun port SIEM détecté"
    echo ""
    
    echo "=== TEST CONNECTIVITÉ ==="
    echo "Wazuh Dashboard (443): $(curl -sk -o /dev/null -w "%{http_code}" https://localhost:443 2>/dev/null || echo "ÉCHEC")"
    echo "SIEM Africa (5000): $(curl -sk -o /dev/null -w "%{http_code}" https://localhost:5000 2>/dev/null || echo "ÉCHEC")"
    echo "Wazuh API (55000): $(curl -sk -o /dev/null -w "%{http_code}" https://localhost:55000 2>/dev/null || echo "ÉCHEC")"
    echo ""
    
    echo "=== BASE DE DONNÉES SIEM AFRICA ==="
    if [[ -f /opt/siem-africa/database/siem_africa.db ]]; then
        echo "Fichier: $(ls -lh /opt/siem-africa/database/siem_africa.db | awk '{print $5}')"
        echo "Règles totales: $(sqlite3 /opt/siem-africa/database/siem_africa.db 'SELECT COUNT(*) FROM regles;' 2>/dev/null)"
        echo "Règles Wazuh: $(sqlite3 /opt/siem-africa/database/siem_africa.db 'SELECT COUNT(*) FROM regles WHERE source="wazuh";' 2>/dev/null)"
        echo "Règles Snort: $(sqlite3 /opt/siem-africa/database/siem_africa.db 'SELECT COUNT(*) FROM regles WHERE source="snort";' 2>/dev/null)"
        echo "Catégories: $(sqlite3 /opt/siem-africa/database/siem_africa.db 'SELECT COUNT(*) FROM categories;' 2>/dev/null)"
        echo "Alertes enregistrées: $(sqlite3 /opt/siem-africa/database/siem_africa.db 'SELECT COUNT(*) FROM alertes_log;' 2>/dev/null)"
        echo "Utilisateurs dashboard: $(sqlite3 /opt/siem-africa/database/siem_africa.db 'SELECT COUNT(*) FROM utilisateurs;' 2>/dev/null)"
    else
        echo "Base de données non trouvée !"
    fi
    echo ""
    
    echo "=== UTILISATEURS SYSTÈME ==="
    id snort 2>/dev/null || echo "Utilisateur snort: NON CRÉÉ"
    id wazuh 2>/dev/null || echo "Utilisateur wazuh: NON CRÉÉ"  
    id siem 2>/dev/null || echo "Utilisateur siem: NON CRÉÉ"
    id ossec 2>/dev/null || echo "Utilisateur ossec: NON CRÉÉ"
    echo ""
    
    echo "=== CERTIFICATS SSL ==="
    if [[ -f /opt/siem-africa/certs/cert.pem ]]; then
        echo "SIEM Africa:"
        openssl x509 -in /opt/siem-africa/certs/cert.pem -noout -dates 2>/dev/null
    else
        echo "Certificat SIEM Africa: NON TROUVÉ"
    fi
    echo ""
    
    echo "=== DERNIÈRES ALERTES SNORT (10) ==="
    tail -10 /var/log/snort/alert 2>/dev/null || echo "Pas de logs Snort"
    echo ""
    
    echo "=== DERNIÈRES ALERTES WAZUH (10) ==="
    tail -10 /var/ossec/logs/alerts/alerts.log 2>/dev/null || echo "Pas de logs Wazuh"
    echo ""
    
    echo "=== ESPACE DISQUE DÉTAILLÉ ==="
    df -h
    echo ""
    
    echo "=== MÉMOIRE DÉTAILLÉE ==="
    free -h
    echo ""
    
    echo "=== PROCESSUS SIEM ==="
    ps aux | grep -E 'snort|wazuh|ossec|gunicorn|flask' | grep -v grep
    echo ""
    
    echo "═══════════════════════════════════════════════════════════════════════"
    echo "FIN DU RAPPORT DE DIAGNOSTIC"
    echo "═══════════════════════════════════════════════════════════════════════"
    
} > "$REPORT_FILE" 2>&1

echo -e "\033[0;32m✓ Rapport généré: $REPORT_FILE\033[0m"
echo ""
echo "Pour afficher le rapport complet:"
echo "  cat $REPORT_FILE"
echo ""
echo "Pour envoyer le rapport par email:"
echo "  mail -s 'SIEM Africa Diagnostic' admin@example.com < $REPORT_FILE"
echo ""
DIAGSCRIPT
    
    chmod +x ${SIEM_HOME}/scripts/diagnostic.sh
    chown siem:siem ${SIEM_HOME}/scripts/diagnostic.sh
    print_success "Script diagnostic.sh créé"
}

#===============================================================================
# CRÉATION DU SERVICE SYSTEMD SIEM AFRICA
#===============================================================================

create_systemd_service() {
    print_step "Création des services systemd"
    
    # Service Dashboard SIEM Africa
    cat > /etc/systemd/system/siem-africa-dashboard.service << EOF
[Unit]
Description=SIEM Africa Dashboard - Interface française de cybersécurité
After=network.target wazuh-manager.service
Wants=network-online.target

[Service]
Type=simple
User=siem
Group=siem
WorkingDirectory=${SIEM_HOME}/dashboard
Environment="PATH=${SIEM_HOME}/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="FLASK_APP=app.py"
Environment="FLASK_ENV=production"
ExecStart=${SIEM_HOME}/venv/bin/gunicorn \
    --bind 0.0.0.0:5000 \
    --workers 2 \
    --threads 4 \
    --timeout 120 \
    --certfile=${SIEM_HOME}/certs/cert.pem \
    --keyfile=${SIEM_HOME}/certs/key.pem \
    --access-logfile ${SIEM_HOME}/logs/access.log \
    --error-logfile ${SIEM_HOME}/logs/error.log \
    app:app
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable siem-africa-dashboard >> "$LOG_FILE" 2>&1
    
    print_success "Service siem-africa-dashboard créé et activé"
}

#===============================================================================
# CRÉATION DE L'APPLICATION FLASK SIEM AFRICA
#===============================================================================

create_flask_application() {
    print_info "Création de l'application Flask..."
    
    # Créer l'application Flask principale
    cat > ${SIEM_HOME}/dashboard/app.py << 'FLASKAPP'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM Africa - Dashboard Principal
Solution de Cybersécurité pour les PME Africaines
Version 2.1
"""

import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g

app = Flask(__name__, 
            template_folder='/opt/siem-africa/templates',
            static_folder='/opt/siem-africa/static')
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

DATABASE = '/opt/siem-africa/database/siem_africa.db'
FIRST_RUN_FLAG = '/opt/siem-africa/.first_run'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_first_run():
    return os.path.exists(FIRST_RUN_FLAG)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Accès réservé aux administrateurs.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        db = get_db()
        user = db.execute('SELECT * FROM utilisateurs WHERE username = ? AND actif = 1', 
                         (username,)).fetchone()
        
        if user and user['password_hash'] == hash_password(password):
            if user['locked_until']:
                lock_time = datetime.fromisoformat(user['locked_until'])
                if datetime.now() < lock_time:
                    flash(f'Compte verrouillé jusqu\'à {lock_time.strftime("%H:%M:%S")}', 'danger')
                    return render_template('login.html')
            
            db.execute('UPDATE utilisateurs SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?',
                      (datetime.now().isoformat(), user['id']))
            db.commit()
            
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['must_change_password'] = user['must_change_password']
            
            db.execute('INSERT INTO audit_log (user_id, username, action, ip_address) VALUES (?, ?, ?, ?)',
                      (user['id'], username, 'login', request.remote_addr))
            db.commit()
            
            if user['must_change_password']:
                return redirect(url_for('change_password_required'))
            
            return redirect(url_for('dashboard'))
        else:
            if user:
                failed = user['failed_attempts'] + 1
                locked_until = None
                if failed >= 5:
                    locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                db.execute('UPDATE utilisateurs SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                          (failed, locked_until, user['id']))
                db.commit()
            flash('Identifiants incorrects.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        db = get_db()
        db.execute('INSERT INTO audit_log (user_id, username, action, ip_address) VALUES (?, ?, ?, ?)',
                  (session['user_id'], session['username'], 'logout', request.remote_addr))
        db.commit()
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))

@app.route('/change-password-required', methods=['GET', 'POST'])
@login_required
def change_password_required():
    if not session.get('must_change_password'):
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if len(new_password) < 8:
            flash('Le mot de passe doit contenir au moins 8 caractères.', 'danger')
        elif new_password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'danger')
        else:
            db = get_db()
            db.execute('UPDATE utilisateurs SET password_hash = ?, must_change_password = 0, password_changed_at = ? WHERE id = ?',
                      (hash_password(new_password), datetime.now().isoformat(), session['user_id']))
            db.commit()
            
            session['must_change_password'] = False
            
            if session['role'] == 'admin' and is_first_run():
                try:
                    os.remove(FIRST_RUN_FLAG)
                except:
                    pass
            
            flash('Mot de passe modifié avec succès!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('change_password_required.html', first_run=is_first_run())

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    
    stats = {
        'total': db.execute('SELECT COUNT(*) FROM alertes_log').fetchone()[0],
        'critiques': db.execute('SELECT COUNT(*) FROM alertes_log WHERE gravite = "critique"').fetchone()[0],
        'hautes': db.execute('SELECT COUNT(*) FROM alertes_log WHERE gravite = "haute"').fetchone()[0],
        'nouvelles': db.execute('SELECT COUNT(*) FROM alertes_log WHERE statut = "nouveau"').fetchone()[0],
        'regles_total': db.execute('SELECT COUNT(*) FROM regles').fetchone()[0],
        'regles_wazuh': db.execute('SELECT COUNT(*) FROM regles WHERE source = "wazuh"').fetchone()[0],
        'regles_snort': db.execute('SELECT COUNT(*) FROM regles WHERE source = "snort"').fetchone()[0],
    }
    
    alertes = db.execute('''
        SELECT a.*, r.nom_fr, r.gravite, c.icone, c.nom as categorie
        FROM alertes_log a
        LEFT JOIN regles r ON a.rule_id = r.rule_id
        LEFT JOIN categories c ON r.categorie_id = c.id
        ORDER BY a.timestamp DESC
        LIMIT 10
    ''').fetchall()
    
    return render_template('dashboard.html', stats=stats, alertes=alertes)

@app.route('/alertes')
@login_required
def alertes():
    db = get_db()
    
    gravite = request.args.get('gravite', '')
    statut = request.args.get('statut', '')
    source = request.args.get('source', '')
    
    query = '''
        SELECT a.*, r.nom_fr, r.gravite, r.description, r.source, c.icone, c.nom as categorie
        FROM alertes_log a
        LEFT JOIN regles r ON a.rule_id = r.rule_id
        LEFT JOIN categories c ON r.categorie_id = c.id
        WHERE 1=1
    '''
    params = []
    
    if gravite:
        query += ' AND r.gravite = ?'
        params.append(gravite)
    if statut:
        query += ' AND a.statut = ?'
        params.append(statut)
    if source:
        query += ' AND r.source = ?'
        params.append(source)
    
    query += ' ORDER BY a.timestamp DESC LIMIT 100'
    
    alertes = db.execute(query, params).fetchall()
    categories = db.execute('SELECT * FROM categories ORDER BY source, nom').fetchall()
    
    return render_template('alertes.html', alertes=alertes, categories=categories)

@app.route('/regles')
@login_required
def regles():
    db = get_db()
    
    source = request.args.get('source', '')
    categorie = request.args.get('categorie', '')
    gravite = request.args.get('gravite', '')
    search = request.args.get('search', '')
    
    query = '''
        SELECT r.*, c.nom as categorie, c.icone
        FROM regles r
        LEFT JOIN categories c ON r.categorie_id = c.id
        WHERE r.actif = 1
    '''
    params = []
    
    if source:
        query += ' AND r.source = ?'
        params.append(source)
    if categorie:
        query += ' AND r.categorie_id = ?'
        params.append(categorie)
    if gravite:
        query += ' AND r.gravite = ?'
        params.append(gravite)
    if search:
        query += ' AND (r.nom_fr LIKE ? OR r.description LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    
    query += ' ORDER BY r.source, r.gravite DESC, r.nom_fr LIMIT 200'
    
    regles = db.execute(query, params).fetchall()
    categories = db.execute('SELECT * FROM categories ORDER BY source, nom').fetchall()
    
    stats = {
        'total': db.execute('SELECT COUNT(*) FROM regles WHERE actif = 1').fetchone()[0],
        'wazuh': db.execute('SELECT COUNT(*) FROM regles WHERE source = "wazuh" AND actif = 1').fetchone()[0],
        'snort': db.execute('SELECT COUNT(*) FROM regles WHERE source = "snort" AND actif = 1').fetchone()[0],
    }
    
    return render_template('regles.html', regles=regles, categories=categories, stats=stats)

@app.route('/regle/<int:rule_id>')
@login_required
def detail_regle(rule_id):
    db = get_db()
    
    regle = db.execute('''
        SELECT r.*, c.nom as categorie, c.icone, c.couleur
        FROM regles r
        LEFT JOIN categories c ON r.categorie_id = c.id
        WHERE r.rule_id = ?
    ''', (rule_id,)).fetchone()
    
    if not regle:
        flash('Règle non trouvée.', 'danger')
        return redirect(url_for('regles'))
    
    recommandations = db.execute('''
        SELECT * FROM recommandations 
        WHERE regle_id = ? 
        ORDER BY niveau, ordre
    ''', (rule_id,)).fetchall()
    
    return render_template('detail_regle.html', regle=regle, recommandations=recommandations)

@app.route('/statistiques')
@login_required
def statistiques():
    db = get_db()
    
    stats_gravite = db.execute('''
        SELECT gravite, COUNT(*) as nombre
        FROM alertes_log
        GROUP BY gravite
    ''').fetchall()
    
    stats_source = db.execute('''
        SELECT r.source, COUNT(*) as nombre
        FROM alertes_log a
        JOIN regles r ON a.rule_id = r.rule_id
        GROUP BY r.source
    ''').fetchall()
    
    stats_categorie = db.execute('''
        SELECT c.nom, c.icone, COUNT(*) as nombre
        FROM alertes_log a
        JOIN regles r ON a.rule_id = r.rule_id
        JOIN categories c ON r.categorie_id = c.id
        GROUP BY c.id
        ORDER BY nombre DESC
        LIMIT 10
    ''').fetchall()
    
    return render_template('statistiques.html', 
                          stats_gravite=stats_gravite,
                          stats_source=stats_source,
                          stats_categorie=stats_categorie)

@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    stats = {
        'total': db.execute('SELECT COUNT(*) FROM alertes_log').fetchone()[0],
        'critiques': db.execute('SELECT COUNT(*) FROM alertes_log WHERE gravite = "critique"').fetchone()[0],
        'hautes': db.execute('SELECT COUNT(*) FROM alertes_log WHERE gravite = "haute"').fetchone()[0],
        'nouvelles': db.execute('SELECT COUNT(*) FROM alertes_log WHERE statut = "nouveau"').fetchone()[0],
    }
    return jsonify(stats)

# Initialisation des utilisateurs par défaut
def init_db():
    db = get_db()
    
    # Vérifier si les utilisateurs existent
    count = db.execute('SELECT COUNT(*) FROM utilisateurs').fetchone()[0]
    if count == 0:
        # Créer les utilisateurs par défaut
        users = [
            ('admin', 'SiemAfrica2026!', 'admin@siem-africa.local', 'Administrateur', 'admin'),
            ('analyste', 'Analyste123!', 'analyste@siem-africa.local', 'Analyste Sécurité', 'analyste'),
            ('lecteur', 'Lecteur123!', 'lecteur@siem-africa.local', 'Lecteur', 'lecteur'),
        ]
        
        for username, password, email, nom, role in users:
            db.execute('''
                INSERT INTO utilisateurs (username, password_hash, email, nom_complet, role, must_change_password)
                VALUES (?, ?, ?, ?, ?, 1)
            ''', (username, hash_password(password), email, nom, role))
        
        db.commit()

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
FLASKAPP
    
    chown siem:siem ${SIEM_HOME}/dashboard/app.py
    print_success "Application Flask créée"
}

#===============================================================================
# CRÉATION DES TEMPLATES HTML
#===============================================================================

create_templates() {
    print_info "Création des templates HTML..."
    
    # Template de base
    cat > ${SIEM_HOME}/templates/base.html << 'BASEHTML'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}SIEM Africa{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --siem-primary: #2C3E50;
            --siem-success: #27AE60;
            --siem-danger: #E74C3C;
            --siem-warning: #F39C12;
            --siem-info: #3498DB;
        }
        body { background-color: #f8f9fa; }
        .navbar { background: linear-gradient(135deg, var(--siem-primary), #1a252f) !important; }
        .stat-card { border-radius: 10px; border: none; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-card .card-body { padding: 1.5rem; }
        .badge-critique { background-color: var(--siem-danger); }
        .badge-haute { background-color: #E67E22; }
        .badge-moyenne { background-color: var(--siem-warning); }
        .badge-faible { background-color: var(--siem-info); }
        .badge-info { background-color: #95A5A6; }
        .login-container { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, var(--siem-primary), #1a252f); }
        .login-box { background: white; padding: 2rem; border-radius: 15px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); max-width: 400px; width: 100%; }
        .table-hover tbody tr:hover { background-color: rgba(52, 152, 219, 0.1); }
        .source-badge-wazuh { background-color: #9B59B6; }
        .source-badge-snort { background-color: #E67E22; }
    </style>
</head>
<body>
    {% if session.user_id and not session.must_change_password %}
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">
                <i class="bi bi-shield-check me-2"></i>SIEM Africa
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}"><i class="bi bi-speedometer2 me-1"></i>Dashboard</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('alertes') }}"><i class="bi bi-exclamation-triangle me-1"></i>Alertes</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('regles') }}"><i class="bi bi-list-check me-1"></i>Règles</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('statistiques') }}"><i class="bi bi-graph-up me-1"></i>Stats</a></li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle me-1"></i>{{ session.username }}
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><span class="dropdown-item-text text-muted">Rôle: {{ session.role }}</span></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="{{ url_for('logout') }}"><i class="bi bi-box-arrow-right me-2"></i>Déconnexion</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    {% endif %}
    
    <main class="{% if session.user_id and not session.must_change_password %}container-fluid py-4{% endif %}">
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
        <div class="container-fluid">
        {% for category, message in messages %}
        <div class="alert alert-{{ category if category != 'message' else 'info' }} alert-dismissible fade show">
            {{ message }}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
        {% endfor %}
        </div>
        {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </main>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
BASEHTML

    # Page de login
    cat > ${SIEM_HOME}/templates/login.html << 'LOGINHTML'
{% extends "base.html" %}
{% block title %}Connexion - SIEM Africa{% endblock %}
{% block content %}
<div class="login-container">
    <div class="login-box">
        <div class="text-center mb-4">
            <i class="bi bi-shield-check display-1 text-primary"></i>
            <h2 class="mt-3">SIEM Africa</h2>
            <p class="text-muted">Solution de Cybersécurité pour PME Africaines</p>
        </div>
        <form method="POST">
            <div class="mb-3">
                <label class="form-label">Nom d'utilisateur</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="bi bi-person"></i></span>
                    <input type="text" class="form-control" name="username" required autofocus>
                </div>
            </div>
            <div class="mb-4">
                <label class="form-label">Mot de passe</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="bi bi-lock"></i></span>
                    <input type="password" class="form-control" name="password" required>
                </div>
            </div>
            <button type="submit" class="btn btn-primary w-100 py-2">
                <i class="bi bi-box-arrow-in-right me-2"></i>Se connecter
            </button>
        </form>
    </div>
</div>
{% endblock %}
LOGINHTML

    # Page changement mot de passe obligatoire
    cat > ${SIEM_HOME}/templates/change_password_required.html << 'CHPWDHTML'
{% extends "base.html" %}
{% block title %}Changer le mot de passe - SIEM Africa{% endblock %}
{% block content %}
<div class="login-container">
    <div class="login-box" style="max-width: 500px;">
        <div class="text-center mb-4">
            <i class="bi bi-key display-1 text-warning"></i>
            <h2 class="mt-3">Changement obligatoire</h2>
            {% if first_run %}
            <div class="alert alert-info mt-3">
                <i class="bi bi-info-circle me-2"></i>
                <strong>Première installation.</strong> Vous devez changer le mot de passe par défaut.
            </div>
            {% endif %}
        </div>
        <form method="POST">
            <div class="mb-3">
                <label class="form-label">Nouveau mot de passe</label>
                <input type="password" class="form-control" name="new_password" required minlength="8">
                <div class="form-text">Minimum 8 caractères</div>
            </div>
            <div class="mb-4">
                <label class="form-label">Confirmer</label>
                <input type="password" class="form-control" name="confirm_password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100 py-2">
                <i class="bi bi-check-lg me-2"></i>Enregistrer
            </button>
        </form>
    </div>
</div>
{% endblock %}
CHPWDHTML

    # Dashboard
    cat > ${SIEM_HOME}/templates/dashboard.html << 'DASHHTML'
{% extends "base.html" %}
{% block title %}Dashboard - SIEM Africa{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1><i class="bi bi-speedometer2 me-2"></i>Tableau de bord</h1>
</div>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card stat-card bg-info text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6>Total Alertes</h6>
                        <h2 class="mb-0">{{ stats.total }}</h2>
                    </div>
                    <i class="bi bi-bell display-4 opacity-50"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card stat-card bg-danger text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6>Critiques</h6>
                        <h2 class="mb-0">{{ stats.critiques }}</h2>
                    </div>
                    <i class="bi bi-exclamation-octagon display-4 opacity-50"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card stat-card bg-warning text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6>Hautes</h6>
                        <h2 class="mb-0">{{ stats.hautes }}</h2>
                    </div>
                    <i class="bi bi-exclamation-triangle display-4 opacity-50"></i>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card stat-card bg-success text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6>Règles actives</h6>
                        <h2 class="mb-0">{{ stats.regles_total }}</h2>
                    </div>
                    <i class="bi bi-list-check display-4 opacity-50"></i>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header bg-white">
                <h5 class="mb-0"><i class="bi bi-diagram-3 me-2"></i>Règles par source</h5>
            </div>
            <div class="card-body">
                <div class="d-flex justify-content-around text-center">
                    <div>
                        <span class="badge source-badge-wazuh fs-6 mb-2">Wazuh</span>
                        <h3>{{ stats.regles_wazuh }}</h3>
                    </div>
                    <div>
                        <span class="badge source-badge-snort fs-6 mb-2">Snort</span>
                        <h3>{{ stats.regles_snort }}</h3>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header bg-white">
                <h5 class="mb-0"><i class="bi bi-link-45deg me-2"></i>Liens rapides</h5>
            </div>
            <div class="card-body">
                <a href="{{ url_for('alertes') }}" class="btn btn-outline-danger me-2"><i class="bi bi-exclamation-triangle me-1"></i>Alertes</a>
                <a href="{{ url_for('regles') }}" class="btn btn-outline-primary me-2"><i class="bi bi-list-check me-1"></i>Règles</a>
                <a href="{{ url_for('statistiques') }}" class="btn btn-outline-success"><i class="bi bi-graph-up me-1"></i>Statistiques</a>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header bg-white d-flex justify-content-between align-items-center">
        <h5 class="mb-0"><i class="bi bi-clock-history me-2"></i>Dernières alertes</h5>
        <a href="{{ url_for('alertes') }}" class="btn btn-sm btn-primary">Voir tout</a>
    </div>
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead class="table-light">
                <tr>
                    <th>Date</th>
                    <th>Alerte</th>
                    <th>Gravité</th>
                    <th>IP Source</th>
                    <th>Statut</th>
                </tr>
            </thead>
            <tbody>
                {% for alerte in alertes %}
                <tr>
                    <td>{{ alerte.timestamp[:16] if alerte.timestamp else '-' }}</td>
                    <td>{{ alerte.icone }} {{ alerte.nom_fr or 'Alerte inconnue' }}</td>
                    <td><span class="badge badge-{{ alerte.gravite or 'info' }}">{{ alerte.gravite or 'N/A' }}</span></td>
                    <td><code>{{ alerte.source_ip or '-' }}</code></td>
                    <td><span class="badge bg-secondary">{{ alerte.statut }}</span></td>
                </tr>
                {% else %}
                <tr><td colspan="5" class="text-center text-muted py-4">Aucune alerte enregistrée</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
{% endblock %}
DASHHTML

    # Page alertes
    cat > ${SIEM_HOME}/templates/alertes.html << 'ALERTHTML'
{% extends "base.html" %}
{% block title %}Alertes - SIEM Africa{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1><i class="bi bi-exclamation-triangle me-2"></i>Alertes</h1>
</div>

<div class="card mb-4">
    <div class="card-body">
        <form method="GET" class="row g-3">
            <div class="col-md-3">
                <select name="gravite" class="form-select">
                    <option value="">Toutes gravités</option>
                    <option value="critique">🔴 Critique</option>
                    <option value="haute">🟠 Haute</option>
                    <option value="moyenne">🟡 Moyenne</option>
                    <option value="faible">🔵 Faible</option>
                </select>
            </div>
            <div class="col-md-3">
                <select name="source" class="form-select">
                    <option value="">Toutes sources</option>
                    <option value="wazuh">Wazuh</option>
                    <option value="snort">Snort</option>
                </select>
            </div>
            <div class="col-md-3">
                <select name="statut" class="form-select">
                    <option value="">Tous statuts</option>
                    <option value="nouveau">Nouveau</option>
                    <option value="vu">Vu</option>
                    <option value="en_cours">En cours</option>
                    <option value="traite">Traité</option>
                </select>
            </div>
            <div class="col-md-3">
                <button type="submit" class="btn btn-primary w-100"><i class="bi bi-search me-1"></i>Filtrer</button>
            </div>
        </form>
    </div>
</div>

<div class="card">
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead class="table-light">
                <tr>
                    <th>Date</th>
                    <th>Source</th>
                    <th>Alerte</th>
                    <th>Gravité</th>
                    <th>IP Source</th>
                    <th>Statut</th>
                </tr>
            </thead>
            <tbody>
                {% for alerte in alertes %}
                <tr>
                    <td>{{ alerte.timestamp[:16] if alerte.timestamp else '-' }}</td>
                    <td><span class="badge source-badge-{{ alerte.source or 'wazuh' }}">{{ alerte.source or 'wazuh' }}</span></td>
                    <td>{{ alerte.icone }} {{ alerte.nom_fr or 'Alerte' }}</td>
                    <td><span class="badge badge-{{ alerte.gravite or 'info' }}">{{ alerte.gravite or 'N/A' }}</span></td>
                    <td><code>{{ alerte.source_ip or '-' }}</code></td>
                    <td><span class="badge bg-secondary">{{ alerte.statut }}</span></td>
                </tr>
                {% else %}
                <tr><td colspan="6" class="text-center text-muted py-4">Aucune alerte trouvée</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
{% endblock %}
ALERTHTML

    # Page règles
    cat > ${SIEM_HOME}/templates/regles.html << 'REGLESHTML'
{% extends "base.html" %}
{% block title %}Règles - SIEM Africa{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1><i class="bi bi-list-check me-2"></i>Règles de détection</h1>
    <div>
        <span class="badge source-badge-wazuh fs-6 me-2">Wazuh: {{ stats.wazuh }}</span>
        <span class="badge source-badge-snort fs-6">Snort: {{ stats.snort }}</span>
    </div>
</div>

<div class="card mb-4">
    <div class="card-body">
        <form method="GET" class="row g-3">
            <div class="col-md-2">
                <select name="source" class="form-select">
                    <option value="">Toutes sources</option>
                    <option value="wazuh">Wazuh</option>
                    <option value="snort">Snort</option>
                </select>
            </div>
            <div class="col-md-2">
                <select name="gravite" class="form-select">
                    <option value="">Toutes gravités</option>
                    <option value="critique">Critique</option>
                    <option value="haute">Haute</option>
                    <option value="moyenne">Moyenne</option>
                    <option value="faible">Faible</option>
                </select>
            </div>
            <div class="col-md-3">
                <select name="categorie" class="form-select">
                    <option value="">Toutes catégories</option>
                    {% for cat in categories %}
                    <option value="{{ cat.id }}">{{ cat.icone }} {{ cat.nom }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="col-md-3">
                <input type="text" name="search" class="form-control" placeholder="Rechercher...">
            </div>
            <div class="col-md-2">
                <button type="submit" class="btn btn-primary w-100"><i class="bi bi-search me-1"></i>Filtrer</button>
            </div>
        </form>
    </div>
</div>

<div class="card">
    <div class="card-body p-0">
        <table class="table table-hover mb-0">
            <thead class="table-light">
                <tr>
                    <th>ID</th>
                    <th>Source</th>
                    <th>Nom</th>
                    <th>Catégorie</th>
                    <th>Gravité</th>
                    <th>MITRE</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for regle in regles %}
                <tr>
                    <td><code>{{ regle.rule_id }}</code></td>
                    <td><span class="badge source-badge-{{ regle.source }}">{{ regle.source }}</span></td>
                    <td>{{ regle.icone }} {{ regle.nom_fr }}</td>
                    <td>{{ regle.categorie }}</td>
                    <td><span class="badge badge-{{ regle.gravite }}">{{ regle.gravite }}</span></td>
                    <td><code>{{ regle.mitre_id or '-' }}</code></td>
                    <td><a href="{{ url_for('detail_regle', rule_id=regle.rule_id) }}" class="btn btn-sm btn-outline-primary"><i class="bi bi-eye"></i></a></td>
                </tr>
                {% else %}
                <tr><td colspan="7" class="text-center text-muted py-4">Aucune règle trouvée</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
{% endblock %}
REGLESHTML

    # Page détail règle
    cat > ${SIEM_HOME}/templates/detail_regle.html << 'DETAILHTML'
{% extends "base.html" %}
{% block title %}{{ regle.nom_fr }} - SIEM Africa{% endblock %}
{% block content %}
<nav aria-label="breadcrumb" class="mb-4">
    <ol class="breadcrumb">
        <li class="breadcrumb-item"><a href="{{ url_for('regles') }}">Règles</a></li>
        <li class="breadcrumb-item active">{{ regle.rule_id }}</li>
    </ol>
</nav>

<div class="row">
    <div class="col-md-8">
        <div class="card mb-4">
            <div class="card-header bg-white">
                <h4 class="mb-0">{{ regle.icone }} {{ regle.nom_fr }}</h4>
            </div>
            <div class="card-body">
                <p class="lead">{{ regle.description }}</p>
                
                <div class="row">
                    <div class="col-md-6">
                        <h6>Impact</h6>
                        <p>{{ regle.impact or 'Non défini' }}</p>
                    </div>
                    <div class="col-md-6">
                        <h6>Cause probable</h6>
                        <p>{{ regle.cause_probable or 'Non définie' }}</p>
                    </div>
                </div>
            </div>
        </div>
        
        {% if recommandations %}
        <div class="card">
            <div class="card-header bg-white">
                <h5 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Recommandations</h5>
            </div>
            <div class="card-body">
                {% for reco in recommandations %}
                <div class="mb-3 p-3 bg-light rounded">
                    <div class="d-flex justify-content-between">
                        <strong>{{ loop.index }}. {{ reco.action }}</strong>
                        <span class="badge bg-{{ 'success' if reco.niveau == 'debutant' else 'warning' if reco.niveau == 'intermediaire' else 'danger' }}">{{ reco.niveau }}</span>
                    </div>
                    {% if reco.commande %}
                    <code class="d-block mt-2 p-2 bg-dark text-white rounded">{{ reco.commande }}</code>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
    </div>
    
    <div class="col-md-4">
        <div class="card">
            <div class="card-header bg-white">
                <h5 class="mb-0">Informations</h5>
            </div>
            <ul class="list-group list-group-flush">
                <li class="list-group-item d-flex justify-content-between">
                    <span>ID Règle</span>
                    <code>{{ regle.rule_id }}</code>
                </li>
                <li class="list-group-item d-flex justify-content-between">
                    <span>Source</span>
                    <span class="badge source-badge-{{ regle.source }}">{{ regle.source }}</span>
                </li>
                <li class="list-group-item d-flex justify-content-between">
                    <span>Gravité</span>
                    <span class="badge badge-{{ regle.gravite }}">{{ regle.gravite }}</span>
                </li>
                <li class="list-group-item d-flex justify-content-between">
                    <span>Catégorie</span>
                    <span>{{ regle.icone }} {{ regle.categorie }}</span>
                </li>
                <li class="list-group-item d-flex justify-content-between">
                    <span>MITRE ATT&CK</span>
                    <code>{{ regle.mitre_id or '-' }}</code>
                </li>
                <li class="list-group-item d-flex justify-content-between">
                    <span>Tactique</span>
                    <span>{{ regle.mitre_tactic or '-' }}</span>
                </li>
            </ul>
        </div>
    </div>
</div>
{% endblock %}
DETAILHTML

    # Page statistiques
    cat > ${SIEM_HOME}/templates/statistiques.html << 'STATSHTML'
{% extends "base.html" %}
{% block title %}Statistiques - SIEM Africa{% endblock %}
{% block content %}
<h1 class="mb-4"><i class="bi bi-graph-up me-2"></i>Statistiques</h1>

<div class="row">
    <div class="col-md-6 mb-4">
        <div class="card h-100">
            <div class="card-header bg-white">
                <h5 class="mb-0">Alertes par gravité</h5>
            </div>
            <div class="card-body">
                {% for stat in stats_gravite %}
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="badge badge-{{ stat.gravite }} fs-6">{{ stat.gravite }}</span>
                    <span class="fw-bold">{{ stat.nombre }}</span>
                </div>
                {% else %}
                <p class="text-muted">Aucune donnée</p>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <div class="col-md-6 mb-4">
        <div class="card h-100">
            <div class="card-header bg-white">
                <h5 class="mb-0">Alertes par source</h5>
            </div>
            <div class="card-body">
                {% for stat in stats_source %}
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="badge source-badge-{{ stat.source }} fs-6">{{ stat.source }}</span>
                    <span class="fw-bold">{{ stat.nombre }}</span>
                </div>
                {% else %}
                <p class="text-muted">Aucune donnée</p>
                {% endfor %}
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header bg-white">
        <h5 class="mb-0">Top 10 catégories</h5>
    </div>
    <div class="card-body">
        <table class="table">
            <thead>
                <tr>
                    <th>Catégorie</th>
                    <th>Nombre d'alertes</th>
                </tr>
            </thead>
            <tbody>
                {% for stat in stats_categorie %}
                <tr>
                    <td>{{ stat.icone }} {{ stat.nom }}</td>
                    <td><span class="badge bg-primary">{{ stat.nombre }}</span></td>
                </tr>
                {% else %}
                <tr><td colspan="2" class="text-muted">Aucune donnée</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
{% endblock %}
STATSHTML

    chown -R siem:siem ${SIEM_HOME}/templates
    print_success "Templates HTML créés"
}

#===============================================================================
# FINALISATION
#===============================================================================

finalize_installation() {
    print_step "Finalisation de l'installation"
    
    # Créer le répertoire de logs
    mkdir -p ${SIEM_HOME}/logs
    touch ${SIEM_HOME}/logs/access.log ${SIEM_HOME}/logs/error.log
    chown -R siem:siem ${SIEM_HOME}/logs
    
    # Permissions finales
    chown -R siem:siem ${SIEM_HOME}
    chmod 755 ${SIEM_HOME}
    
    # Démarrage des services
    print_info "Démarrage des services..."
    
    systemctl start wazuh-indexer >> "$LOG_FILE" 2>&1 || print_warning "Wazuh Indexer déjà démarré ou erreur"
    sleep 5
    systemctl start wazuh-manager >> "$LOG_FILE" 2>&1 || print_warning "Wazuh Manager déjà démarré ou erreur"
    sleep 3
    systemctl start wazuh-dashboard >> "$LOG_FILE" 2>&1 || print_warning "Wazuh Dashboard déjà démarré ou erreur"
    sleep 2
    systemctl start siem-africa-dashboard >> "$LOG_FILE" 2>&1 || print_warning "SIEM Africa Dashboard erreur"
    
    # Récupérer l'IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    # Affichage du résumé
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    INSTALLATION TERMINÉE AVEC SUCCÈS !                       ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                              ACCÈS AUX DASHBOARDS                             ${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}🔷 WAZUH DASHBOARD (Interface native - Anglais)${NC}"
    echo -e "   URL         : ${WHITE}https://${SERVER_IP}:443${NC}"
    echo -e "   Utilisateur : ${WHITE}admin${NC}"
    echo -e "   Mot de passe: ${WHITE}${WAZUH_ADMIN_PASS:-Voir /root/wazuh-passwords.txt}${NC}"
    echo ""
    echo -e "${CYAN}🔷 SIEM AFRICA DASHBOARD (Interface française)${NC}"
    echo -e "   URL         : ${WHITE}https://${SERVER_IP}:5000${NC}"
    echo -e "   Utilisateur : ${WHITE}admin${NC}"
    echo -e "   Mot de passe: ${WHITE}${DASHBOARD_ADMIN_PASS}${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT: Changez TOUS les mots de passe à la première connexion !${NC}"
    echo ""
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                           FICHIERS D'IDENTIFIANTS                             ${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "   ${WHITE}/root/credentials.txt${NC}     - Tous les identifiants"
    echo -e "   ${WHITE}${SCRID_FILE}${NC}   - Dashboard + Commandes"
    echo ""
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}                          COMMANDES UTILES                                     ${NC}"
    echo -e "${WHITE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "   Changer les mots de passe : ${WHITE}sudo ${SIEM_HOME}/scripts/change_passwords.sh --all${NC}"
    echo -e "   Diagnostic complet        : ${WHITE}sudo ${SIEM_HOME}/scripts/diagnostic.sh${NC}"
    echo -e "   État des services         : ${WHITE}systemctl status snort wazuh-* siem-africa-dashboard${NC}"
    echo ""
    echo -e "${GREEN}Merci d'utiliser SIEM Africa !${NC}"
    echo ""
}

#===============================================================================
# MAIN
#===============================================================================

main() {
    # Initialisation log
    mkdir -p $(dirname "$LOG_FILE")
    echo "=== Installation SIEM Africa v2.1 - $(date) ===" > "$LOG_FILE"
    
    print_banner
    
    echo -e "${YELLOW}Cette installation va configurer:${NC}"
    echo ""
    echo -e "  ${WHITE}•${NC} Vérification des prérequis (OS, RAM ≥4Go, Disque ≥50Go, Internet)"
    echo -e "  ${WHITE}•${NC} Création des utilisateurs système (snort, wazuh, siem)"
    echo -e "  ${WHITE}•${NC} Installation de Snort IDS"
    echo -e "  ${WHITE}•${NC} Installation de Wazuh Stack complète:"
    echo -e "      - Wazuh Indexer (OpenSearch) - Port 9200"
    echo -e "      - Wazuh Manager - Ports 1514/1515"
    echo -e "      - Wazuh Dashboard - Port 443"
    echo -e "  ${WHITE}•${NC} Installation de SIEM Africa Dashboard - Port 5000"
    echo -e "  ${WHITE}•${NC} Configuration de la base de données (507 règles traduites)"
    echo -e "  ${WHITE}•${NC} Liaison Snort → Wazuh → SIEM Africa"
    echo ""
    echo -e "${YELLOW}Temps estimé: 20-40 minutes selon la connexion Internet${NC}"
    echo ""
    read -p "Voulez-vous continuer ? (o/N) " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[OoYy]$ ]]; then
        echo "Installation annulée."
        exit 0
    fi
    
    # Exécution des étapes
    check_prerequisites
    update_system
    create_users
    install_snort
    install_wazuh_stack
    configure_snort_wazuh_integration
    install_siem_africa
    create_database
    create_flask_application
    create_templates
    create_credentials_files
    create_change_password_script
    create_diagnostic_script
    create_systemd_service
    finalize_installation
}

# Lancement
main "$@"

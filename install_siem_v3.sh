#!/bin/bash

#===============================================================================
#
#          FILE: install_siem_v3.sh
#
#         USAGE: curl -sL https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main/install_siem_v3.sh | sudo bash
#
#   DESCRIPTION: Installation automatique de Snort IDS + Wazuh SIEM
#                Avec création des utilisateurs et fichier credentials
#
#   OBJECTIFS COUVERTS :
#   1. Créer utilisateur Snort (sudo)
#   2. Créer utilisateur Wazuh (sudo)
#   3. Installer les dépendances
#   4. Installer Snort
#   5. Installer Wazuh (Manager, Indexer, Dashboard)
#   6. Lier Snort à Wazuh
#   7. Centraliser les credentials dans un fichier
#
#        AUTHOR: SIEM Africa Team
#       VERSION: 3.0
#
#===============================================================================

set -e

#---------------------------------------
# COULEURS
#---------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

#---------------------------------------
# VARIABLES
#---------------------------------------
LOG_FILE="/var/log/siem-install.log"
WAZUH_VERSION="4.7"
SNORT_CONF="/etc/snort/snort.conf"
MIN_RAM=4
MIN_DISK=30
RETRY_COUNT=3

# CREDENTIALS PAR DÉFAUT
SNORT_USER="snort"
SNORT_PASSWORD="snort123"
WAZUH_USER="wazuh"
WAZUH_PASSWORD="wazuh123"
CREDENTIALS_FILE="/root/siem_credentials.txt"

#---------------------------------------
# FONCTIONS UTILITAIRES
#---------------------------------------
log() {
    echo -e "$1" | tee -a $LOG_FILE
}

log_success() {
    log "${GREEN}[✓]${NC} $1"
}

log_error() {
    log "${RED}[✗]${NC} $1"
}

log_info() {
    log "${CYAN}[i]${NC} $1"
}

log_warning() {
    log "${YELLOW}[!]${NC} $1"
}

log_step() {
    log "${BLUE}[ÉTAPE $1]${NC} $2"
}

#---------------------------------------
# BANNIÈRE
#---------------------------------------
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║     🛡️  SNORT + WAZUH - Installation Automatique v3.0           ║"
    echo "║                                                                  ║"
    echo "║     Package de sécurité pour entreprises                        ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

#---------------------------------------
# VÉRIFICATION ROOT
#---------------------------------------
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Ce script doit être exécuté en tant que root (sudo)"
        exit 1
    fi
    log_success "Exécution en tant que root"
}

#---------------------------------------
# VÉRIFICATION OS
#---------------------------------------
check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Impossible de détecter l'OS"
        exit 1
    fi

    case $OS in
        ubuntu)
            if [[ "$VERSION" != "20.04" && "$VERSION" != "22.04" && "$VERSION" != "24.04" ]]; then
                log_warning "Ubuntu $VERSION détecté. Versions recommandées: 20.04, 22.04, 24.04"
            else
                log_success "OS compatible: Ubuntu $VERSION"
            fi
            ;;
        debian)
            if [[ "$VERSION" != "11" && "$VERSION" != "12" ]]; then
                log_warning "Debian $VERSION détecté. Versions recommandées: 11, 12"
            else
                log_success "OS compatible: Debian $VERSION"
            fi
            ;;
        *)
            log_error "OS non supporté: $OS. Utilisez Ubuntu ou Debian."
            exit 1
            ;;
    esac
}

#---------------------------------------
# VÉRIFICATION RESSOURCES
#---------------------------------------
check_resources() {
    log_info "Vérification des ressources système..."
    
    # RAM
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM" -lt "$MIN_RAM" ]; then
        log_error "RAM insuffisante: ${TOTAL_RAM}Go (minimum: ${MIN_RAM}Go)"
        exit 1
    fi
    log_success "RAM: ${TOTAL_RAM}Go (minimum: ${MIN_RAM}Go)"
    
    # Disque
    AVAILABLE_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$AVAILABLE_DISK" -lt "$MIN_DISK" ]; then
        log_error "Espace disque insuffisant: ${AVAILABLE_DISK}Go (minimum: ${MIN_DISK}Go)"
        exit 1
    fi
    log_success "Disque disponible: ${AVAILABLE_DISK}Go (minimum: ${MIN_DISK}Go)"
    
    # CPU
    CPU_CORES=$(nproc)
    log_success "CPU: ${CPU_CORES} cœurs"
}

#---------------------------------------
# VÉRIFICATION RÉSEAU
#---------------------------------------
check_network() {
    log_info "Vérification de la connexion Internet..."
    
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log_error "Pas de connexion Internet (ping 8.8.8.8 échoué)"
        exit 1
    fi
    
    if ! ping -c 1 google.com &> /dev/null; then
        log_warning "Problème DNS détecté. Correction automatique..."
        echo "nameserver 8.8.8.8" | tee /etc/resolv.conf > /dev/null
        echo "nameserver 8.8.4.4" | tee -a /etc/resolv.conf > /dev/null
        
        if ! ping -c 1 google.com &> /dev/null; then
            log_error "Impossible de résoudre les noms de domaine"
            exit 1
        fi
    fi
    
    log_success "Connexion Internet OK"
}

#---------------------------------------
# NETTOYAGE INSTALLATIONS PRÉCÉDENTES
#---------------------------------------
cleanup_previous() {
    log_info "Nettoyage des installations précédentes..."
    
    systemctl stop wazuh-manager 2>/dev/null || true
    systemctl stop wazuh-indexer 2>/dev/null || true
    systemctl stop wazuh-dashboard 2>/dev/null || true
    systemctl stop filebeat 2>/dev/null || true
    systemctl stop snort 2>/dev/null || true
    
    apt remove --purge wazuh-manager wazuh-indexer wazuh-dashboard filebeat snort -y 2>/dev/null || true
    
    rm -rf /var/ossec 2>/dev/null || true
    rm -rf /etc/wazuh-indexer 2>/dev/null || true
    rm -rf /var/lib/wazuh-indexer 2>/dev/null || true
    rm -rf /usr/share/wazuh-indexer 2>/dev/null || true
    rm -rf /etc/filebeat 2>/dev/null || true
    rm -rf /var/lib/filebeat 2>/dev/null || true
    rm -rf /etc/snort 2>/dev/null || true
    rm -rf /var/log/snort 2>/dev/null || true
    
    rm -f wazuh-install.sh 2>/dev/null || true
    rm -f wazuh-install-files.tar 2>/dev/null || true
    rm -f /var/log/wazuh-install.log 2>/dev/null || true
    
    apt autoremove -y 2>/dev/null || true
    apt clean 2>/dev/null || true
    
    log_success "Nettoyage terminé"
}

#---------------------------------------
# MISE À JOUR SYSTÈME
#---------------------------------------
update_system() {
    log_info "Mise à jour du système..."
    
    apt update -qq
    DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq
    
    log_success "Système mis à jour"
}

#---------------------------------------
# INSTALLATION DÉPENDANCES
#---------------------------------------
install_dependencies() {
    log_info "Installation des dépendances..."
    
    DEBIAN_FRONTEND=noninteractive apt install -y -qq \
        curl \
        wget \
        gnupg \
        apt-transport-https \
        lsb-release \
        ca-certificates \
        software-properties-common \
        net-tools \
        jq
    
    log_success "Dépendances installées"
}

#---------------------------------------
# OBJECTIF 1 : CRÉER UTILISATEUR SNORT
#---------------------------------------
create_snort_user() {
    log_step "1/7" "CRÉATION UTILISATEUR SNORT"
    
    if id "$SNORT_USER" &>/dev/null; then
        log_info "Utilisateur $SNORT_USER existe déjà"
    else
        useradd -m -s /bin/bash -c "Utilisateur Snort IDS" $SNORT_USER
        echo "$SNORT_USER:$SNORT_PASSWORD" | chpasswd
        log_success "Utilisateur $SNORT_USER créé"
    fi
    
    # Ajouter au groupe sudo
    usermod -aG sudo $SNORT_USER 2>/dev/null || true
    log_success "Utilisateur $SNORT_USER ajouté au groupe sudo"
}

#---------------------------------------
# OBJECTIF 2 : CRÉER UTILISATEUR WAZUH
#---------------------------------------
create_wazuh_user() {
    log_step "2/7" "CRÉATION UTILISATEUR WAZUH"
    
    if id "$WAZUH_USER" &>/dev/null; then
        log_info "Utilisateur $WAZUH_USER existe déjà"
    else
        useradd -m -s /bin/bash -c "Utilisateur Wazuh SIEM" $WAZUH_USER
        echo "$WAZUH_USER:$WAZUH_PASSWORD" | chpasswd
        log_success "Utilisateur $WAZUH_USER créé"
    fi
    
    # Ajouter au groupe sudo
    usermod -aG sudo $WAZUH_USER 2>/dev/null || true
    log_success "Utilisateur $WAZUH_USER ajouté au groupe sudo"
}

#---------------------------------------
# OBJECTIF 4 : INSTALLATION SNORT
#---------------------------------------
install_snort() {
    log_step "3/7" "INSTALLATION DE SNORT"
    
    DEBIAN_FRONTEND=noninteractive apt install -y snort 2>/dev/null || {
        log_warning "Snort non disponible, tentative alternative..."
        add-apt-repository ppa:oisf/suricata-stable -y 2>/dev/null || true
        apt update -qq
        DEBIAN_FRONTEND=noninteractive apt install -y snort 2>/dev/null || {
            log_error "Impossible d'installer Snort"
            return 1
        }
    }
    
    log_success "Snort installé"
    return 0
}

#---------------------------------------
# CONFIGURATION SNORT
#---------------------------------------
configure_snort() {
    log_step "4/7" "CONFIGURATION DE SNORT"
    
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    
    if [ -z "$LOCAL_NET" ]; then
        LOCAL_NET="192.168.1.0/24"
    fi
    
    log_info "Réseau détecté: $LOCAL_NET"
    
    if [ -f "$SNORT_CONF" ]; then
        cp $SNORT_CONF ${SNORT_CONF}.backup
        sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $LOCAL_NET|g" $SNORT_CONF
        sed -i "s|var HOME_NET any|var HOME_NET $LOCAL_NET|g" $SNORT_CONF
    fi
    
    mkdir -p /var/log/snort
    mkdir -p /etc/snort/rules
    
    # Donner les permissions à l'utilisateur snort
    chown -R $SNORT_USER:$SNORT_USER /var/log/snort
    chown -R $SNORT_USER:$SNORT_USER /etc/snort 2>/dev/null || true
    chmod -R 755 /var/log/snort
    
    # Créer service systemd
    if [ ! -f /etc/systemd/system/snort.service ]; then
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        
        cat > /etc/systemd/system/snort.service << EOF
[Unit]
Description=Snort IDS
After=network.target

[Service]
Type=simple
User=$SNORT_USER
ExecStart=/usr/sbin/snort -q -c /etc/snort/snort.conf -i $INTERFACE -A fast
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    systemctl enable snort 2>/dev/null || true
    systemctl start snort 2>/dev/null || log_warning "Snort n'a pas pu démarrer"
    
    log_success "Snort configuré (HOME_NET: $LOCAL_NET)"
    return 0
}

#---------------------------------------
# OBJECTIF 5 : INSTALLATION WAZUH
#---------------------------------------
install_wazuh() {
    log_step "5/7" "INSTALLATION DE WAZUH $WAZUH_VERSION"
    
    log_info "Cette étape peut prendre 10-20 minutes..."
    
    curl -sO https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh
    
    if [ ! -f "wazuh-install.sh" ]; then
        log_error "Impossible de télécharger le script Wazuh"
        return 1
    fi
    
    chmod +x wazuh-install.sh
    
    local attempt=1
    while [ $attempt -le $RETRY_COUNT ]; do
        log_info "Tentative d'installation $attempt/$RETRY_COUNT..."
        
        if bash wazuh-install.sh -a -i >> $LOG_FILE 2>&1; then
            log_success "Wazuh installé avec succès!"
            
            # Donner les permissions à l'utilisateur wazuh
            chown -R $WAZUH_USER:$WAZUH_USER /var/ossec 2>/dev/null || true
            
            return 0
        fi
        
        log_warning "Tentative $attempt échouée"
        
        if [ $attempt -lt $RETRY_COUNT ]; then
            log_info "Nettoyage avant nouvelle tentative..."
            systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
            apt remove --purge wazuh-manager wazuh-indexer wazuh-dashboard -y 2>/dev/null || true
            rm -rf /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer 2>/dev/null || true
            rm -f wazuh-install-files.tar 2>/dev/null || true
            sleep 5
        fi
        
        attempt=$((attempt + 1))
    done
    
    log_error "Installation de Wazuh échouée après $RETRY_COUNT tentatives"
    return 1
}

#---------------------------------------
# OBJECTIF 6 : INTÉGRATION SNORT-WAZUH
#---------------------------------------
configure_integration() {
    log_step "6/7" "INTÉGRATION SNORT-WAZUH"
    
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    
    if [ -f "$OSSEC_CONF" ]; then
        if ! grep -q "/var/log/snort/alert" $OSSEC_CONF; then
            sed -i '/<\/ossec_config>/i \
  <localfile>\
    <log_format>snort-full</log_format>\
    <location>/var/log/snort/alert</location>\
  </localfile>' $OSSEC_CONF
            
            log_success "Intégration Snort-Wazuh configurée"
        else
            log_info "Intégration déjà configurée"
        fi
        
        systemctl restart wazuh-manager 2>/dev/null || true
    else
        log_warning "Fichier ossec.conf non trouvé"
    fi
    
    return 0
}

#---------------------------------------
# OBJECTIF 7 : CRÉER FICHIER CREDENTIALS
#---------------------------------------
create_credentials_file() {
    log_step "7/7" "CRÉATION FICHIER CREDENTIALS"
    
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    HOSTNAME=$(hostname)
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Récupérer le password Wazuh Dashboard
    WAZUH_DASHBOARD_PASS="Voir /root/wazuh-install-files.tar"
    if [ -f "wazuh-install-files.tar" ]; then
        tar -xf wazuh-install-files.tar -C /tmp 2>/dev/null || true
        WAZUH_DASHBOARD_PASS=$(grep -A1 "admin" /tmp/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | tail -1 | tr -d ' ' || echo "Voir /root/wazuh-install-files.tar")
        
        # Copier le fichier tar dans /root
        cp wazuh-install-files.tar /root/ 2>/dev/null || true
    fi
    
    cat > $CREDENTIALS_FILE << EOF
╔══════════════════════════════════════════════════════════════════╗
║                    SIEM CREDENTIALS                              ║
╚══════════════════════════════════════════════════════════════════╝

Date de création : $DATE
Serveur          : $IP_ADDRESS
Hostname         : $HOSTNAME

══════════════════════════════════════════════════════════════════
                    UTILISATEURS SYSTÈME
══════════════════════════════════════════════════════════════════

UTILISATEUR SNORT
-----------------
Username : $SNORT_USER
Password : $SNORT_PASSWORD
Accès    : sudo
Rôle     : Gestion Snort IDS (/etc/snort, /var/log/snort)

UTILISATEUR WAZUH
-----------------
Username : $WAZUH_USER
Password : $WAZUH_PASSWORD
Accès    : sudo
Rôle     : Gestion Wazuh SIEM (/var/ossec)

══════════════════════════════════════════════════════════════════
                    WAZUH DASHBOARD
══════════════════════════════════════════════════════════════════

URL      : https://$IP_ADDRESS
Username : admin
Password : $WAZUH_DASHBOARD_PASS

══════════════════════════════════════════════════════════════════
                    COMMANDES UTILES
══════════════════════════════════════════════════════════════════

Vérifier Snort        : systemctl status snort
Vérifier Wazuh Manager: systemctl status wazuh-manager
Vérifier Wazuh Indexer: systemctl status wazuh-indexer
Vérifier Dashboard    : systemctl status wazuh-dashboard

Logs Snort            : tail -f /var/log/snort/alert
Logs Wazuh            : tail -f /var/ossec/logs/ossec.log

══════════════════════════════════════════════════════════════════
⚠️  IMPORTANT : Changez ces mots de passe en production !
══════════════════════════════════════════════════════════════════
EOF
    
    chmod 600 $CREDENTIALS_FILE
    log_success "Fichier credentials créé: $CREDENTIALS_FILE"
}

#---------------------------------------
# AFFICHER RÉSUMÉ
#---------------------------------------
show_summary() {
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║     ✓ INSTALLATION TERMINÉE AVEC SUCCÈS !                       ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    UTILISATEURS CRÉÉS                              ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}Utilisateur Snort${NC}"
    echo -e "  Username : ${GREEN}$SNORT_USER${NC}"
    echo -e "  Password : ${GREEN}$SNORT_PASSWORD${NC}"
    echo ""
    echo -e "  ${YELLOW}Utilisateur Wazuh${NC}"
    echo -e "  Username : ${GREEN}$WAZUH_USER${NC}"
    echo -e "  Password : ${GREEN}$WAZUH_PASSWORD${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    WAZUH DASHBOARD                                 ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  URL         : ${GREEN}https://${IP_ADDRESS}${NC}"
    echo -e "  Utilisateur : ${YELLOW}admin${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                    FICHIER CREDENTIALS                             ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}$CREDENTIALS_FILE${NC}"
    echo ""
    echo -e "  Pour voir les credentials : ${YELLOW}cat $CREDENTIALS_FILE${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}Note: Le certificat SSL est auto-signé.${NC}"
    echo ""
}

#---------------------------------------
# AFFICHER ERREUR
#---------------------------------------
show_error() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     ✗ INSTALLATION ÉCHOUÉE                                      ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Consultez: $LOG_FILE"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    touch $LOG_FILE
    
    show_banner
    
    log_info "Début de l'installation - $(date)"
    echo ""
    
    # Vérifications
    echo -e "${CYAN}[VÉRIFICATIONS]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_root
    check_os
    check_resources
    check_network
    echo ""
    
    # Préparation
    echo -e "${CYAN}[PRÉPARATION]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    cleanup_previous
    update_system
    install_dependencies
    echo ""
    
    # Installation
    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    
    # Objectif 1: Créer utilisateur Snort
    create_snort_user
    echo ""
    
    # Objectif 2: Créer utilisateur Wazuh
    create_wazuh_user
    echo ""
    
    # Objectif 4: Installer Snort
    if ! install_snort; then
        show_error
        exit 1
    fi
    
    # Configurer Snort
    if ! configure_snort; then
        log_warning "Problème configuration Snort"
    fi
    echo ""
    
    # Objectif 5: Installer Wazuh
    if ! install_wazuh; then
        show_error
        exit 1
    fi
    echo ""
    
    # Objectif 6: Intégration Snort-Wazuh
    configure_integration
    echo ""
    
    # Objectif 7: Créer fichier credentials
    create_credentials_file
    echo ""
    
    # Résumé
    show_summary
    
    log_info "Installation terminée - $(date)"
}

# Exécuter
main "$@"

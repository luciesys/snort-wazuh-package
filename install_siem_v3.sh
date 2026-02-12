#!/bin/bash

#===============================================================================
#
#          FILE: install_siem_v3.sh
#
#         USAGE: curl -sL https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main/install_siem_v3.sh | sudo bash
#
#   DESCRIPTION: Installation automatique de Snort IDS + Wazuh SIEM
#
#   COMPORTEMENT :
#   - Si prérequis non rempli → ARRÊT IMMÉDIAT
#   - Si pas d'Internet → ARRÊT IMMÉDIAT
#   - Si Snort/Wazuh déjà installé → SUPPRIME TOUT ET RÉINSTALLE
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

SNORT_USER="snort"
SNORT_PASSWORD="snort123"
WAZUH_USER="wazuh"
WAZUH_PASSWORD="wazuh123"
CREDENTIALS_FILE="/root/siem_credentials.txt"

#---------------------------------------
# FONCTIONS
#---------------------------------------
log() { echo -e "$1" | tee -a $LOG_FILE; }
log_success() { log "${GREEN}[✓]${NC} $1"; }
log_error() { log "${RED}[✗]${NC} $1"; }
log_info() { log "${CYAN}[i]${NC} $1"; }
log_warning() { log "${YELLOW}[!]${NC} $1"; }
log_step() { log "${BLUE}[ÉTAPE $1]${NC} $2"; }

abort() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║     ✗ INSTALLATION ARRÊTÉE                                      ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}Raison: $1${NC}"
    echo -e "  Log: $LOG_FILE"
    echo ""
    exit 1
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║     🛡️  SNORT + WAZUH - Installation Automatique v3.0           ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        abort "Ce script doit être exécuté en tant que root (sudo)"
    fi
    log_success "Exécution en tant que root"
}

check_os() {
    [ ! -f /etc/os-release ] && abort "Impossible de détecter l'OS"
    . /etc/os-release
    case $ID in
        ubuntu)
            [[ "$VERSION_ID" != "20.04" && "$VERSION_ID" != "22.04" && "$VERSION_ID" != "24.04" ]] && abort "Ubuntu $VERSION_ID non supporté. Versions acceptées: 20.04, 22.04, 24.04"
            log_success "OS compatible: Ubuntu $VERSION_ID"
            ;;
        debian)
            [[ "$VERSION_ID" != "11" && "$VERSION_ID" != "12" ]] && abort "Debian $VERSION_ID non supporté. Versions acceptées: 11, 12"
            log_success "OS compatible: Debian $VERSION_ID"
            ;;
        *) abort "OS non supporté: $ID. Seuls Ubuntu et Debian sont acceptés." ;;
    esac
}

check_ram() {
    TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
    [ "$TOTAL_RAM" -lt "$MIN_RAM" ] && abort "RAM insuffisante: ${TOTAL_RAM}Go (minimum: ${MIN_RAM}Go)"
    log_success "RAM: ${TOTAL_RAM}Go"
}

check_disk() {
    AVAILABLE_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    [ "$AVAILABLE_DISK" -lt "$MIN_DISK" ] && abort "Disque insuffisant: ${AVAILABLE_DISK}Go (minimum: ${MIN_DISK}Go)"
    log_success "Disque: ${AVAILABLE_DISK}Go"
}

check_cpu() {
    CPU_CORES=$(nproc)
    [ "$CPU_CORES" -lt 2 ] && abort "CPU insuffisant: ${CPU_CORES} cœur(s) (minimum: 2)"
    log_success "CPU: ${CPU_CORES} cœurs"
}

check_internet() {
    log_info "Vérification connexion Internet..."
    ping -c 3 8.8.8.8 &>/dev/null || abort "Pas de connexion Internet"
    if ! ping -c 3 google.com &>/dev/null; then
        log_warning "Problème DNS - Correction..."
        echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
        ping -c 3 google.com &>/dev/null || abort "DNS non fonctionnel"
    fi
    curl -s --head --connect-timeout 10 https://packages.wazuh.com &>/dev/null || abort "Impossible d'accéder aux dépôts Wazuh"
    log_success "Connexion Internet OK"
}

cleanup_all() {
    log_info "Nettoyage complet..."
    systemctl stop snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true
    systemctl disable snort wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true
    apt remove --purge -y snort wazuh-manager wazuh-indexer wazuh-dashboard wazuh-agent filebeat 2>/dev/null || true
    rm -rf /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer /usr/share/wazuh-indexer
    rm -rf /etc/filebeat /var/lib/filebeat /etc/snort /var/log/snort
    rm -rf /usr/share/wazuh-dashboard /etc/wazuh-dashboard
    rm -f /root/wazuh-install.sh /root/wazuh-install-files.tar wazuh-install.sh wazuh-install-files.tar
    rm -f /var/log/wazuh-install.log /etc/systemd/system/snort.service
    systemctl daemon-reload
    apt autoremove -y 2>/dev/null || true
    apt clean 2>/dev/null || true
    log_success "Nettoyage terminé"
}

check_existing() {
    log_info "Vérification installations existantes..."
    if dpkg -l | grep -qE "snort|wazuh" 2>/dev/null || [ -d "/etc/snort" ] || [ -d "/var/ossec" ]; then
        log_warning "Installation existante détectée → Suppression et réinstallation"
        cleanup_all
    else
        log_success "Aucune installation existante"
    fi
}

update_system() {
    log_info "Mise à jour système..."
    apt update -qq || abort "Échec mise à jour APT"
    DEBIAN_FRONTEND=noninteractive apt upgrade -y -qq || abort "Échec mise à jour système"
    log_success "Système mis à jour"
}

install_dependencies() {
    log_info "Installation dépendances..."
    DEBIAN_FRONTEND=noninteractive apt install -y -qq curl wget gnupg apt-transport-https lsb-release ca-certificates software-properties-common net-tools jq || abort "Échec installation dépendances"
    log_success "Dépendances installées"
}

create_users() {
    log_step "1/4" "CRÉATION UTILISATEURS"
    for user in $SNORT_USER $WAZUH_USER; do
        pass=$([ "$user" = "$SNORT_USER" ] && echo "$SNORT_PASSWORD" || echo "$WAZUH_PASSWORD")
        if id "$user" &>/dev/null; then
            echo "$user:$pass" | chpasswd
        else
            useradd -m -s /bin/bash "$user" || abort "Impossible de créer $user"
            echo "$user:$pass" | chpasswd
        fi
        usermod -aG sudo "$user" 2>/dev/null || true
    done
    log_success "Utilisateurs snort et wazuh créés"
}

install_snort() {
    log_step "2/4" "INSTALLATION SNORT"
    DEBIAN_FRONTEND=noninteractive apt install -y snort 2>/dev/null || {
        add-apt-repository ppa:oisf/suricata-stable -y 2>/dev/null || true
        apt update -qq
        DEBIAN_FRONTEND=noninteractive apt install -y snort || abort "Impossible d'installer Snort"
    }
    log_success "Snort installé"
}

configure_snort() {
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    [ -z "$LOCAL_NET" ] && LOCAL_NET="192.168.1.0/24"
    [ -f "$SNORT_CONF" ] && sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $LOCAL_NET|g; s|var HOME_NET any|var HOME_NET $LOCAL_NET|g" $SNORT_CONF
    mkdir -p /var/log/snort /etc/snort/rules
    chown -R $SNORT_USER:$SNORT_USER /var/log/snort /etc/snort 2>/dev/null || true
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
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable snort && systemctl start snort 2>/dev/null || true
    log_success "Snort configuré (HOME_NET: $LOCAL_NET)"
}

install_wazuh() {
    log_step "3/4" "INSTALLATION WAZUH $WAZUH_VERSION"
    log_info "Cette étape prend 10-20 minutes..."
    curl -sO https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh || abort "Impossible de télécharger Wazuh"
    chmod +x wazuh-install.sh
    local attempt=1 success=false
    while [ $attempt -le $RETRY_COUNT ]; do
        log_info "Tentative $attempt/$RETRY_COUNT..."
        if bash wazuh-install.sh -a -i >> $LOG_FILE 2>&1; then
            success=true; break
        fi
        log_warning "Tentative $attempt échouée"
        [ $attempt -lt $RETRY_COUNT ] && {
            systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
            apt remove --purge wazuh-manager wazuh-indexer wazuh-dashboard -y 2>/dev/null || true
            rm -rf /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer wazuh-install-files.tar 2>/dev/null || true
            sleep 5
        }
        attempt=$((attempt + 1))
    done
    [ "$success" = false ] && abort "Installation Wazuh échouée après $RETRY_COUNT tentatives"
    log_success "Wazuh installé"
    chown -R $WAZUH_USER:$WAZUH_USER /var/ossec 2>/dev/null || true
    [ -f "wazuh-install-files.tar" ] && cp wazuh-install-files.tar /root/
}

configure_integration() {
    log_step "4/4" "INTÉGRATION SNORT-WAZUH"
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    [ ! -f "$OSSEC_CONF" ] && abort "ossec.conf non trouvé"
    grep -q "/var/log/snort/alert" $OSSEC_CONF || sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>snort-full</log_format>\n    <location>/var/log/snort/alert</location>\n  </localfile>' $OSSEC_CONF
    systemctl restart wazuh-manager || abort "Impossible de redémarrer Wazuh"
    log_success "Intégration configurée"
}

create_credentials_file() {
    log_info "Création fichier credentials..."
    IP=$(hostname -I | awk '{print $1}')
    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    WAZUH_PASS="Voir /root/wazuh-install-files.tar"
    [ -f "/root/wazuh-install-files.tar" ] && {
        tar -xf /root/wazuh-install-files.tar -C /tmp 2>/dev/null
        WAZUH_PASS=$(grep -A1 "admin" /tmp/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | tail -1 | tr -d ' ')
        rm -rf /tmp/wazuh-install-files
    }
    cat > $CREDENTIALS_FILE << EOF
╔══════════════════════════════════════════════════════════════════╗
║                    SIEM CREDENTIALS                              ║
╚══════════════════════════════════════════════════════════════════╝

Date: $DATE | Serveur: $IP

══════════════════════════════════════════════════════════════════
UTILISATEURS SYSTÈME
══════════════════════════════════════════════════════════════════
SNORT  : $SNORT_USER / $SNORT_PASSWORD (sudo)
WAZUH  : $WAZUH_USER / $WAZUH_PASSWORD (sudo)

══════════════════════════════════════════════════════════════════
WAZUH DASHBOARD
══════════════════════════════════════════════════════════════════
URL      : https://$IP
Username : admin
Password : $WAZUH_PASS

══════════════════════════════════════════════════════════════════
⚠️  Changez ces mots de passe en production !
══════════════════════════════════════════════════════════════════
EOF
    chmod 600 $CREDENTIALS_FILE
    log_success "Credentials: $CREDENTIALS_FILE"
}

show_summary() {
    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     ✓ INSTALLATION TERMINÉE AVEC SUCCÈS !                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        ACCÈS WAZUH DASHBOARD                       ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  URL         : ${GREEN}https://${IP}${NC}"
    echo -e "  Utilisateur : ${YELLOW}admin${NC}"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        UTILISATEURS CRÉÉS                          ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  • snort (accès sudo)"
    echo -e "  • wazuh (accès sudo)"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        ÉTAT DES SERVICES                           ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    for s in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet $s 2>/dev/null; then
            echo -e "  $s: ${GREEN}● Actif${NC}"
        else
            echo -e "  $s: ${RED}○ Inactif${NC}"
        fi
    done
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        FICHIER CREDENTIALS                         ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Tous les mots de passe : ${YELLOW}$CREDENTIALS_FILE${NC}"
    echo -e "  Pour afficher          : ${GREEN}cat $CREDENTIALS_FILE${NC}"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                   COMMANDES DE VÉRIFICATION                        ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}Vérifier les services :${NC}"
    echo -e "  systemctl status snort"
    echo -e "  systemctl status wazuh-manager"
    echo -e "  systemctl status wazuh-indexer"
    echo -e "  systemctl status wazuh-dashboard"
    echo ""
    echo -e "  ${YELLOW}Vérifier les ports :${NC}"
    echo -e "  ss -tlnp | grep -E '443|1514|1515|9200|55000'"
    echo ""
    echo -e "  ${YELLOW}Vérifier les logs :${NC}"
    echo -e "  tail -f /var/log/snort/alert"
    echo -e "  tail -f /var/ossec/logs/ossec.log"
    echo ""
    echo -e "  ${YELLOW}Vérifier les utilisateurs :${NC}"
    echo -e "  id snort"
    echo -e "  id wazuh"
    echo ""
    echo -e "  ${YELLOW}Tester le dashboard :${NC}"
    echo -e "  curl -k -s -o /dev/null -w '%{http_code}' https://localhost"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        PORTS UTILISÉS                              ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  443   - Wazuh Dashboard (HTTPS)"
    echo -e "  1514  - Wazuh Agent communication"
    echo -e "  1515  - Wazuh Agent enrollment"
    echo -e "  9200  - Wazuh Indexer"
    echo -e "  55000 - Wazuh API"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        FICHIERS IMPORTANTS                         ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  /root/siem_credentials.txt       - Mots de passe"
    echo -e "  /root/wazuh-install-files.tar    - Fichiers Wazuh"
    echo -e "  /var/ossec/etc/ossec.conf        - Config Wazuh"
    echo -e "  /etc/snort/snort.conf            - Config Snort"
    echo -e "  /var/log/siem-install.log        - Log installation"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}Note: Le certificat SSL est auto-signé.${NC}"
    echo ""
}

main() {
    echo "=== Installation SIEM - $(date) ===" > $LOG_FILE
    show_banner
    
    echo -e "${CYAN}[VÉRIFICATIONS OBLIGATOIRES]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_root; check_os; check_ram; check_disk; check_cpu; check_internet
    echo ""
    
    echo -e "${CYAN}[VÉRIFICATION INSTALLATION EXISTANTE]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_existing
    echo ""
    
    echo -e "${CYAN}[PRÉPARATION]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    update_system; install_dependencies
    echo ""
    
    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    create_users; echo ""
    install_snort; configure_snort; echo ""
    install_wazuh; echo ""
    configure_integration; echo ""
    create_credentials_file; echo ""
    
    show_summary
    log_info "Installation terminée - $(date)"
}

main "$@"

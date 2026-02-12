#!/bin/bash

#===============================================================================
#
#          FILE: install_siem.sh (VERSION AMÉLIORÉE)
#
#         USAGE: curl -sL https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main/install_siem.sh | sudo bash
#
#   DESCRIPTION: Installation automatique de Snort IDS + Wazuh SIEM
#                Version améliorée avec meilleure gestion des erreurs
#
#        AUTHOR: SIEM Africa Team
#       VERSION: 2.0
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
    echo "║     🛡️  SNORT + WAZUH - Installation Automatique v2.0           ║"
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
    
    # Test DNS
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log_error "Pas de connexion Internet (ping 8.8.8.8 échoué)"
        exit 1
    fi
    
    # Test résolution DNS
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
    
    # Arrêter les services
    systemctl stop wazuh-manager 2>/dev/null || true
    systemctl stop wazuh-indexer 2>/dev/null || true
    systemctl stop wazuh-dashboard 2>/dev/null || true
    systemctl stop filebeat 2>/dev/null || true
    systemctl stop snort 2>/dev/null || true
    
    # Désinstaller les paquets
    apt remove --purge wazuh-manager wazuh-indexer wazuh-dashboard filebeat snort -y 2>/dev/null || true
    
    # Supprimer les répertoires
    rm -rf /var/ossec 2>/dev/null || true
    rm -rf /etc/wazuh-indexer 2>/dev/null || true
    rm -rf /var/lib/wazuh-indexer 2>/dev/null || true
    rm -rf /usr/share/wazuh-indexer 2>/dev/null || true
    rm -rf /etc/filebeat 2>/dev/null || true
    rm -rf /var/lib/filebeat 2>/dev/null || true
    rm -rf /etc/snort 2>/dev/null || true
    rm -rf /var/log/snort 2>/dev/null || true
    
    # Supprimer les fichiers d'installation
    rm -f wazuh-install.sh 2>/dev/null || true
    rm -f wazuh-install-files.tar 2>/dev/null || true
    rm -f /var/log/wazuh-install.log 2>/dev/null || true
    
    # Nettoyer APT
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
# INSTALLATION SNORT
#---------------------------------------
install_snort() {
    log_step "1/4" "INSTALLATION DE SNORT"
    
    log_info "Installation de Snort..."
    
    # Installation
    DEBIAN_FRONTEND=noninteractive apt install -y snort 2>/dev/null || {
        # Si snort n'est pas disponible, essayer avec le PPA
        log_warning "Snort non disponible dans les repos par défaut, tentative avec PPA..."
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
    log_step "2/4" "CONFIGURATION DE SNORT"
    
    # Détecter le réseau local
    LOCAL_NET=$(ip route | grep -oP 'src \K[\d.]+' | head -1 | sed 's/\.[0-9]*$/.0\/24/')
    
    if [ -z "$LOCAL_NET" ]; then
        LOCAL_NET="192.168.1.0/24"
    fi
    
    log_info "Réseau détecté: $LOCAL_NET"
    
    # Backup config originale
    if [ -f "$SNORT_CONF" ]; then
        cp $SNORT_CONF ${SNORT_CONF}.backup
    fi
    
    # Configurer HOME_NET
    if [ -f "$SNORT_CONF" ]; then
        sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $LOCAL_NET|g" $SNORT_CONF
        sed -i "s|var HOME_NET any|var HOME_NET $LOCAL_NET|g" $SNORT_CONF
    fi
    
    # Créer répertoires
    mkdir -p /var/log/snort
    mkdir -p /etc/snort/rules
    
    # Permissions
    chmod -R 755 /var/log/snort
    
    # Créer service systemd si n'existe pas
    if [ ! -f /etc/systemd/system/snort.service ]; then
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
        
        cat > /etc/systemd/system/snort.service << EOF
[Unit]
Description=Snort IDS
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/snort -q -c /etc/snort/snort.conf -i $INTERFACE -A fast
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    # Activer et démarrer
    systemctl daemon-reload
    systemctl enable snort 2>/dev/null || true
    systemctl start snort 2>/dev/null || log_warning "Snort n'a pas pu démarrer (sera configuré manuellement)"
    
    log_success "Snort configuré (HOME_NET: $LOCAL_NET)"
    return 0
}

#---------------------------------------
# INSTALLATION WAZUH
#---------------------------------------
install_wazuh() {
    log_step "3/4" "INSTALLATION DE WAZUH $WAZUH_VERSION"
    
    log_info "Cette étape peut prendre 10-20 minutes. Veuillez patienter..."
    
    # Télécharger le script d'installation Wazuh
    curl -sO https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh
    
    if [ ! -f "wazuh-install.sh" ]; then
        log_error "Impossible de télécharger le script Wazuh"
        return 1
    fi
    
    chmod +x wazuh-install.sh
    
    # Installation avec retry
    local attempt=1
    while [ $attempt -le $RETRY_COUNT ]; do
        log_info "Tentative d'installation $attempt/$RETRY_COUNT..."
        
        # Lancer l'installation
        if bash wazuh-install.sh -a -i >> $LOG_FILE 2>&1; then
            log_success "Wazuh installé avec succès!"
            
            # Récupérer le mot de passe admin
            if [ -f "wazuh-install-files.tar" ]; then
                tar -xf wazuh-install-files.tar -C /tmp 2>/dev/null || true
                WAZUH_PASSWORD=$(cat /tmp/wazuh-install-files/wazuh-passwords.txt 2>/dev/null | grep -oP "admin:\s*\K.*" || echo "Voir wazuh-install-files.tar")
            fi
            
            return 0
        fi
        
        log_warning "Tentative $attempt échouée"
        
        # Si ce n'est pas la dernière tentative, nettoyer et réessayer
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
    log_info "Consultez le log: $LOG_FILE"
    log_info "Et le log Wazuh: /var/log/wazuh-install.log"
    return 1
}

#---------------------------------------
# INTÉGRATION SNORT-WAZUH
#---------------------------------------
configure_integration() {
    log_step "4/4" "INTÉGRATION SNORT-WAZUH"
    
    # Configurer Wazuh pour lire les logs Snort
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    
    if [ -f "$OSSEC_CONF" ]; then
        # Vérifier si la config Snort existe déjà
        if ! grep -q "/var/log/snort/alert" $OSSEC_CONF; then
            # Ajouter la configuration Snort avant </ossec_config>
            sed -i '/<\/ossec_config>/i \
  <localfile>\
    <log_format>snort-full</log_format>\
    <location>/var/log/snort/alert</location>\
  </localfile>' $OSSEC_CONF
            
            log_success "Intégration Snort-Wazuh configurée"
        else
            log_info "Intégration déjà configurée"
        fi
        
        # Redémarrer Wazuh Manager
        systemctl restart wazuh-manager 2>/dev/null || true
    else
        log_warning "Fichier ossec.conf non trouvé, intégration manuelle requise"
    fi
    
    return 0
}

#---------------------------------------
# AFFICHER RÉSUMÉ
#---------------------------------------
show_summary() {
    # Obtenir l'IP
    IP_ADDRESS=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║     ✓ INSTALLATION TERMINÉE AVEC SUCCÈS !                       ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                        INFORMATIONS D'ACCÈS                        ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  WAZUH DASHBOARD"
    echo -e "  ───────────────"
    echo -e "  URL         : ${GREEN}https://${IP_ADDRESS}${NC}"
    echo -e "  Utilisateur : ${YELLOW}admin${NC}"
    echo -e "  Mot de passe: ${YELLOW}${WAZUH_PASSWORD:-Voir wazuh-install-files.tar}${NC}"
    echo ""
    echo -e "  SERVICES"
    echo -e "  ────────"
    
    # Vérifier les services
    for service in snort wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo -e "  $service: ${GREEN}● Actif${NC}"
        else
            echo -e "  $service: ${RED}○ Inactif${NC}"
        fi
    done
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}Note: Le certificat SSL est auto-signé.${NC}"
    echo -e "  ${YELLOW}Votre navigateur affichera un avertissement de sécurité.${NC}"
    echo ""
    echo -e "  Log d'installation: ${LOG_FILE}"
    echo ""
}

#---------------------------------------
# AFFICHER ERREUR
#---------------------------------------
show_error() {
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                                                                  ║${NC}"
    echo -e "${RED}║     ✗ INSTALLATION ÉCHOUÉE                                      ║${NC}"
    echo -e "${RED}║                                                                  ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}Consultez les logs pour plus de détails:${NC}"
    echo -e "  - $LOG_FILE"
    echo -e "  - /var/log/wazuh-install.log"
    echo ""
    echo -e "  ${YELLOW}Commandes utiles pour débugger:${NC}"
    echo -e "  sudo journalctl -u wazuh-manager -n 50"
    echo -e "  sudo journalctl -u wazuh-indexer -n 50"
    echo -e "  sudo cat /var/log/wazuh-install.log | tail -100"
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    # Créer fichier log
    touch $LOG_FILE
    
    show_banner
    
    log_info "Début de l'installation - $(date)"
    echo ""
    
    # Vérifications préliminaires
    echo -e "${CYAN}[VÉRIFICATIONS PRÉLIMINAIRES]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    check_root
    check_os
    check_resources
    check_network
    echo ""
    
    # Nettoyage
    echo -e "${CYAN}[PRÉPARATION]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    cleanup_previous
    update_system
    install_dependencies
    echo ""
    
    # Installation
    echo -e "${CYAN}[INSTALLATION]${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    
    # Snort
    if ! install_snort; then
        log_error "Échec installation Snort"
        show_error
        exit 1
    fi
    
    if ! configure_snort; then
        log_warning "Problème configuration Snort (non bloquant)"
    fi
    echo ""
    
    # Wazuh
    if ! install_wazuh; then
        log_error "Échec installation Wazuh"
        show_error
        exit 1
    fi
    echo ""
    
    # Intégration
    configure_integration
    echo ""
    
    # Résumé
    show_summary
    
    log_info "Installation terminée - $(date)"
}

# Exécuter
main "$@"

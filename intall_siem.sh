#!/bin/bash

#===============================================================================
#
#          FILE: install_siem.sh
#
#         USAGE: sudo bash install_siem.sh
#
#   DESCRIPTION: Installation automatisée de Snort (IDS) + Wazuh (SIEM)
#                Supporte Ubuntu 20.04/22.04/24.04 et Debian 11/12
#
#        AUTHOR: Equipe Projet ASR - IUT Douala
#       VERSION: 2.0
#       CREATED: Février 2026
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
# VARIABLES GLOBALES
#---------------------------------------
SNORT_USER="snort"
SNORT_PASS="snort123"
WAZUH_USER="wazuh"
WAZUH_PASS="wazuh123"
LOG_FILE="/var/log/install_siem.log"
CREDENTIALS_FILE="/root/credentials.txt"

#---------------------------------------
# FONCTIONS D'AFFICHAGE
#---------------------------------------
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║        INSTALLATION AUTOMATISÉE SNORT + WAZUH                    ║"
    echo "║        Snort 2.9.x (IDS) + Wazuh 4.7 (SIEM)                     ║"
    echo "║                                                                  ║"
    echo "║        Supporte: Ubuntu 20.04/22.04/24.04                       ║"
    echo "║                  Debian 11/12                                    ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ÉTAPE $1 : $2${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

#---------------------------------------
# FONCTION: Vérification connexion Internet avec délai 60s
#---------------------------------------
check_internet_with_timeout() {
    print_info "Test de la connexion Internet..."
    
    if ping -c 1 google.com &> /dev/null || ping -c 1 8.8.8.8 &> /dev/null; then
        print_success "Connexion Internet disponible"
        return 0
    else
        echo -e "\n${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ⚠️  AUCUNE CONNEXION INTERNET DÉTECTÉE                          ║${NC}"
        echo -e "${RED}║                                                                  ║${NC}"
        echo -e "${RED}║  Vous avez 60 secondes pour établir une connexion Internet.     ║${NC}"
        echo -e "${RED}║  L'installation sera annulée si aucune connexion n'est détectée.║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}\n"
        
        local countdown=60
        while [ $countdown -gt 0 ]; do
            echo -ne "\r${YELLOW}Temps restant : ${countdown} secondes...${NC}  "
            
            if ping -c 1 google.com &> /dev/null || ping -c 1 8.8.8.8 &> /dev/null; then
                echo ""
                print_success "Connexion Internet établie !"
                return 0
            fi
            
            sleep 5
            countdown=$((countdown - 5))
        done
        
        echo ""
        print_error "Délai dépassé. Aucune connexion Internet détectée."
        print_error "Installation annulée."
        exit 1
    fi
}

#---------------------------------------
# ÉTAPE 1: Vérification des prérequis
#---------------------------------------
check_prerequisites() {
    print_step "1/11" "VÉRIFICATION DES PRÉREQUIS"
    
    # Vérifier root
    if [ "$EUID" -ne 0 ]; then
        print_error "Ce script doit être exécuté en tant que root (sudo)"
        exit 1
    fi
    print_success "Droits root confirmés"
    
    # Vérifier Ubuntu ou Debian
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
            print_success "Système détecté : $PRETTY_NAME"
        else
            print_error "Ce script nécessite Ubuntu ou Debian"
            print_error "Système détecté : $PRETTY_NAME"
            exit 1
        fi
    else
        print_error "Impossible de détecter le système d'exploitation"
        exit 1
    fi
    
    # Vérifier la RAM (minimum 4 Go recommandé)
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_RAM" -lt 3500 ]; then
        print_warning "RAM détectée : ${TOTAL_RAM} Mo (minimum recommandé : 4 Go)"
        print_warning "L'installation peut échouer avec peu de RAM"
    else
        print_success "RAM suffisante : ${TOTAL_RAM} Mo"
    fi
    
    # Vérifier Internet avec timeout
    check_internet_with_timeout
}

#---------------------------------------
# ÉTAPE 2: Détection du réseau
#---------------------------------------
detect_network() {
    print_step "2/11" "DÉTECTION DU RÉSEAU ET DE L'INTERFACE"
    
    # Détecter l'interface réseau principale
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(ip link | grep -E "^[0-9]+" | grep -v "lo:" | head -n1 | awk -F: '{print $2}' | tr -d ' ')
    fi
    print_success "Interface détectée : $INTERFACE"
    
    # Détecter l'IP et le réseau
    IP_ADDR=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | head -n1)
    if [ -z "$IP_ADDR" ]; then
        print_error "Impossible de détecter l'adresse IP"
        exit 1
    fi
    
    # Extraire le réseau (format CIDR)
    NETWORK=$(echo $IP_ADDR | sed 's/\.[0-9]*\//.0\//')
    print_success "Réseau détecté : $NETWORK"
    
    # Extraire juste l'IP sans le masque
    IP_ONLY=$(echo $IP_ADDR | cut -d'/' -f1)
    
    echo -e "\n${YELLOW}[i]${NC} Configuration réseau détectée :"
    echo -e "    - Interface : ${CYAN}$INTERFACE${NC}"
    echo -e "    - Réseau    : ${CYAN}$NETWORK${NC}"
    
    read -p "Ces paramètres sont-ils corrects ? (O/n) : " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        read -p "Entrez l'interface réseau : " INTERFACE
        read -p "Entrez le réseau (ex: 192.168.1.0/24) : " NETWORK
    fi
    print_success "Configuration réseau validée"
}

#---------------------------------------
# ÉTAPE 3: Installation des dépendances + OpenSSH
#---------------------------------------
install_dependencies() {
    print_step "3/11" "INSTALLATION DES DÉPENDANCES ET OPENSSH"
    
    print_info "Mise à jour des paquets..."
    apt-get update >> "$LOG_FILE" 2>&1
    
    print_info "Installation des dépendances..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        wget \
        gnupg \
        apt-transport-https \
        lsb-release \
        ca-certificates \
        software-properties-common \
        net-tools \
        acl \
        >> "$LOG_FILE" 2>&1
    
    print_info "Installation d'OpenSSH Server..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server >> "$LOG_FILE" 2>&1
    systemctl enable ssh >> "$LOG_FILE" 2>&1
    systemctl start ssh >> "$LOG_FILE" 2>&1
    
    # Vérifier que SSH fonctionne
    if systemctl is-active --quiet ssh; then
        print_success "OpenSSH Server installé et actif (port 22)"
    else
        print_warning "OpenSSH installé mais le service n'a pas démarré"
    fi
    
    print_success "Dépendances installées"
}

#---------------------------------------
# ÉTAPE 4: Création utilisateur Snort
#---------------------------------------
create_snort_user() {
    print_step "4/11" "CRÉATION DE L'UTILISATEUR SNORT"
    
    if id "$SNORT_USER" &>/dev/null; then
        print_warning "L'utilisateur $SNORT_USER existe déjà"
    else
        groupadd -f $SNORT_USER
        print_success "Groupe $SNORT_USER créé"
        
        useradd -r -s /sbin/nologin -g $SNORT_USER $SNORT_USER 2>/dev/null || true
        print_success "Utilisateur $SNORT_USER créé"
    fi
    
    echo "$SNORT_USER:$SNORT_PASS" | chpasswd
    print_success "Mot de passe défini : $SNORT_PASS"
    
    usermod -aG sudo $SNORT_USER 2>/dev/null || usermod -aG wheel $SNORT_USER 2>/dev/null || true
    print_success "Utilisateur $SNORT_USER ajouté au groupe sudo"
}

#---------------------------------------
# ÉTAPE 5: Création utilisateur Wazuh
#---------------------------------------
create_wazuh_user() {
    print_step "5/11" "CRÉATION DE L'UTILISATEUR WAZUH"
    
    if id "$WAZUH_USER" &>/dev/null; then
        print_warning "L'utilisateur $WAZUH_USER existe déjà"
    else
        useradd -m -s /bin/bash $WAZUH_USER
        print_success "Utilisateur $WAZUH_USER créé"
    fi
    
    echo "$WAZUH_USER:$WAZUH_PASS" | chpasswd
    print_success "Mot de passe défini : $WAZUH_PASS"
    
    usermod -aG sudo $WAZUH_USER 2>/dev/null || usermod -aG wheel $WAZUH_USER 2>/dev/null || true
    print_success "Utilisateur $WAZUH_USER ajouté au groupe sudo"
}

#---------------------------------------
# ÉTAPE 6: Installation de Snort
#---------------------------------------
install_snort() {
    print_step "6/11" "INSTALLATION DE SNORT 2.9.x"
    
    print_info "Préconfiguration de Snort..."
    echo "snort snort/interface string $INTERFACE" | debconf-set-selections
    echo "snort snort/address_range string $NETWORK" | debconf-set-selections
    
    print_info "Installation de Snort..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y snort >> "$LOG_FILE" 2>&1
    
    if command -v snort &> /dev/null; then
        SNORT_VERSION=$(snort -V 2>&1 | grep -oP "Version \K[0-9.]+") || SNORT_VERSION="2.9.x"
        print_success "Snort installé (version $SNORT_VERSION)"
    else
        print_error "Échec de l'installation de Snort"
        exit 1
    fi
}

#---------------------------------------
# ÉTAPE 7: Configuration de Snort
#---------------------------------------
configure_snort() {
    print_step "7/11" "CONFIGURATION DE SNORT"
    
    SNORT_CONF="/etc/snort/snort.conf"
    
    # Backup de la configuration originale
    if [ -f "$SNORT_CONF" ]; then
        cp "$SNORT_CONF" "${SNORT_CONF}.backup"
        print_success "Backup de la configuration créé"
    fi
    
    # Configurer HOME_NET
    if [ -f "$SNORT_CONF" ]; then
        sed -i "s|ipvar HOME_NET any|ipvar HOME_NET $NETWORK|g" "$SNORT_CONF"
        sed -i "s|ipvar HOME_NET \[.*\]|ipvar HOME_NET $NETWORK|g" "$SNORT_CONF"
        print_success "HOME_NET configuré : $NETWORK"
    fi
    
    # Créer les répertoires nécessaires
    mkdir -p /var/log/snort
    mkdir -p /etc/snort/rules
    chown -R snort:snort /var/log/snort
    chmod -R 5775 /var/log/snort
    print_success "Répertoires Snort créés"
    
    # Configurer le format de sortie pour Wazuh
    if ! grep -q "output alert_fast" "$SNORT_CONF"; then
        echo "" >> "$SNORT_CONF"
        echo "# Output pour Wazuh" >> "$SNORT_CONF"
        echo "output alert_fast: snort.alert.fast" >> "$SNORT_CONF"
        print_success "Format de sortie configuré pour Wazuh"
    fi
    
    # Créer le service systemd pour Snort
    cat > /etc/systemd/system/snort.service << EOF
[Unit]
Description=Snort NIDS
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i $INTERFACE -A fast -l /var/log/snort
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable snort >> "$LOG_FILE" 2>&1
    systemctl start snort >> "$LOG_FILE" 2>&1
    
    if systemctl is-active --quiet snort; then
        print_success "Service Snort démarré"
    else
        print_warning "Le service Snort n'a pas démarré (vérifiez les logs)"
    fi
}

#---------------------------------------
# ÉTAPE 8: Installation de Wazuh
#---------------------------------------
install_wazuh() {
    print_step "8/11" "INSTALLATION DE WAZUH 4.7"
    
    print_info "Téléchargement de l'assistant Wazuh..."
    curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
    
    print_info "Installation de Wazuh (all-in-one)..."
    print_info "Cette étape peut prendre 10-15 minutes..."
    
    bash wazuh-install.sh -a >> "$LOG_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "Wazuh installé avec succès"
    else
        print_error "Erreur lors de l'installation de Wazuh"
        print_info "Consultez le fichier $LOG_FILE pour plus de détails"
    fi
    
    # Nettoyer
    rm -f wazuh-install.sh
}

#---------------------------------------
# ÉTAPE 9: Configuration de Wazuh
#---------------------------------------
configure_wazuh() {
    print_step "9/11" "CONFIGURATION DE WAZUH"
    
    print_info "Attente du démarrage des services..."
    sleep 10
    
    # Vérifier les services
    for service in wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet $service; then
            print_success "Service $service : ACTIF"
        else
            print_warning "Service $service : INACTIF"
            systemctl start $service 2>/dev/null || true
        fi
    done
    
    # Extraire le mot de passe du dashboard
    print_info "Extraction du mot de passe dashboard..."
    if [ -f /usr/share/wazuh-install-files/wazuh-passwords.txt ]; then
        WAZUH_ADMIN_PASS=$(grep "admin" /usr/share/wazuh-install-files/wazuh-passwords.txt | head -1 | awk '{print $NF}')
    else
        WAZUH_ADMIN_PASS="Voir /usr/share/wazuh-install-files/"
    fi
}

#---------------------------------------
# ÉTAPE 10: Liaison Snort-Wazuh
#---------------------------------------
configure_snort_wazuh_integration() {
    print_step "10/11" "LIAISON SNORT - WAZUH"
    
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    
    print_info "Configuration de la liaison..."
    
    if [ -f "$OSSEC_CONF" ]; then
        # Vérifier si la configuration existe déjà
        if ! grep -q "snort.alert.fast" "$OSSEC_CONF"; then
            # Ajouter la configuration pour lire les logs Snort
            sed -i '/<\/ossec_config>/i \
  <localfile>\
    <log_format>snort-fast<\/log_format>\
    <location>\/var\/log\/snort\/snort.alert.fast<\/location>\
  <\/localfile>' "$OSSEC_CONF"
            print_success "Configuration ajoutée"
        else
            print_warning "Configuration déjà présente"
        fi
        
        # Configurer les permissions
        print_info "Configuration des permissions..."
        chmod 755 /var/log/snort
        chmod 644 /var/log/snort/* 2>/dev/null || true
        setfacl -m u:wazuh:rx /var/log/snort 2>/dev/null || true
        setfacl -m u:wazuh:r /var/log/snort/* 2>/dev/null || true
        print_success "Permissions configurées"
        
        # Redémarrer Wazuh Manager
        print_info "Redémarrage de Wazuh Manager..."
        systemctl restart wazuh-manager >> "$LOG_FILE" 2>&1
        print_success "Wazuh Manager redémarré"
        
        print_success "Liaison Snort-Wazuh configurée"
    else
        print_error "Fichier de configuration Wazuh non trouvé"
    fi
}

#---------------------------------------
# ÉTAPE 11: Génération des credentials
#---------------------------------------
generate_credentials() {
    print_step "11/11" "GÉNÉRATION DU FICHIER CREDENTIALS"
    
    cat > "$CREDENTIALS_FILE" << EOF
╔══════════════════════════════════════════════════════════════════╗
║              CREDENTIALS - INSTALLATION SIEM                      ║
║              Généré le : $(date '+%Y-%m-%d %H:%M:%S')               ║
╚══════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════
  UTILISATEURS SYSTÈME
═══════════════════════════════════════════════════════════════════
  
  Utilisateur Snort  : $SNORT_USER / $SNORT_PASS
  Utilisateur Wazuh  : $WAZUH_USER / $WAZUH_PASS

═══════════════════════════════════════════════════════════════════
  ACCÈS SSH
═══════════════════════════════════════════════════════════════════

  Serveur   : $IP_ONLY
  Port      : 22
  Commande  : ssh $WAZUH_USER@$IP_ONLY

═══════════════════════════════════════════════════════════════════
  WAZUH DASHBOARD
═══════════════════════════════════════════════════════════════════

  URL           : https://$IP_ONLY
  Utilisateur   : admin
  Mot de passe  : $WAZUH_ADMIN_PASS

═══════════════════════════════════════════════════════════════════
  CONFIGURATION SNORT
═══════════════════════════════════════════════════════════════════

  Réseau surveillé : $NETWORK
  Interface        : $INTERFACE
  Alertes          : /var/log/snort/snort.alert.fast
  Config           : /etc/snort/snort.conf

═══════════════════════════════════════════════════════════════════
  COMMANDES UTILES
═══════════════════════════════════════════════════════════════════

  # Vérifier les services
  sudo systemctl status snort
  sudo systemctl status wazuh-manager
  
  # Voir les alertes Snort en temps réel
  sudo tail -f /var/log/snort/snort.alert.fast
  
  # Redémarrer les services
  sudo systemctl restart snort
  sudo systemctl restart wazuh-manager

═══════════════════════════════════════════════════════════════════
  INSTALLATION DES AGENTS WAZUH
═══════════════════════════════════════════════════════════════════

  Pour surveiller d'autres machines, installez l'agent Wazuh :

  🐧 Linux (Ubuntu/Debian/CentOS) :
  curl -sO https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main/agents/install_agent.sh
  sudo bash install_agent.sh $IP_ONLY

  🪟 Windows (PowerShell Administrateur) :
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main/agents/install_agent.ps1" -OutFile "install_agent.ps1"
  .\\install_agent.ps1 -ServerIP $IP_ONLY

EOF

    chmod 600 "$CREDENTIALS_FILE"
    print_success "Fichier credentials créé : $CREDENTIALS_FILE"
}

#---------------------------------------
# AFFICHAGE FINAL
#---------------------------------------
print_final_summary() {
    echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║        ✓ INSTALLATION TERMINÉE AVEC SUCCÈS !                    ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  CREDENTIALS : sudo cat /root/credentials.txt${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n${YELLOW}Utilisateur Snort :${NC} $SNORT_USER / $SNORT_PASS"
    echo -e "${YELLOW}Utilisateur Wazuh :${NC} $WAZUH_USER / $WAZUH_PASS"
    
    echo -e "\n${YELLOW}Dashboard Wazuh   :${NC} https://$IP_ONLY"
    echo -e "${YELLOW}(mot de passe dans le fichier credentials)${NC}"
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  CONFIGURATION SNORT${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n${YELLOW}Réseau surveillé :${NC} $NETWORK"
    echo -e "${YELLOW}Interface        :${NC} $INTERFACE"
    echo -e "${YELLOW}Alertes          :${NC} /var/log/snort/snort.alert.fast"
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  INSTALLATION DES AGENTS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n${YELLOW}🐧 Linux :${NC}"
    echo -e "curl -sO https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main/agents/install_agent.sh"
    echo -e "sudo bash install_agent.sh $IP_ONLY"
    
    echo -e "\n${YELLOW}🪟 Windows (PowerShell Admin) :${NC}"
    echo -e "Voir le fichier credentials pour les instructions"
    
    echo ""
}

#---------------------------------------
# MAIN
#---------------------------------------
main() {
    print_banner
    
    echo -e "Ce script va installer :"
    echo -e "  • Snort 2.9.x (IDS)"
    echo -e "  • Wazuh 4.7 (SIEM)"
    echo -e "  • OpenSSH Server"
    echo -e "\n${YELLOW}Durée estimée : 15-20 minutes${NC}\n"
    
    read -p "Continuer ? (O/n) : " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "Installation annulée."
        exit 0
    fi
    
    # Créer le fichier de log
    touch "$LOG_FILE"
    
    # Exécuter les étapes
    check_prerequisites
    detect_network
    install_dependencies
    create_snort_user
    create_wazuh_user
    install_snort
    configure_snort
    install_wazuh
    configure_wazuh
    configure_snort_wazuh_integration
    generate_credentials
    
    # Afficher le résumé
    print_final_summary
}

# Lancer le script
main "$@"

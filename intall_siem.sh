#!/bin/bash

# ============================================================================
#   SCRIPT D'INSTALLATION AUTOMATISÉE SNORT + WAZUH
#   Snort 2.9.x (IDS) + Wazuh 4.7 (SIEM)
# ============================================================================

set -e

# === VARIABLES GLOBALES ===
SNORT_USER="snort"
SNORT_GROUP="snort"
SNORT_PASSWORD="snort123"

WAZUH_USER="wazuh"
WAZUH_PASSWORD="wazuh123"
WAZUH_VERSION="4.7"

SNORT_CONFIG="/etc/snort/snort.conf"
SNORT_RULES_DIR="/etc/snort/rules"
SNORT_LOG_DIR="/var/log/snort"
SNORT_ALERT_FILE="/var/log/snort/snort.alert.fast"
WAZUH_CONFIG="/var/ossec/etc/ossec.conf"
CREDENTIALS_FILE="/root/credentials.txt"
LOG_FILE="/var/log/install_siem.log"

# === COULEURS ===
VERT='\033[0;32m'
ROUGE='\033[0;31m'
JAUNE='\033[1;33m'
BLEU='\033[0;34m'
CYAN='\033[0;36m'
BLANC='\033[1;37m'
NC='\033[0m'

# === FONCTIONS D'AFFICHAGE ===
afficher_banniere() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                      ║"
    echo "║          INSTALLATION AUTOMATISÉE SNORT + WAZUH                      ║"
    echo "║          Snort 2.9.x (IDS) + Wazuh 4.7 (SIEM)                        ║"
    echo "║                                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

succes() {
    echo -e "${VERT}[✓]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCES] $1" >> "$LOG_FILE"
}

erreur() {
    echo -e "${ROUGE}[✗]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERREUR] $1" >> "$LOG_FILE"
}

info() {
    echo -e "${BLEU}[i]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOG_FILE"
}

attention() {
    echo -e "${JAUNE}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ATTENTION] $1" >> "$LOG_FILE"
}

etape() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}   $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ETAPE] $1" >> "$LOG_FILE"
}

# === INITIALISATION ===
initialiser_log() {
    echo "=== LOG INSTALLATION SNORT + WAZUH ===" > "$LOG_FILE"
    echo "Démarré le : $(date)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
}

initialiser_credentials() {
    cat > "$CREDENTIALS_FILE" << EOF
══════════════════════════════════════════════════════════════════════
                    CREDENTIALS - SNORT + WAZUH
                    Généré le : $(date)
══════════════════════════════════════════════════════════════════════

EOF
    chmod 600 "$CREDENTIALS_FILE"
}

# === VÉRIFICATION DES PRÉREQUIS ===
verifier_prerequis() {
    etape "ÉTAPE 1/10 : VÉRIFICATION DES PRÉREQUIS"
    
    if [ "$EUID" -ne 0 ]; then
        erreur "Ce script doit être exécuté en tant que root (sudo)"
        echo -e "${JAUNE}Usage : sudo bash $0${NC}"
        exit 1
    fi
    succes "Droits root confirmés"
    
    if [ ! -f /etc/os-release ]; then
        erreur "Impossible de détecter le système d'exploitation"
        exit 1
    fi
    
    source /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        erreur "Ce script est conçu pour Ubuntu. Système détecté : $ID"
        exit 1
    fi
    succes "Système Ubuntu détecté : $VERSION"
    
    RAM_TOTALE=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$RAM_TOTALE" -lt 4000 ]; then
        attention "RAM : ${RAM_TOTALE} Mo (4 Go minimum recommandé)"
    else
        succes "RAM suffisante : ${RAM_TOTALE} Mo"
    fi
    
    info "Test de la connexion Internet..."
    if ping -c 1 -W 5 google.com &> /dev/null || ping -c 1 -W 5 8.8.8.8 &> /dev/null; then
        succes "Connexion Internet disponible"
    else
        erreur "Connexion Internet requise"
        exit 1
    fi
}

# === DÉTECTION RÉSEAU ET INTERFACE ===
detecter_reseau_interface() {
    etape "ÉTAPE 2/10 : DÉTECTION DU RÉSEAU ET DE L'INTERFACE"
    
    # Détection automatique de l'interface principale
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [ -z "$NETWORK_INTERFACE" ]; then
        erreur "Impossible de détecter l'interface réseau"
        echo ""
        echo "Interfaces disponibles :"
        ip -o link show | awk -F': ' '{print "  - "$2}' | grep -v "lo"
        echo ""
        read -p "Entrez le nom de l'interface : " NETWORK_INTERFACE
    fi
    succes "Interface détectée : $NETWORK_INTERFACE"
    
    # Détection automatique du réseau
    HOME_NET=$(ip -o -f inet addr show "$NETWORK_INTERFACE" | awk '{print $4}')
    
    if [ -z "$HOME_NET" ]; then
        read -p "Entrez le réseau (ex: 192.168.1.0/24) : " HOME_NET
    fi
    succes "Réseau détecté : $HOME_NET"
    
    echo ""
    info "Configuration réseau détectée :"
    echo "   - Interface : $NETWORK_INTERFACE"
    echo "   - Réseau    : $HOME_NET"
    echo ""
    
    read -p "Ces paramètres sont-ils corrects ? (O/n) : " CONFIRMATION
    
    if [[ "$CONFIRMATION" =~ ^[Nn]$ ]]; then
        echo ""
        echo "Interfaces disponibles :"
        ip -o link show | awk -F': ' '{print "  - "$2}' | grep -v "lo"
        echo ""
        read -p "Entrez l'interface réseau : " NETWORK_INTERFACE
        read -p "Entrez le réseau (ex: 192.168.1.0/24) : " HOME_NET
    fi
    
    succes "Configuration réseau validée"
}

# === INSTALLATION DES DÉPENDANCES ===
installer_dependances() {
    etape "ÉTAPE 3/10 : INSTALLATION DES DÉPENDANCES"
    
    info "Mise à jour des paquets..."
    apt update -qq
    
    info "Installation des dépendances..."
    apt install -y -qq curl wget gnupg apt-transport-https net-tools lsb-release acl debconf-utils
    
    succes "Dépendances installées"
}

# === CRÉATION UTILISATEUR SNORT ===
creer_utilisateur_snort() {
    etape "ÉTAPE 4/10 : CRÉATION DE L'UTILISATEUR SNORT"
    
    if getent group "$SNORT_GROUP" > /dev/null; then
        info "Le groupe $SNORT_GROUP existe déjà"
    else
        groupadd "$SNORT_GROUP"
        succes "Groupe $SNORT_GROUP créé"
    fi
    
    if id "$SNORT_USER" &> /dev/null; then
        info "L'utilisateur $SNORT_USER existe déjà"
    else
        useradd -m -g "$SNORT_GROUP" -s /bin/bash "$SNORT_USER"
        succes "Utilisateur $SNORT_USER créé"
    fi
    
    echo "$SNORT_USER:$SNORT_PASSWORD" | chpasswd
    succes "Mot de passe défini : $SNORT_PASSWORD"
    
    usermod -aG sudo "$SNORT_USER"
    succes "Utilisateur $SNORT_USER ajouté au groupe sudo"
    
    cat >> "$CREDENTIALS_FILE" << EOF
--- UTILISATEUR SNORT ---
Utilisateur  : $SNORT_USER
Mot de passe : $SNORT_PASSWORD
Groupe       : sudo

EOF
}

# === CRÉATION UTILISATEUR WAZUH ===
creer_utilisateur_wazuh() {
    etape "ÉTAPE 5/10 : CRÉATION DE L'UTILISATEUR WAZUH"
    
    if id "$WAZUH_USER" &> /dev/null; then
        info "L'utilisateur $WAZUH_USER existe déjà"
    else
        useradd -m -s /bin/bash "$WAZUH_USER"
        succes "Utilisateur $WAZUH_USER créé"
    fi
    
    echo "$WAZUH_USER:$WAZUH_PASSWORD" | chpasswd
    succes "Mot de passe défini : $WAZUH_PASSWORD"
    
    usermod -aG sudo "$WAZUH_USER"
    succes "Utilisateur $WAZUH_USER ajouté au groupe sudo"
    
    cat >> "$CREDENTIALS_FILE" << EOF
--- UTILISATEUR WAZUH ---
Utilisateur  : $WAZUH_USER
Mot de passe : $WAZUH_PASSWORD
Groupe       : sudo

EOF
}

# === INSTALLATION DE SNORT ===
installer_snort() {
    etape "ÉTAPE 6/10 : INSTALLATION DE SNORT 2.9.x"
    
    if command -v snort &> /dev/null; then
        info "Snort est déjà installé"
        snort -V 2>&1 | head -2
        return 0
    fi
    
    info "Préconfiguration de Snort..."
    echo "snort snort/address_range string $HOME_NET" | debconf-set-selections
    echo "snort snort/interface string $NETWORK_INTERFACE" | debconf-set-selections
    
    info "Installation de Snort..."
    DEBIAN_FRONTEND=noninteractive apt install -y snort
    
    succes "Snort installé"
    snort -V 2>&1 | head -2
}

# === CONFIGURATION DE SNORT ===
configurer_snort() {
    etape "ÉTAPE 7/10 : CONFIGURATION DE SNORT"
    
    mkdir -p "$SNORT_LOG_DIR"
    chown -R ${SNORT_USER}:${SNORT_GROUP} "$SNORT_LOG_DIR"
    chmod 750 "$SNORT_LOG_DIR"
    succes "Répertoire de logs créé"
    
    touch "$SNORT_ALERT_FILE"
    chown ${SNORT_USER}:${SNORT_GROUP} "$SNORT_ALERT_FILE"
    chmod 644 "$SNORT_ALERT_FILE"
    succes "Fichier d'alertes créé"
    
    if [ -f "$SNORT_CONFIG" ]; then
        cp "$SNORT_CONFIG" "${SNORT_CONFIG}.backup"
        succes "Configuration sauvegardée"
    fi
    
    sed -i "s|^ipvar HOME_NET.*|ipvar HOME_NET $HOME_NET|" "$SNORT_CONFIG"
    succes "HOME_NET configuré : $HOME_NET"
    
    cat > /etc/systemd/system/snort.service << EOF
[Unit]
Description=Snort 2.9.x IDS
After=network.target

[Service]
Type=simple
User=$SNORT_USER
Group=$SNORT_GROUP
ExecStart=/usr/sbin/snort -q -u $SNORT_USER -g $SNORT_GROUP -c $SNORT_CONFIG -i $NETWORK_INTERFACE -A fast -l $SNORT_LOG_DIR
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    succes "Service systemd créé"
    
    # Règles Community
    info "Installation des règles Community..."
    mkdir -p "$SNORT_RULES_DIR"
    
    wget -q https://www.snort.org/downloads/community/community-rules.tar.gz -O /tmp/community-rules.tar.gz 2>/dev/null || true
    
    if [ -f /tmp/community-rules.tar.gz ]; then
        tar -xzf /tmp/community-rules.tar.gz -C /tmp/
        cp /tmp/community-rules/*.rules "$SNORT_RULES_DIR/" 2>/dev/null || true
        [ -f /tmp/community-rules/sid-msg.map ] && cp /tmp/community-rules/sid-msg.map /etc/snort/
        
        if ! grep -q "community.rules" "$SNORT_CONFIG" 2>/dev/null; then
            echo -e "\n# Règles Community\ninclude \$RULE_PATH/community.rules" >> "$SNORT_CONFIG"
        fi
        
        rm -rf /tmp/community-rules*
        succes "Règles Community installées"
    else
        attention "Règles Community non téléchargées"
    fi
    
    systemctl enable snort
    systemctl start snort
    
    sleep 3
    if systemctl is-active --quiet snort; then
        succes "Snort actif"
    else
        attention "Snort n'a pas démarré - vérifier : journalctl -u snort"
    fi
}

# === INSTALLATION DE WAZUH ===
installer_wazuh() {
    etape "ÉTAPE 8/10 : INSTALLATION DE WAZUH $WAZUH_VERSION"
    
    if [ -f /var/ossec/bin/wazuh-control ]; then
        info "Wazuh est déjà installé"
        return 0
    fi
    
    info "Téléchargement du script Wazuh..."
    curl -sO https://packages.wazuh.com/${WAZUH_VERSION}/wazuh-install.sh
    
    if [ ! -f wazuh-install.sh ]; then
        erreur "Échec du téléchargement"
        exit 1
    fi
    
    echo ""
    attention "Installation de Wazuh en cours..."
    attention "Durée estimée : 10-15 minutes"
    echo ""
    
    bash wazuh-install.sh -a 2>&1 | tee -a "$LOG_FILE"
    
    rm -f wazuh-install.sh
    succes "Wazuh installé"
}

# === CONFIGURATION DE WAZUH ===
configurer_wazuh() {
    etape "ÉTAPE 9/10 : CONFIGURATION DE WAZUH"
    
    info "Attente du démarrage des services..."
    sleep 30
    
    for service in wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            succes "Service $service : ACTIF"
        else
            attention "Service $service : INACTIF"
        fi
    done
    
    info "Extraction du mot de passe dashboard..."
    
    if [ -f /root/wazuh-install-files.tar ]; then
        mkdir -p /tmp/wazuh-extract
        tar -xf /root/wazuh-install-files.tar -C /tmp/wazuh-extract 2>/dev/null || true
        
        if [ -f /tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt ]; then
            WAZUH_ADMIN_PASSWORD=$(grep -A1 "admin" /tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt | tail -1 | tr -d "' " | awk -F: '{print $NF}')
            
            [ -z "$WAZUH_ADMIN_PASSWORD" ] && WAZUH_ADMIN_PASSWORD=$(grep "admin" /tmp/wazuh-extract/wazuh-install-files/wazuh-passwords.txt | awk '{print $NF}' | tr -d "'\"")
            
            IP_SERVEUR=$(hostname -I | awk '{print $1}')
            
            cat >> "$CREDENTIALS_FILE" << EOF
--- DASHBOARD WAZUH ---
URL          : https://$IP_SERVEUR
Utilisateur  : admin
Mot de passe : $WAZUH_ADMIN_PASSWORD

EOF
            succes "Credentials dashboard enregistrés"
        fi
        
        rm -rf /tmp/wazuh-extract
    fi
}

# === LIAISON SNORT - WAZUH ===
lier_snort_wazuh() {
    etape "ÉTAPE 10/10 : LIAISON SNORT - WAZUH"
    
    if [ ! -f "$WAZUH_CONFIG" ]; then
        erreur "Configuration Wazuh non trouvée"
        return 1
    fi
    
    if grep -q "snort.alert.fast" "$WAZUH_CONFIG" 2>/dev/null; then
        info "Liaison déjà configurée"
    else
        info "Configuration de la liaison..."
        
        cp "$WAZUH_CONFIG" "${WAZUH_CONFIG}.backup"
        
        sed -i '/<\/ossec_config>/i \
\
  <!-- INTÉGRATION SNORT IDS -->\
  <localfile>\
    <log_format>snort-fast</log_format>\
    <location>'"$SNORT_ALERT_FILE"'</location>\
  </localfile>' "$WAZUH_CONFIG"
        
        succes "Configuration ajoutée"
    fi
    
    info "Configuration des permissions..."
    usermod -aG "$SNORT_GROUP" ossec 2>/dev/null || true
    setfacl -m g:ossec:rx "$SNORT_LOG_DIR" 2>/dev/null || true
    setfacl -m g:ossec:r "$SNORT_ALERT_FILE" 2>/dev/null || true
    chmod 644 "$SNORT_ALERT_FILE"
    succes "Permissions configurées"
    
    info "Redémarrage de Wazuh Manager..."
    systemctl restart wazuh-manager
    
    sleep 5
    if systemctl is-active --quiet wazuh-manager; then
        succes "Wazuh Manager redémarré"
    else
        attention "Problème au redémarrage"
    fi
    
    succes "Liaison Snort-Wazuh configurée"
}

# === AFFICHAGE DU RÉSUMÉ ===
afficher_resume() {
    IP_SERVEUR=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${VERT}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${VERT}║            ✓ INSTALLATION TERMINÉE AVEC SUCCÈS !                     ║${NC}"
    echo -e "${VERT}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}   CREDENTIALS : sudo cat $CREDENTIALS_FILE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "   Utilisateur Snort : ${VERT}$SNORT_USER${NC} / ${VERT}$SNORT_PASSWORD${NC}"
    echo -e "   Utilisateur Wazuh : ${VERT}$WAZUH_USER${NC} / ${VERT}$WAZUH_PASSWORD${NC}"
    echo ""
    echo -e "   Dashboard Wazuh   : ${VERT}https://$IP_SERVEUR${NC}"
    echo -e "   (mot de passe dans le fichier credentials)"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}   CONFIGURATION SNORT${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "   Réseau surveillé : ${VERT}$HOME_NET${NC}"
    echo -e "   Interface        : ${VERT}$NETWORK_INTERFACE${NC}"
    echo -e "   Alertes          : ${VERT}$SNORT_ALERT_FILE${NC}"
    echo ""
    
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}   COMMANDES UTILES${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "   sudo cat $CREDENTIALS_FILE"
    echo "   sudo systemctl status snort"
    echo "   sudo systemctl status wazuh-manager"
    echo "   sudo tail -f $SNORT_ALERT_FILE"
    echo ""
    
    cat >> "$CREDENTIALS_FILE" << EOF
--- CONFIGURATION SNORT ---
Interface    : $NETWORK_INTERFACE
Réseau       : $HOME_NET
Alertes      : $SNORT_ALERT_FILE
Config       : $SNORT_CONFIG

--- COMMANDES UTILES ---
sudo systemctl status snort
sudo systemctl status wazuh-manager
sudo tail -f $SNORT_ALERT_FILE
EOF
    
    echo "" >> "$LOG_FILE"
    echo "Installation terminée le : $(date)" >> "$LOG_FILE"
}

# === PROGRAMME PRINCIPAL ===
main() {
    initialiser_log
    afficher_banniere
    
    echo -e "${BLANC}Ce script va installer :${NC}"
    echo "  • Snort 2.9.x (IDS)"
    echo "  • Wazuh 4.7 (SIEM)"
    echo ""
    echo -e "${JAUNE}Durée estimée : 15-20 minutes${NC}"
    echo ""
    read -p "Continuer ? (O/n) : " CONFIRM
    
    [[ "$CONFIRM" =~ ^[Nn]$ ]] && echo "Annulé." && exit 0
    
    initialiser_credentials
    verifier_prerequis
    detecter_reseau_interface
    installer_dependances
    creer_utilisateur_snort
    creer_utilisateur_wazuh
    installer_snort
    configurer_snort
    installer_wazuh
    configurer_wazuh
    lier_snort_wazuh
    afficher_resume
}

main "$@"

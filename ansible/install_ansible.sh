#!/bin/bash

#===============================================================================
#
#          FILE: install_ansible.sh
#
#         USAGE: curl -sL https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main/ansible/install_ansible.sh | bash
#
#   DESCRIPTION: Installation automatique d'Ansible sur Ubuntu/Debian
#
#        AUTHOR: SIEM Africa Team
#       VERSION: 1.0
#
#===============================================================================

set -e

#---------------------------------------
# COULEURS
#---------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#---------------------------------------
# BANNIÈRE
#---------------------------------------
clear
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                  ║"
echo "║     🤖 ANSIBLE - Installation Automatique                       ║"
echo "║                                                                  ║"
echo "║     Pour déployer SIEM (Snort + Wazuh) sur plusieurs serveurs   ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

#---------------------------------------
# VÉRIFICATION OS
#---------------------------------------
echo -e "${CYAN}[1/4]${NC} Vérification du système..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}[✗]${NC} OS non supporté"
    exit 1
fi

case $OS in
    ubuntu|debian)
        echo -e "${GREEN}[✓]${NC} OS compatible: $OS"
        ;;
    *)
        echo -e "${RED}[✗]${NC} OS non supporté: $OS (Ubuntu/Debian requis)"
        exit 1
        ;;
esac

#---------------------------------------
# MISE À JOUR
#---------------------------------------
echo -e "${CYAN}[2/4]${NC} Mise à jour des paquets..."

sudo apt update -qq
echo -e "${GREEN}[✓]${NC} Paquets mis à jour"

#---------------------------------------
# INSTALLATION ANSIBLE
#---------------------------------------
echo -e "${CYAN}[3/4]${NC} Installation d'Ansible..."

# Installer les dépendances
sudo apt install -y software-properties-common

# Ajouter le PPA Ansible (pour Ubuntu)
if [ "$OS" == "ubuntu" ]; then
    sudo add-apt-repository --yes --update ppa:ansible/ansible
fi

# Installer Ansible
sudo apt install -y ansible sshpass

echo -e "${GREEN}[✓]${NC} Ansible installé"

#---------------------------------------
# VÉRIFICATION
#---------------------------------------
echo -e "${CYAN}[4/4]${NC} Vérification de l'installation..."

ANSIBLE_VERSION=$(ansible --version | head -1)
echo -e "${GREEN}[✓]${NC} $ANSIBLE_VERSION"

#---------------------------------------
# CRÉATION STRUCTURE
#---------------------------------------
echo ""
echo -e "${CYAN}[i]${NC} Création de la structure de projet..."

mkdir -p ~/ansible-siem/playbooks
mkdir -p ~/ansible-siem/roles

cd ~/ansible-siem

# Créer le fichier inventory.ini d'exemple
cat > inventory.ini << 'EOF'
#===============================================================================
# INVENTORY - Liste des serveurs cibles
#===============================================================================
#
# COMMENT UTILISER :
# 1. Remplace les IP par celles de tes serveurs
# 2. Remplace 'ton_user' par ton nom d'utilisateur SSH
# 3. Remplace 'ton_password' par ton mot de passe SSH
#
# EXEMPLE :
#   Si ton serveur est 192.168.1.100 avec user 'admin' et password '1234'
#   → 192.168.1.100 ansible_user=admin ansible_password=1234
#
#===============================================================================

[siem_servers]
# Serveurs où installer Snort + Wazuh (serveur complet)
# Décommente et modifie la ligne suivante :
# 192.168.1.100 ansible_user=ton_user ansible_password=ton_password

[wazuh_agents]
# Machines où installer seulement l'agent Wazuh
# Décommente et modifie les lignes suivantes :
# 192.168.1.101 ansible_user=ton_user ansible_password=ton_password
# 192.168.1.102 ansible_user=ton_user ansible_password=ton_password

[all:vars]
# Variables globales
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

# Créer le fichier ansible.cfg
cat > ansible.cfg << 'EOF'
#===============================================================================
# CONFIGURATION ANSIBLE
#===============================================================================

[defaults]
# Fichier d'inventaire par défaut
inventory = inventory.ini

# Ne pas vérifier les clés SSH (pratique pour les nouvelles machines)
host_key_checking = False

# Utilisateur distant par défaut
remote_user = root

# Timeout de connexion
timeout = 30

# Nombre de machines en parallèle
forks = 5

# Ne pas créer de fichiers .retry
retry_files_enabled = False

# Couleurs dans le terminal
force_color = True

[privilege_escalation]
# Utiliser sudo automatiquement
become = True
become_method = sudo
become_user = root
become_ask_pass = False
EOF

echo -e "${GREEN}[✓]${NC} Structure créée dans ~/ansible-siem/"

#---------------------------------------
# RÉSUMÉ
#---------------------------------------
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                                  ║${NC}"
echo -e "${GREEN}║     ✓ ANSIBLE INSTALLÉ AVEC SUCCÈS !                            ║${NC}"
echo -e "${GREEN}║                                                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                      PROCHAINES ÉTAPES                             ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${YELLOW}1.${NC} Va dans le dossier Ansible :"
echo -e "     ${GREEN}cd ~/ansible-siem${NC}"
echo ""
echo -e "  ${YELLOW}2.${NC} Édite le fichier inventory.ini :"
echo -e "     ${GREEN}nano inventory.ini${NC}"
echo -e "     → Ajoute les IP de tes serveurs"
echo ""
echo -e "  ${YELLOW}3.${NC} Télécharge les playbooks :"
echo -e "     ${GREEN}wget https://raw.githubusercontent.com/.../install_siem.yml -P playbooks/${NC}"
echo ""
echo -e "  ${YELLOW}4.${NC} Lance l'installation :"
echo -e "     ${GREEN}ansible-playbook playbooks/install_siem.yml${NC}"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""


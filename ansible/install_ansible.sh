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
[siem_servers]
# 192.168.1.100 ansible_user=admin ansible_password=password

[wazuh_agents]
# 192.168.1.101 ansible_user=admin ansible_password=password

[all:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

# Créer le fichier ansible.cfg
cat > ansible.cfg << 'EOF'
[defaults]
inventory = inventory.ini
host_key_checking = False
remote_user = root
timeout = 30
forks = 5
retry_files_enabled = False
force_color = True

[privilege_escalation]
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
echo -e "${GREEN}║     ✓ ANSIBLE INSTALLÉ AVEC SUCCÈS !                            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${YELLOW}1.${NC} cd ~/ansible-siem"
echo -e "  ${YELLOW}2.${NC} nano inventory.ini  (ajoute tes serveurs)"
echo -e "  ${YELLOW}3.${NC} ansible-playbook playbooks/install_siem.yml"
echo ""

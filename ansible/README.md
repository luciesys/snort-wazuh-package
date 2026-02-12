# 🤖 ANSIBLE - Déploiement SIEM Automatisé

## 📋 C'est quoi ?

Installer automatiquement le SIEM (Snort + Wazuh) sur plusieurs serveurs en même temps.

## 📁 Fichiers
```
ansible/
├── install_ansible.sh    ← Installe Ansible
├── inventory.ini         ← Liste des serveurs (À MODIFIER)
├── ansible.cfg           ← Configuration
└── playbooks/
    ├── install_siem.yml    ← Installe Snort + Wazuh
    ├── install_agent.yml   ← Installe l'agent Wazuh
    └── uninstall_siem.yml  ← Désinstalle tout
```

## 🚀 Utilisation

### 1. Installer Ansible
```bash
curl -sL https://raw.githubusercontent.com/luciesys/snort-wazuh-package/main/ansible/install_ansible.sh | bash
```

### 2. Configurer les serveurs
```bash
cd ~/ansible-siem
nano inventory.ini
```

### 3. Lancer l'installation
```bash
ansible-playbook playbooks/install_siem.yml
```

## 📖 Playbooks

| Playbook | Description |
|----------|-------------|
| `install_siem.yml` | Installe Snort + Wazuh complet |
| `install_agent.yml` | Installe l'agent sur les clients |
| `uninstall_siem.yml` | Désinstalle tout |

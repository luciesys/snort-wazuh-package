# SIEM AFRICA - Package d'Installation v2.1

## 🎯 Description

SIEM Africa est une solution de cybersécurité complète conçue pour les PME africaines francophones.
Cette version inclut la **stack Wazuh complète** avec **deux dashboards**.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SIEM AFRICA v2.1                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐          ┌─────────────────────────────────────────────┐  │
│  │   SNORT     │          │              WAZUH STACK                    │  │
│  │    IDS      │   logs   │  ┌─────────┐ ┌─────────┐ ┌──────────────┐  │  │
│  │             │ ───────▶ │  │ Indexer │ │ Manager │ │  Dashboard   │  │  │
│  │ Interface   │          │  │  :9200  │ │ :1514   │ │    :443      │  │  │
│  │  réseau     │          │  └─────────┘ └─────────┘ └──────────────┘  │  │
│  └─────────────┘          └─────────────────────────────────────────────┘  │
│                                         │                                   │
│                                         │ API :55000                        │
│                                         ▼                                   │
│                           ┌─────────────────────────────────────────────┐  │
│                           │         SIEM AFRICA DASHBOARD               │  │
│                           │     (Interface Française + Recommandations) │  │
│                           │                  :5000                      │  │
│                           └─────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 📊 Les 2 Dashboards

| Dashboard | Port | Langue | Usage |
|-----------|------|--------|-------|
| **Wazuh Dashboard** | 443 | Anglais | Interface native, visualisation avancée, gestion agents |
| **SIEM Africa Dashboard** | 5000 | Français | Alertes traduites, recommandations contextuelles |

## ✅ Prérequis

| Critère | Minimum | Recommandé |
|---------|---------|------------|
| **OS** | Ubuntu 20.04 / Debian 10 | Ubuntu 22.04 / Debian 12 |
| **RAM** | 4 Go | 8 Go |
| **Disque** | 50 Go libres | 100 Go libres |
| **Internet** | Requis | Requis |
| **Accès** | root (sudo) | root (sudo) |

### Systèmes supportés :
- Ubuntu 20.04 / 22.04 / 24.04 LTS
- Debian 10 / 11 / 12

## 🚀 Installation

```bash
# 1. Extraire le package
tar -xzf siem-africa-v2.1.tar.gz
cd siem-africa-v2.1

# 2. Lancer l'installation (20-40 minutes)
sudo ./install_all.sh
```

## 👥 Utilisateurs créés

### Utilisateurs système Linux

| Utilisateur | Mot de passe | Rôle |
|-------------|--------------|------|
| snort | snort123 | Exécute Snort IDS |
| wazuh | wazuh123 | Exécute services Wazuh |
| siem | siem123 | Exécute SIEM Africa |

### Utilisateurs Dashboard SIEM Africa

| Utilisateur | Mot de passe | Rôle |
|-------------|--------------|------|
| admin | SiemAfrica2026! | Administrateur |
| analyste | Analyste123! | Analyste sécurité |
| lecteur | Lecteur123! | Lecture seule |

## 🔐 Accès aux Dashboards

### Wazuh Dashboard (Anglais)
```
URL: https://[IP_SERVEUR]:443
User: admin
Pass: (voir /root/wazuh-passwords.txt)
```

### SIEM Africa Dashboard (Français)
```
URL: https://[IP_SERVEUR]:5000
User: admin
Pass: SiemAfrica2026!
```

⚠️ **IMPORTANT** : Changement de mot de passe OBLIGATOIRE à la première connexion !

## 📄 Fichiers d'identifiants

| Fichier | Contenu |
|---------|---------|
| `/root/credentials.txt` | Tous les identifiants système et services |
| `/opt/siem-africa/SCRID.txt` | Identifiants dashboard + commandes de vérification |
| `/root/wazuh-passwords.txt` | Mots de passe générés par Wazuh |

## 🔄 Gestion des mots de passe

```bash
# Changer TOUS les mots de passe
sudo /opt/siem-africa/scripts/change_passwords.sh --all

# Options disponibles
sudo /opt/siem-africa/scripts/change_passwords.sh --snort
sudo /opt/siem-africa/scripts/change_passwords.sh --wazuh
sudo /opt/siem-africa/scripts/change_passwords.sh --siem
sudo /opt/siem-africa/scripts/change_passwords.sh --dashboard
sudo /opt/siem-africa/scripts/change_passwords.sh --wazuh-admin
```

## 🔍 Commandes de vérification

```bash
# État des services
systemctl status snort wazuh-indexer wazuh-manager wazuh-dashboard siem-africa-dashboard

# Ports en écoute
ss -tlnp | grep -E '443|5000|9200|55000|1514'

# Test connectivité
curl -k https://localhost:443    # Wazuh Dashboard
curl -k https://localhost:5000   # SIEM Africa

# Base de données
sqlite3 /opt/siem-africa/database/siem_africa.db "SELECT COUNT(*) FROM regles;"

# Diagnostic complet
sudo /opt/siem-africa/scripts/diagnostic.sh
```

## 📁 Structure des fichiers

```
/opt/siem-africa/
├── database/
│   └── siem_africa.db      # 507 règles traduites
├── dashboard/
│   └── app.py              # Application Flask
├── templates/              # Templates HTML
├── static/                 # CSS, JS, images
├── scripts/
│   ├── change_passwords.sh # Gestion mots de passe
│   └── diagnostic.sh       # Diagnostic système
├── certs/                  # Certificats SSL
├── logs/                   # Logs application
├── SCRID.txt              # Identifiants + commandes
└── .first_run             # Flag première exécution
```

## 📊 Contenu de la base de données

- **507 règles** traduites en français
  - 207 règles Wazuh
  - 300 règles Snort
- **25 catégories** d'alertes
- **Recommandations** contextuelles pour règles critiques
- **Mapping MITRE ATT&CK** complet

## 🆘 Dépannage

```bash
# Logs d'installation
tail -f /var/log/siem-africa-install.log

# Logs Snort
tail -f /var/log/snort/alert

# Logs Wazuh
tail -f /var/ossec/logs/alerts/alerts.log

# Logs SIEM Africa
tail -f /opt/siem-africa/logs/error.log

# Redémarrer tous les services
sudo systemctl restart snort wazuh-indexer wazuh-manager wazuh-dashboard siem-africa-dashboard
```

## 📜 Licence



---

**SIEM Africa** - Solution de Cybersécurité pour les PME Africaines 🌍🔒


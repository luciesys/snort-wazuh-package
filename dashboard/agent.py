#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM AFRICA - Agent d'Interprétation
=====================================
Cet agent interroge l'API Wazuh toutes les 30 secondes,
récupère les nouvelles alertes, les interprète grâce à la
base de données locale, et les stocke pour le dashboard.

Auteur: SIEM Africa Team
Version: 1.0
"""

import sqlite3
import requests
import json
import time
import logging
import os
import urllib3
from datetime import datetime, timedelta
from pathlib import Path

# Désactiver les warnings SSL (Wazuh utilise des certificats auto-signés)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# CONFIGURATION
# ============================================================================
CONFIG = {
    'wazuh_host': 'localhost',
    'wazuh_port': 55000,
    'wazuh_user': 'wazuh',
    'wazuh_password': 'wazuh',
    'db_path': '/opt/siem-africa/database/siem_africa.db',
    'log_path': '/var/log/siem-africa/agent.log',
    'check_interval': 30,
    'alerts_limit': 100,
}

# ============================================================================
# LOGGING
# ============================================================================
def setup_logging():
    log_dir = os.path.dirname(CONFIG['log_path'])
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(CONFIG['log_path']),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('siem-africa-agent')

# ============================================================================
# CONNEXION WAZUH API
# ============================================================================
class WazuhConnector:
    def __init__(self, host, port, user, password):
        self.base_url = f"https://{host}:{port}"
        self.user = user
        self.password = password
        self.token = None
        self.token_expiry = None
        self.logger = logging.getLogger('siem-africa-agent')
    
    def authenticate(self):
        try:
            url = f"{self.base_url}/security/user/authenticate"
            response = requests.post(
                url,
                auth=(self.user, self.password),
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data['data']['token']
                self.token_expiry = datetime.now() + timedelta(minutes=14)
                self.logger.info("✅ Authentification Wazuh réussie")
                return True
            else:
                self.logger.error(f"❌ Échec authentification: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Erreur connexion Wazuh: {str(e)}")
            return False
    
    def get_token(self):
        if self.token is None or datetime.now() >= self.token_expiry:
            if not self.authenticate():
                return None
        return self.token
    
    def get_alerts(self, limit=100, offset=0):
        token = self.get_token()
        if not token:
            return None
        
        try:
            url = f"{self.base_url}/alerts"
            headers = {"Authorization": f"Bearer {token}"}
            params = {
                "limit": limit,
                "offset": offset,
                "sort": "-timestamp"
            }
            
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json().get('data', {}).get('affected_items', [])
            else:
                self.logger.warning(f"⚠️ Erreur récupération alertes: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"❌ Erreur API alertes: {str(e)}")
            return []

# ============================================================================
# INTERPRÉTEUR D'ALERTES
# ============================================================================
class AlertInterpreter:
    def __init__(self, db_path):
        self.db_path = db_path
        self.logger = logging.getLogger('siem-africa-agent')
        self.conn = None
    
    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            self.logger.info(f"✅ Connexion BDD: {self.db_path}")
            return True
        except Exception as e:
            self.logger.error(f"❌ Erreur connexion BDD: {str(e)}")
            return False
    
    def close(self):
        if self.conn:
            self.conn.close()
    
    def get_rule_info(self, wazuh_rule_id):
        try:
            cursor = self.conn.cursor()
            
            cursor.execute("""
                SELECT r.*, c.nom as categorie_nom, c.icone, c.couleur
                FROM regles r
                LEFT JOIN categories c ON r.categorie_id = c.id
                WHERE r.wazuh_rule_id = ?
            """, (wazuh_rule_id,))
            
            rule = cursor.fetchone()
            
            if rule:
                cursor.execute("""
                    SELECT action, commande, niveau, ordre
                    FROM recommandations
                    WHERE regle_id = ?
                    ORDER BY ordre
                """, (rule['id'],))
                
                recommandations = cursor.fetchall()
                
                return {
                    'found': True,
                    'rule': dict(rule),
                    'recommandations': [dict(r) for r in recommandations]
                }
            else:
                return self.get_unknown_rule_info()
                
        except Exception as e:
            self.logger.error(f"❌ Erreur lecture règle {wazuh_rule_id}: {str(e)}")
            return self.get_unknown_rule_info()
    
    def get_unknown_rule_info(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT r.*, c.nom as categorie_nom, c.icone, c.couleur
                FROM regles r
                LEFT JOIN categories c ON r.categorie_id = c.id
                WHERE r.wazuh_rule_id = 99999
            """)
            rule = cursor.fetchone()
            
            cursor.execute("""
                SELECT action, commande, niveau, ordre
                FROM recommandations r2
                JOIN regles r ON r2.regle_id = r.id
                WHERE r.wazuh_rule_id = 99999
                ORDER BY ordre
            """)
            recommandations = cursor.fetchall()
            
            return {
                'found': False,
                'rule': dict(rule) if rule else None,
                'recommandations': [dict(r) for r in recommandations]
            }
        except:
            return {'found': False, 'rule': None, 'recommandations': []}
    
    def alert_exists(self, wazuh_alert_id):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT id FROM alertes_log WHERE wazuh_alert_id = ?",
                (wazuh_alert_id,)
            )
            return cursor.fetchone() is not None
        except:
            return False
    
    def store_alert(self, alert_data, rule_info):
        try:
            cursor = self.conn.cursor()
            
            cursor.execute("""
                INSERT INTO alertes_log (
                    wazuh_alert_id, wazuh_rule_id, timestamp,
                    agent_id, agent_name, agent_ip,
                    source_ip, source_port, dest_ip, dest_port,
                    protocole, utilisateur, description_wazuh,
                    raw_log, statut
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_data.get('id', ''),
                alert_data.get('rule', {}).get('id', 0),
                alert_data.get('timestamp', datetime.now().isoformat()),
                alert_data.get('agent', {}).get('id', ''),
                alert_data.get('agent', {}).get('name', ''),
                alert_data.get('agent', {}).get('ip', ''),
                alert_data.get('data', {}).get('srcip', ''),
                alert_data.get('data', {}).get('srcport', None),
                alert_data.get('data', {}).get('dstip', ''),
                alert_data.get('data', {}).get('dstport', None),
                alert_data.get('data', {}).get('protocol', ''),
                alert_data.get('data', {}).get('srcuser', ''),
                alert_data.get('rule', {}).get('description', ''),
                json.dumps(alert_data),
                'nouveau'
            ))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Erreur stockage alerte: {str(e)}")
            return False

# ============================================================================
# AGENT PRINCIPAL
# ============================================================================
class SIEMAfricaAgent:
    def __init__(self, config):
        self.config = config
        self.logger = setup_logging()
        self.wazuh = WazuhConnector(
            config['wazuh_host'],
            config['wazuh_port'],
            config['wazuh_user'],
            config['wazuh_password']
        )
        self.interpreter = AlertInterpreter(config['db_path'])
        self.running = True
        self.stats = {
            'total_processed': 0,
            'new_alerts': 0,
            'known_rules': 0,
            'unknown_rules': 0,
            'errors': 0
        }
    
    def start(self):
        self.logger.info("=" * 60)
        self.logger.info("🛡️  SIEM AFRICA - Agent d'Interprétation")
        self.logger.info("=" * 60)
        
        if not self.interpreter.connect():
            self.logger.error("❌ Impossible de démarrer sans BDD")
            return False
        
        if not self.wazuh.authenticate():
            self.logger.warning("⚠️ Connexion Wazuh échouée - Réessai dans 30s")
        
        self.logger.info(f"⏱️  Intervalle de vérification: {self.config['check_interval']}s")
        self.logger.info("🚀 Agent démarré - En attente d'alertes...")
        
        while self.running:
            try:
                self.process_alerts()
                time.sleep(self.config['check_interval'])
            except KeyboardInterrupt:
                self.logger.info("🛑 Arrêt demandé par l'utilisateur")
                self.running = False
            except Exception as e:
                self.logger.error(f"❌ Erreur dans la boucle principale: {str(e)}")
                self.stats['errors'] += 1
                time.sleep(self.config['check_interval'])
        
        self.stop()
        return True
    
    def process_alerts(self):
        alerts = self.wazuh.get_alerts(limit=self.config['alerts_limit'])
        
        if alerts is None:
            self.logger.warning("⚠️ Impossible de récupérer les alertes")
            return
        
        new_count = 0
        
        for alert in alerts:
            alert_id = alert.get('id', '')
            
            if self.interpreter.alert_exists(alert_id):
                continue
            
            rule_id = alert.get('rule', {}).get('id', 0)
            rule_info = self.interpreter.get_rule_info(rule_id)
            
            if self.interpreter.store_alert(alert, rule_info):
                new_count += 1
                self.stats['new_alerts'] += 1
                
                if rule_info['found']:
                    self.stats['known_rules'] += 1
                    gravite = rule_info['rule'].get('gravite', 'moyenne')
                    nom = rule_info['rule'].get('nom_fr', 'Alerte')
                else:
                    self.stats['unknown_rules'] += 1
                    gravite = 'moyenne'
                    nom = 'Alerte non identifiée'
                
                icon = {'critique': '🔴', 'haute': '🟠', 'moyenne': '🟡', 'faible': '🟢', 'info': 'ℹ️'}.get(gravite, '⚪')
                self.logger.info(f"{icon} Nouvelle alerte: {nom} (Rule {rule_id})")
        
        self.stats['total_processed'] += len(alerts)
        
        if new_count > 0:
            self.logger.info(f"📊 {new_count} nouvelle(s) alerte(s) traitée(s)")
    
    def stop(self):
        self.logger.info("-" * 60)
        self.logger.info("📊 STATISTIQUES DE SESSION")
        self.logger.info(f"   Alertes traitées: {self.stats['total_processed']}")
        self.logger.info(f"   Nouvelles alertes: {self.stats['new_alerts']}")
        self.logger.info(f"   Règles connues: {self.stats['known_rules']}")
        self.logger.info(f"   Règles inconnues: {self.stats['unknown_rules']}")
        self.logger.info(f"   Erreurs: {self.stats['errors']}")
        self.logger.info("-" * 60)
        self.logger.info("🛑 Agent arrêté")
        self.interpreter.close()

# ============================================================================
# POINT D'ENTRÉE
# ============================================================================
def load_config():
    config = CONFIG.copy()
    
    config_file = '/opt/siem-africa/config.json'
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except:
            pass
    
    config['wazuh_host'] = os.environ.get('WAZUH_HOST', config['wazuh_host'])
    config['wazuh_port'] = int(os.environ.get('WAZUH_PORT', config['wazuh_port']))
    config['wazuh_user'] = os.environ.get('WAZUH_USER', config['wazuh_user'])
    config['wazuh_password'] = os.environ.get('WAZUH_PASSWORD', config['wazuh_password'])
    
    return config

def main():
    config = load_config()
    agent = SIEMAfricaAgent(config)
    agent.start()

if __name__ == "__main__":
    main()

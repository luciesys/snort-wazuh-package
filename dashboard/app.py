#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM AFRICA - Dashboard Web
============================
Interface web simple pour visualiser les alertes de sécurité
interprétées par l'agent SIEM Africa.

Auteur: SIEM Africa Team
Version: 1.0
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
import sqlite3
import json
import os
from datetime import datetime, timedelta

# ============================================================================
# CONFIGURATION
# ============================================================================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'siem-africa-secret-key-2026')

DB_PATH = os.environ.get('SIEM_DB_PATH', '/opt/siem-africa/database/siem_africa.db')

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def format_timestamp(timestamp_str):
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime('%d/%m/%Y %H:%M:%S')
    except:
        return timestamp_str

def get_gravite_info(gravite):
    info = {
        'critique': {'icon': '🔴', 'color': '#dc3545', 'label': 'Critique', 'class': 'danger'},
        'haute': {'icon': '🟠', 'color': '#fd7e14', 'label': 'Haute', 'class': 'warning'},
        'moyenne': {'icon': '🟡', 'color': '#ffc107', 'label': 'Moyenne', 'class': 'info'},
        'faible': {'icon': '🟢', 'color': '#28a745', 'label': 'Faible', 'class': 'success'},
        'info': {'icon': 'ℹ️', 'color': '#17a2b8', 'label': 'Info', 'class': 'secondary'}
    }
    return info.get(gravite, info['moyenne'])

# ============================================================================
# ROUTES - PAGES
# ============================================================================
@app.route('/')
def index():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT r.gravite, COUNT(*) as total
        FROM alertes_log a
        LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
        WHERE a.statut NOT IN ('traite', 'ignore', 'faux_positif')
        GROUP BY r.gravite
    """)
    stats_gravite = {row['gravite'] or 'moyenne': row['total'] for row in cursor.fetchall()}
    
    for g in ['critique', 'haute', 'moyenne', 'faible', 'info']:
        if g not in stats_gravite:
            stats_gravite[g] = 0
    
    cursor.execute("""
        SELECT COUNT(*) as total FROM alertes_log 
        WHERE statut NOT IN ('traite', 'ignore', 'faux_positif')
    """)
    total_alertes = cursor.fetchone()['total']
    
    cursor.execute("""
        SELECT 
            a.id, a.timestamp, a.source_ip, a.agent_name, a.statut,
            a.wazuh_rule_id,
            COALESCE(r.nom_fr, 'Alerte non identifiée') as nom_alerte,
            COALESCE(r.gravite, 'moyenne') as gravite,
            COALESCE(c.icone, '❓') as icone,
            COALESCE(c.nom, 'Non identifié') as categorie
        FROM alertes_log a
        LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
        LEFT JOIN categories c ON r.categorie_id = c.id
        WHERE a.statut NOT IN ('traite', 'ignore', 'faux_positif')
        ORDER BY a.timestamp DESC
        LIMIT 20
    """)
    alertes = cursor.fetchall()
    
    cursor.execute("""
        SELECT 
            COALESCE(c.nom, 'Non identifié') as categorie,
            COALESCE(c.icone, '❓') as icone,
            COUNT(*) as total
        FROM alertes_log a
        LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
        LEFT JOIN categories c ON r.categorie_id = c.id
        WHERE a.statut NOT IN ('traite', 'ignore', 'faux_positif')
        GROUP BY c.id
        ORDER BY total DESC
        LIMIT 5
    """)
    stats_categories = cursor.fetchall()
    
    conn.close()
    
    return render_template('index.html',
        stats_gravite=stats_gravite,
        total_alertes=total_alertes,
        alertes=alertes,
        stats_categories=stats_categories,
        get_gravite_info=get_gravite_info,
        format_timestamp=format_timestamp
    )

@app.route('/alerte/<int:alerte_id>')
def detail_alerte(alerte_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            a.*,
            COALESCE(r.nom_fr, 'Alerte non identifiée') as nom_alerte,
            COALESCE(r.description, 'Aucune description disponible') as description_fr,
            COALESCE(r.gravite, 'moyenne') as gravite,
            r.impact,
            r.cause_probable,
            r.mitre_id,
            COALESCE(c.nom, 'Non identifié') as categorie,
            COALESCE(c.icone, '❓') as icone
        FROM alertes_log a
        LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
        LEFT JOIN categories c ON r.categorie_id = c.id
        WHERE a.id = ?
    """, (alerte_id,))
    
    alerte = cursor.fetchone()
    
    if not alerte:
        conn.close()
        return "Alerte non trouvée", 404
    
    cursor.execute("""
        SELECT rec.action, rec.commande, rec.niveau, rec.ordre
        FROM recommandations rec
        JOIN regles r ON rec.regle_id = r.id
        WHERE r.wazuh_rule_id = ?
        ORDER BY rec.ordre
    """, (alerte['wazuh_rule_id'],))
    
    recommandations = cursor.fetchall()
    
    if not recommandations:
        cursor.execute("""
            SELECT rec.action, rec.commande, rec.niveau, rec.ordre
            FROM recommandations rec
            JOIN regles r ON rec.regle_id = r.id
            WHERE r.wazuh_rule_id = 99999
            ORDER BY rec.ordre
        """)
        recommandations = cursor.fetchall()
    
    if alerte['statut'] == 'nouveau':
        cursor.execute(
            "UPDATE alertes_log SET statut = 'vu' WHERE id = ?",
            (alerte_id,)
        )
        conn.commit()
    
    conn.close()
    
    return render_template('detail.html',
        alerte=alerte,
        recommandations=recommandations,
        get_gravite_info=get_gravite_info,
        format_timestamp=format_timestamp
    )

@app.route('/alertes')
def liste_alertes():
    conn = get_db()
    cursor = conn.cursor()
    
    gravite = request.args.get('gravite', '')
    statut = request.args.get('statut', '')
    categorie = request.args.get('categorie', '')
    
    query = """
        SELECT 
            a.id, a.timestamp, a.source_ip, a.agent_name, a.statut,
            a.wazuh_rule_id,
            COALESCE(r.nom_fr, 'Alerte non identifiée') as nom_alerte,
            COALESCE(r.gravite, 'moyenne') as gravite,
            COALESCE(c.icone, '❓') as icone,
            COALESCE(c.nom, 'Non identifié') as categorie
        FROM alertes_log a
        LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
        LEFT JOIN categories c ON r.categorie_id = c.id
        WHERE 1=1
    """
    params = []
    
    if gravite:
        query += " AND r.gravite = ?"
        params.append(gravite)
    
    if statut:
        query += " AND a.statut = ?"
        params.append(statut)
    
    if categorie:
        query += " AND c.nom = ?"
        params.append(categorie)
    
    query += " ORDER BY a.timestamp DESC LIMIT 100"
    
    cursor.execute(query, params)
    alertes = cursor.fetchall()
    
    cursor.execute("SELECT DISTINCT nom FROM categories ORDER BY nom")
    categories = cursor.fetchall()
    
    conn.close()
    
    return render_template('alertes.html',
        alertes=alertes,
        categories=categories,
        filtre_gravite=gravite,
        filtre_statut=statut,
        filtre_categorie=categorie,
        get_gravite_info=get_gravite_info,
        format_timestamp=format_timestamp
    )

# ============================================================================
# ROUTES - ACTIONS
# ============================================================================
@app.route('/alerte/<int:alerte_id>/action', methods=['POST'])
def action_alerte(alerte_id):
    action = request.form.get('action')
    note = request.form.get('note', '')
    
    if action not in ['traite', 'ignore', 'faux_positif', 'en_cours']:
        return "Action invalide", 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE alertes_log 
        SET statut = ?, notes = COALESCE(notes || '\n', '') || ?
        WHERE id = ?
    """, (action, f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}" if note else '', alerte_id))
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('index'))

# ============================================================================
# ROUTES - API JSON
# ============================================================================
@app.route('/api/stats')
def api_stats():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT r.gravite, COUNT(*) as total
        FROM alertes_log a
        LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
        WHERE a.statut NOT IN ('traite', 'ignore', 'faux_positif')
        GROUP BY r.gravite
    """)
    stats = {row['gravite'] or 'moyenne': row['total'] for row in cursor.fetchall()}
    
    conn.close()
    return jsonify(stats)

@app.route('/api/alertes/recent')
def api_alertes_recent():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            a.id, a.timestamp, a.source_ip,
            COALESCE(r.nom_fr, 'Non identifiée') as nom,
            COALESCE(r.gravite, 'moyenne') as gravite
        FROM alertes_log a
        LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
        WHERE a.statut NOT IN ('traite', 'ignore', 'faux_positif')
        ORDER BY a.timestamp DESC
        LIMIT 10
    """)
    
    alertes = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(alertes)

# ============================================================================
# FILTRES JINJA2
# ============================================================================
@app.template_filter('timeago')
def timeago_filter(timestamp_str):
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        diff = now - dt
        
        if diff.days > 0:
            return f"il y a {diff.days} jour(s)"
        elif diff.seconds > 3600:
            return f"il y a {diff.seconds // 3600} heure(s)"
        elif diff.seconds > 60:
            return f"il y a {diff.seconds // 60} minute(s)"
        else:
            return "à l'instant"
    except:
        return timestamp_str

# ============================================================================
# POINT D'ENTRÉE
# ============================================================================
if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print(f"❌ Base de données non trouvée: {DB_PATH}")
        print("   Exécutez d'abord le script d'installation.")
        exit(1)
    
    print("=" * 60)
    print("🛡️  SIEM AFRICA - Dashboard Web")
    print("=" * 60)
    print(f"📊 Base de données: {DB_PATH}")
    print(f"🌐 Accès: http://localhost:5000")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIEM AFRICA - Dashboard Web avec Authentification
==================================================
Interface web sécurisée avec:
- Authentification obligatoire
- HTTPS
- Expiration mot de passe (90 jours)
- Verrouillage après 5 tentatives

Auteur: SIEM Africa Team
Version: 2.0
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import secrets
import os
from datetime import datetime, timedelta
from functools import wraps

# ============================================================================
# CONFIGURATION
# ============================================================================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=8)

DB_PATH = os.environ.get('SIEM_DB_PATH', '/opt/siem-africa/database/siem_africa.db')

# Configuration mot de passe
PASSWORD_VALIDITY_DAYS = 90
PASSWORD_ALERT_DAYS_1 = 15  # Première alerte
PASSWORD_ALERT_DAYS_2 = 5   # Alerte urgente
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
DEFAULT_PASSWORD = 'SiemAfrica2026!'

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """Hash le mot de passe avec SHA256 + sel"""
    salt = "siem_africa_2026"
    return hashlib.sha256((password + salt).encode()).hexdigest()

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

def log_audit(username, action, ip_address, details, success):
    """Enregistre une action dans le journal d'audit"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (username, action, ip_address, details, success)
            VALUES (?, ?, ?, ?, ?)
        """, (username, action, ip_address, details, 1 if success else 0))
        conn.commit()
        conn.close()
    except:
        pass

def get_password_expiry_warning(user):
    """Retourne un message d'avertissement si le mot de passe expire bientôt"""
    if not user['password_expires_at']:
        return None
    
    try:
        expires_at = datetime.fromisoformat(user['password_expires_at'])
        now = datetime.now()
        days_left = (expires_at - now).days
        
        if days_left <= 0:
            return {'level': 'danger', 'message': 'Votre mot de passe a expiré. Vous devez le changer immédiatement.', 'days': 0}
        elif days_left <= PASSWORD_ALERT_DAYS_2:
            return {'level': 'danger', 'message': f'⚠️ URGENT: Votre mot de passe expire dans {days_left} jour(s) !', 'days': days_left}
        elif days_left <= PASSWORD_ALERT_DAYS_1:
            return {'level': 'warning', 'message': f'Votre mot de passe expire dans {days_left} jour(s).', 'days': days_left}
    except:
        pass
    
    return None

def validate_password(password):
    """Vérifie que le mot de passe respecte les règles de sécurité"""
    errors = []
    
    if len(password) < 8:
        errors.append("Le mot de passe doit contenir au moins 8 caractères")
    if not any(c.isupper() for c in password):
        errors.append("Le mot de passe doit contenir au moins une majuscule")
    if not any(c.islower() for c in password):
        errors.append("Le mot de passe doit contenir au moins une minuscule")
    if not any(c.isdigit() for c in password):
        errors.append("Le mot de passe doit contenir au moins un chiffre")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Le mot de passe doit contenir au moins un caractère spécial (!@#$%...)")
    
    return errors

# ============================================================================
# DÉCORATEURS
# ============================================================================
def login_required(f):
    """Décorateur pour protéger les routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'warning')
            return redirect(url_for('login'))
        
        # Vérifier si le mot de passe doit être changé
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT must_change_password FROM utilisateurs WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if user and user['must_change_password'] == 1:
            return redirect(url_for('change_password'))
        
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# ROUTES - AUTHENTIFICATION
# ============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier si l'utilisateur existe
        cursor.execute("SELECT * FROM utilisateurs WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            log_audit(username, 'LOGIN_FAILED', ip_address, 'Utilisateur inconnu', False)
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'danger')
            conn.close()
            return render_template('login.html')
        
        # Vérifier si le compte est verrouillé
        if user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < locked_until:
                remaining = int((locked_until - datetime.now()).total_seconds() / 60) + 1
                log_audit(username, 'LOGIN_BLOCKED', ip_address, f'Compte verrouillé, {remaining} min restantes', False)
                flash(f'Compte verrouillé. Réessayez dans {remaining} minute(s).', 'danger')
                conn.close()
                return render_template('login.html')
            else:
                # Déverrouiller le compte
                cursor.execute("UPDATE utilisateurs SET locked_until = NULL, failed_attempts = 0 WHERE id = ?", (user['id'],))
                conn.commit()
        
        # Vérifier le mot de passe
        if hash_password(password) != user['password_hash']:
            # Incrémenter les tentatives échouées
            failed_attempts = user['failed_attempts'] + 1
            
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                # Verrouiller le compte
                locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                cursor.execute("""
                    UPDATE utilisateurs 
                    SET failed_attempts = ?, locked_until = ?
                    WHERE id = ?
                """, (failed_attempts, locked_until.isoformat(), user['id']))
                log_audit(username, 'ACCOUNT_LOCKED', ip_address, f'{MAX_FAILED_ATTEMPTS} tentatives échouées', False)
                flash(f'Trop de tentatives échouées. Compte verrouillé pendant {LOCKOUT_DURATION_MINUTES} minutes.', 'danger')
            else:
                cursor.execute("UPDATE utilisateurs SET failed_attempts = ? WHERE id = ?", (failed_attempts, user['id']))
                remaining = MAX_FAILED_ATTEMPTS - failed_attempts
                log_audit(username, 'LOGIN_FAILED', ip_address, f'Mot de passe incorrect, {remaining} tentatives restantes', False)
                flash(f'Mot de passe incorrect. {remaining} tentative(s) restante(s).', 'danger')
            
            conn.commit()
            conn.close()
            return render_template('login.html')
        
        # Connexion réussie
        cursor.execute("""
            UPDATE utilisateurs 
            SET failed_attempts = 0, locked_until = NULL, last_login = ?
            WHERE id = ?
        """, (datetime.now().isoformat(), user['id']))
        conn.commit()
        conn.close()
        
        # Créer la session
        session.permanent = True
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['must_change_password'] = user['must_change_password']
        
        log_audit(username, 'LOGIN_SUCCESS', ip_address, 'Connexion réussie', True)
        
        # Rediriger vers changement de mot de passe si nécessaire
        if user['must_change_password'] == 1:
            flash('Vous devez changer votre mot de passe pour continuer.', 'warning')
            return redirect(url_for('change_password'))
        
        # Vérifier si le mot de passe a expiré
        if user['password_expires_at']:
            expires_at = datetime.fromisoformat(user['password_expires_at'])
            if datetime.now() > expires_at:
                session['must_change_password'] = 1
                flash('Votre mot de passe a expiré. Vous devez le changer.', 'danger')
                return redirect(url_for('change_password'))
        
        return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    log_audit(username, 'LOGOUT', request.remote_addr, 'Déconnexion', True)
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM utilisateurs WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        
        # Vérifier le mot de passe actuel (sauf si c'est le premier changement)
        if user['must_change_password'] != 1:
            if hash_password(current_password) != user['password_hash']:
                flash('Mot de passe actuel incorrect.', 'danger')
                conn.close()
                return render_template('change_password.html', must_change=user['must_change_password'])
        
        # Vérifier que les nouveaux mots de passe correspondent
        if new_password != confirm_password:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            conn.close()
            return render_template('change_password.html', must_change=user['must_change_password'])
        
        # Valider le nouveau mot de passe
        errors = validate_password(new_password)
        if errors:
            for error in errors:
                flash(error, 'danger')
            conn.close()
            return render_template('change_password.html', must_change=user['must_change_password'])
        
        # Vérifier que le nouveau mot de passe n'est pas dans l'historique
        new_hash = hash_password(new_password)
        password_history = user['password_history'] or ''
        if new_hash in password_history.split(','):
            flash('Vous ne pouvez pas réutiliser un ancien mot de passe.', 'danger')
            conn.close()
            return render_template('change_password.html', must_change=user['must_change_password'])
        
        # Mettre à jour l'historique (garder les 3 derniers)
        history_list = password_history.split(',') if password_history else []
        history_list.insert(0, user['password_hash'])
        history_list = history_list[:3]
        new_history = ','.join(history_list)
        
        # Mettre à jour le mot de passe
        cursor.execute("""
            UPDATE utilisateurs 
            SET password_hash = ?,
                must_change_password = 0,
                password_created_at = ?,
                password_expires_at = ?,
                password_history = ?
            WHERE id = ?
        """, (
            new_hash,
            datetime.now().isoformat(),
            (datetime.now() + timedelta(days=PASSWORD_VALIDITY_DAYS)).isoformat(),
            new_history,
            session['user_id']
        ))
        
        conn.commit()
        conn.close()
        
        session['must_change_password'] = 0
        log_audit(session['username'], 'PASSWORD_CHANGED', request.remote_addr, 'Mot de passe changé', True)
        flash('Mot de passe changé avec succès !', 'success')
        
        return redirect(url_for('index'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT must_change_password FROM utilisateurs WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    return render_template('change_password.html', must_change=user['must_change_password'] if user else 0)

# ============================================================================
# ROUTES - DASHBOARD
# ============================================================================
@app.route('/')
@login_required
def index():
    conn = get_db()
    cursor = conn.cursor()
    
    # Récupérer l'utilisateur pour l'alerte d'expiration
    cursor.execute("SELECT * FROM utilisateurs WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    password_warning = get_password_expiry_warning(user) if user else None
    
    # Statistiques par gravité
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
    
    # Total des alertes
    cursor.execute("""
        SELECT COUNT(*) as total FROM alertes_log 
        WHERE statut NOT IN ('traite', 'ignore', 'faux_positif')
    """)
    total_alertes = cursor.fetchone()['total']
    
    # Total alertes aujourd'hui
    cursor.execute("""
        SELECT COUNT(*) as total FROM alertes_log 
        WHERE date(timestamp) = date('now')
    """)
    alertes_today = cursor.fetchone()['total']
    
    # Dernières alertes
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
        LIMIT 10
    """)
    alertes = cursor.fetchall()
    
    # Top 5 IP attaquantes
    cursor.execute("""
        SELECT source_ip, COUNT(*) as total
        FROM alertes_log
        WHERE source_ip IS NOT NULL AND source_ip != ''
        AND statut NOT IN ('traite', 'ignore', 'faux_positif')
        GROUP BY source_ip
        ORDER BY total DESC
        LIMIT 5
    """)
    top_ips = cursor.fetchall()
    
    # Top 5 règles déclenchées
    cursor.execute("""
        SELECT 
            COALESCE(r.nom_fr, 'Non identifiée') as nom,
            COUNT(*) as total
        FROM alertes_log a
        LEFT JOIN regles r ON a.wazuh_rule_id = r.wazuh_rule_id
        WHERE a.statut NOT IN ('traite', 'ignore', 'faux_positif')
        GROUP BY a.wazuh_rule_id
        ORDER BY total DESC
        LIMIT 5
    """)
    top_rules = cursor.fetchall()
    
    # Statistiques par catégorie
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
    
    # Alertes par heure (24 dernières heures)
    cursor.execute("""
        SELECT strftime('%H', timestamp) as heure, COUNT(*) as total
        FROM alertes_log
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY heure
        ORDER BY heure
    """)
    alertes_par_heure = {row['heure']: row['total'] for row in cursor.fetchall()}
    
    # Compléter avec des zéros pour les heures manquantes
    for h in range(24):
        heure_str = f"{h:02d}"
        if heure_str not in alertes_par_heure:
            alertes_par_heure[heure_str] = 0
    
    conn.close()
    
    # Calcul du score de sécurité (0-100)
    total_non_traite = sum(stats_gravite.values())
    if total_non_traite == 0:
        security_score = 100
    else:
        # Pénalités selon gravité
        penalty = (stats_gravite['critique'] * 20 + 
                  stats_gravite['haute'] * 10 + 
                  stats_gravite['moyenne'] * 5 + 
                  stats_gravite['faible'] * 2)
        security_score = max(0, 100 - penalty)
    
    return render_template('index.html',
        username=session.get('username'),
        password_warning=password_warning,
        stats_gravite=stats_gravite,
        total_alertes=total_alertes,
        alertes_today=alertes_today,
        alertes=alertes,
        top_ips=top_ips,
        top_rules=top_rules,
        stats_categories=stats_categories,
        alertes_par_heure=dict(sorted(alertes_par_heure.items())),
        security_score=security_score,
        get_gravite_info=get_gravite_info,
        format_timestamp=format_timestamp
    )

@app.route('/alerte/<int:alerte_id>')
@login_required
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
        cursor.execute("UPDATE alertes_log SET statut = 'vu' WHERE id = ?", (alerte_id,))
        conn.commit()
    
    conn.close()
    
    return render_template('detail.html',
        alerte=alerte,
        recommandations=recommandations,
        get_gravite_info=get_gravite_info,
        format_timestamp=format_timestamp
    )

@app.route('/alertes')
@login_required
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

@app.route('/alerte/<int:alerte_id>/action', methods=['POST'])
@login_required
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
    """, (action, f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {session.get('username')}: {note}" if note else '', alerte_id))
    
    conn.commit()
    conn.close()
    
    log_audit(session.get('username'), f'ALERT_{action.upper()}', request.remote_addr, f'Alerte {alerte_id}', True)
    
    return redirect(url_for('index'))

# ============================================================================
# ROUTES - API
# ============================================================================
@app.route('/api/stats')
@login_required
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
        exit(1)
    
    # Créer l'utilisateur par défaut si nécessaire
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM utilisateurs")
        if cursor.fetchone()['count'] == 0:
            cursor.execute("""
                INSERT INTO utilisateurs (username, password_hash, must_change_password, password_expires_at)
                VALUES (?, ?, 1, datetime('now', '+90 days'))
            """, ('admin', hash_password(DEFAULT_PASSWORD)))
            conn.commit()
        conn.close()
    except:
        pass
    
    print("=" * 60)
    print("🛡️  SIEM AFRICA - Dashboard Web Sécurisé")
    print("=" * 60)
    print(f"🔐 Utilisateur par défaut: admin / {DEFAULT_PASSWORD}")
    print(f"🌐 Accès: https://localhost:5000")
    print("=" * 60)
    
    # Lancer avec HTTPS
    ssl_cert = '/opt/siem-africa/ssl/cert.pem'
    ssl_key = '/opt/siem-africa/ssl/key.pem'
    
    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        app.run(host='0.0.0.0', port=5000, ssl_context=(ssl_cert, ssl_key), debug=False)
    else:
        print("⚠️ Certificats SSL non trouvés, démarrage en HTTP")
        app.run(host='0.0.0.0', port=5000, debug=False)

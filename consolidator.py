#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Outil de consolidation et d'analyse pour les rapports de sécurité JSON.
"""

import argparse
import json
import os
from datetime import datetime
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt


SCAN_REPORTS_DIR = "scans/"

# Copied from security_checker.py to make the tool self-contained
REMEDIATION_ADVICE = {
    "CERT_EXPIRED": { "default": "Renouvelez votre certificat SSL/TLS immédiatement." },
    "CERT_VERIFY_FAILED": { "default": "Vérifiez que votre chaîne de certificats est complète (certificats intermédiaires) et que le certificat n'est pas auto-signé." },
    "TLS_OBSOLETE": { "description": "Désactivez les protocoles SSL/TLS obsolètes.", "nginx": "Dans votre bloc server, utilisez : ssl_protocols TLSv1.2 TLSv1.3;", "apache": "Dans votre configuration SSL, utilisez : SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", "default": "Consultez la documentation de votre serveur pour désactiver SSLv3, TLSv1.0 et TLSv1.1." },
    "NO_HTTPS_REDIRECT": { "nginx": "Dans votre bloc server pour le port 80, utilisez : return 301 https://$host$request_uri;", "apache": "Utilisez mod_rewrite pour forcer la redirection vers HTTPS.", "default": "Configurez votre serveur web pour forcer la redirection de tout le trafic HTTP vers HTTPS." },
    "DMARC_MISSING": { "default": "Ajoutez un enregistrement DMARC à votre zone DNS pour protéger contre l'usurpation d'e-mail. Exemple : 'v=DMARC1; p=none; rua=mailto:dmarc-reports@votre-domaine.com;'" },
    "SPF_MISSING": { "default": "Ajoutez un enregistrement SPF à votre zone DNS pour spécifier les serveurs autorisés à envoyer des e-mails pour votre domaine. Exemple : 'v=spf1 include:_spf.google.com ~all'" },
    "COOKIE_NO_SECURE": { "default": "Ajoutez l'attribut 'Secure' à tous vos cookies pour vous assurer qu'ils ne sont envoyés que sur des connexions HTTPS." },
    "COOKIE_NO_HTTPONLY": { "default": "Ajoutez l'attribut 'HttpOnly' à vos cookies de session pour empêcher leur accès via JavaScript." },
    "COOKIE_NO_SAMESITE": { "default": "Ajoutez l'attribut 'SameSite=Strict' ou 'SameSite=Lax' à vos cookies pour vous protéger contre les attaques CSRF." },
    "HSTS_MISSING": { "nginx": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';", "apache": "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'", "default": "Implémentez l'en-tête HSTS avec un 'max-age' d'au moins 6 mois (15552000 secondes)." },
    "XFO_MISSING": { "nginx": "add_header X-Frame-Options 'SAMEORIGIN';", "apache": "Header always set X-Frame-Options 'SAMEORIGIN'", "default": "Ajoutez l'en-tête 'X-Frame-Options: SAMEORIGIN' ou 'DENY' pour vous protéger du clickjacking." },
    "XCTO_MISSING": { "nginx": "add_header X-Content-Type-Options 'nosniff';", "apache": "Header always set X-Content-Type-Options 'nosniff'", "default": "Ajoutez l'en-tête 'X-Content-Type-Options: nosniff'." },
    "CSP_MISSING": { "default": "Envisagez d'implémenter une Content Security Policy (CSP) pour une défense en profondeur contre les attaques par injection de script (XSS)." },
    "SERVER_HEADER_VISIBLE": { "nginx": "Dans votre configuration nginx, ajoutez 'server_tokens off;'.", "apache": "Dans votre configuration apache, ajoutez 'ServerTokens Prod'.", "default": "Supprimez ou masquez les en-têtes qui révèlent la version de votre serveur." },
    "JS_LIB_OBSOLETE": { "default": "Une ou plusieurs bibliothèques JavaScript sont obsolètes. Mettez-les à jour vers leur dernière version stable pour corriger les vulnérabilités connues." },
    "WP_CONFIG_BAK_EXPOSED": { "default": "Supprimez immédiatement le fichier de sauvegarde de configuration WordPress exposé publiquement." },
    "WP_USER_ENUM_ENABLED": { "default": "Empêchez l'énumération des utilisateurs sur WordPress, par exemple en utilisant un plugin de sécurité ou en ajoutant des règles de réécriture." }
}

SUPPORTED_REPORTS = {
    "dmarc": "DMARC_MISSING",
    "spf": "SPF_MISSING",
    "hsts": "HSTS_MISSING",
    "xfo": "XFO_MISSING",
    "xcto": "XCTO_MISSING",
    "csp": "CSP_MISSING",
    "js-libs": "JS_LIB_OBSOLETE",
    "http-redirect": "NO_HTTPS_REDIRECT"
}

def load_scan_results():
    """
    Charge tous les rapports de scan JSON depuis le répertoire `scans/`.

    Retourne:
        list: Une liste de dictionnaires, chaque dictionnaire représentant un scan.
              Ex: [{'domain': 'google.com', 'date': datetime.obj, 'data': {...}}, ...]
    """
    scan_files = [f for f in os.listdir(SCAN_REPORTS_DIR) if f.endswith('.json')]
    results = []
    for filename in scan_files:
        try:
            # Le format du nom de fichier est {hostname}_{ddmmyy}.json
            parts = filename.replace('.json', '').split('_')
            domain = "_".join(parts[:-1])
            date_str = parts[-1]
            scan_date = datetime.strptime(date_str, '%d%m%y')

            filepath = os.path.join(SCAN_REPORTS_DIR, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            results.append({
                "domain": domain,
                "date": scan_date,
                "data": data
            })
        except (IndexError, ValueError, json.JSONDecodeError) as e:
            print(f"Avertissement : Impossible de parser le fichier '{filename}'. Erreur: {e}")
            continue

    # Trie les résultats par domaine puis par date (du plus récent au plus ancien)
    results.sort(key=lambda x: (x['domain'], x['date']), reverse=True)
    return results

def main():
    """
    Fonction principale pour l'outil de consolidation.
    """
    parser = argparse.ArgumentParser(description="Outil de consolidation pour les rapports de sécurité.")
    parser.add_argument("--list-scans", metavar="DOMAIN", help="Liste tous les scans disponibles pour un domaine, triés par date.")
    parser.add_argument("--compare", nargs=3, metavar=("DOMAIN", "DATE1", "DATE2"), help="Compare les scans d'un domaine entre deux dates (format YYYY-MM-DD).")
    parser.add_argument("--quick-wins", metavar="DOMAIN", nargs='?', const="all", help="Identifie les vulnérabilités 'quick win' pour un domaine spécifique ou pour tous les domaines.")
    parser.add_argument("--status", action="store_true", help="Affiche l'état des scans par rapport à une liste de cibles.")
    parser.add_argument("--oldest", action="store_true", help="Affiche les scans les plus anciens.")
    parser.add_argument("--list-expiring-certs", nargs='?', const=30, default=None, type=int, metavar='DAYS', help="Liste les certificats expirant bientôt (par défaut: 30 jours).")
    parser.add_argument("--report", nargs='+', metavar='TYPE', help="Génère un rapport d'actions pour un ou plusieurs types de vulnérabilités (ex: dmarc, hsts, ou 'all').")
    parser.add_argument("--summary-html", action="store_true", help="Génère un rapport de synthèse HTML pour tous les sites cibles.")
    parser.add_argument("--graph", metavar="DOMAIN", help="Génère un graphique d'évolution du score pour un domaine.")

    args = parser.parse_args()

    if not os.path.exists(SCAN_REPORTS_DIR):
        print(f"Le répertoire des scans '{SCAN_REPORTS_DIR}' n'existe pas. Veuillez le créer et y placer vos rapports JSON.")
        return

    all_scans = load_scan_results()

    if not all_scans and not args.status:
        print("Aucun rapport de scan trouvé dans le répertoire 'scans/'.")
        return

    if args.list_scans:
        display_scans_for_domain(all_scans, args.list_scans)
    elif args.compare:
        compare_scans(all_scans, args.compare[0], args.compare[1], args.compare[2])
    elif args.quick_wins:
        display_quick_wins(all_scans, args.quick_wins)
    elif args.status:
        display_scan_status(all_scans)
    elif args.oldest:
        display_oldest_scans(all_scans)
    elif args.list_expiring_certs is not None:
        display_expiring_certificates(all_scans, args.list_expiring_certs)
    elif args.report:
        generate_vulnerability_report(all_scans, args.report)
    elif args.summary_html:
        generate_html_summary(all_scans)
    elif args.graph:
        generate_evolution_graph(all_scans, args.graph)
    else:
        # Si aucune commande n'est spécifiée, afficher un résumé
        print(f"✅ {len(all_scans)} rapport(s) de scan chargé(s).")
        # parser.print_help()

def display_scans_for_domain(all_scans, domain):
    """Affiche tous les scans disponibles pour un domaine spécifique."""
    scans_for_domain = [s for s in all_scans if s['domain'] == domain]
    if not scans_for_domain:
        print(f"Aucun scan trouvé pour le domaine '{domain}'.")
        return

    print(f"🔎 Scans disponibles pour '{domain}':")
    for scan in scans_for_domain:
        date_str = scan['date'].strftime('%Y-%m-%d')
        score = scan['data'].get('score_final', 'N/A')
        grade = scan['data'].get('note', 'N/A')
        print(f"  - Date: {date_str}, Score: {score}, Note: {grade}")

def display_scan_status(all_scans):
    """Affiche l'état des scans par rapport à la liste des cibles."""
    try:
        with open('targets.txt', 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Le fichier 'targets.txt' est introuvable. Veuillez le créer.")
        return

    scanned_domains = {s['domain'] for s in all_scans}
    print("📊 État des scans cibles :")

    scanned_count = 0
    for target in targets:
        if target in scanned_domains:
            print(f"  [✅] {target}")
            scanned_count += 1
        else:
            print(f"  [❌] {target}")

    print(f"\nTotal: {scanned_count} / {len(targets)} cibles scannées.")

def _extract_vulnerabilities(scan_data):
    """Helper pour extraire un set de vulnérabilités identifiables d'un rapport."""
    vulnerabilities = set()

    def find_issues(data, path=""):
        if isinstance(data, dict):
            # Une vulnérabilité est un dictionnaire qui contient un remediation_id
            if 'remediation_id' in data:
                # On vérifie aussi qu'il ne s'agit pas d'un cas "réussi" qui aurait quand même un ID
                # (certains objets comme les cookies en ont)
                is_successful_case = data.get('present') is True or data.get('statut') == 'SUCCESS'
                if not is_successful_case:
                    vuln_id = f"{path}.{data['remediation_id']}"
                    vulnerabilities.add(vuln_id)

            # On continue la récursion même si on a trouvé une vulnérabilité
            # pour les cas où des vulnérabilités sont nichées.
            for key, value in data.items():
                find_issues(value, f"{path}.{key}" if path else key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                find_issues(item, f"{path}[{i}]")

    find_issues(scan_data)
    return vulnerabilities

def compare_scans(all_scans, domain, date1_str, date2_str):
    """Compare deux scans pour un domaine donné."""
    try:
        d1 = datetime.strptime(date1_str, '%Y-%m-%d').date()
        d2 = datetime.strptime(date2_str, '%Y-%m-%d').date()
    except ValueError:
        print("Erreur: Le format de la date doit être YYYY-MM-DD.")
        return

    # S'assurer que d1 est avant d2
    if d1 > d2:
        d1, d2 = d2, d1

    scan1 = next((s for s in all_scans if s['domain'] == domain and s['date'].date() == d1), None)
    scan2 = next((s for s in all_scans if s['domain'] == domain and s['date'].date() == d2), None)

    if not scan1 or not scan2:
        print(f"Impossible de trouver les deux scans pour '{domain}' aux dates {d1} et {d2}.")
        if not scan1: print(f"Aucun scan trouvé pour la date {d1}")
        if not scan2: print(f"Aucun scan trouvé pour la date {d2}")
        # Proposer les dates disponibles
        display_scans_for_domain(all_scans, domain)
        return

    print(f"🔄 Comparaison des scans pour '{domain}' entre {d1} et {d2}\n")

    # Comparaison des scores
    score1 = scan1['data'].get('score_final', 0)
    score2 = scan2['data'].get('score_final', 0)
    print(f"Score: {score1} (à {d1}) -> {score2} (à {d2})")
    if score2 < score1:
        print(f"  -> ✅ Amélioration du score de {score1 - score2} points.")
    elif score2 > score1:
        print(f"  -> ⚠️ Dégradation du score de {score2 - score1} points.")
    else:
        print("  -> 😐 Score inchangé.")

    # Comparaison des vulnérabilités
    vulns1 = _extract_vulnerabilities(scan1['data'])
    vulns2 = _extract_vulnerabilities(scan2['data'])

    fixed_vulns = vulns1 - vulns2
    new_vulns = vulns2 - vulns1
    persistent_vulns = vulns1 & vulns2

    print("\n--- Changements des vulnérabilités ---")
    if fixed_vulns:
        print("\n[✅ VULNÉRABILITÉS CORRIGÉES]")
        for v in sorted(list(fixed_vulns)):
            print(f"  - {v}")

    if new_vulns:
        print("\n[❌ NOUVELLES VULNÉRABILITÉS]")
        for v in sorted(list(new_vulns)):
            print(f"  - {v}")

    if not fixed_vulns and not new_vulns:
        print("\n[😐] Aucune nouvelle vulnérabilité détectée et aucune n'a été corrigée.")

    if persistent_vulns:
        print(f"\n[⚠️ {len(persistent_vulns)} VULNÉRABILITÉS PERSISTANTES]")


def display_oldest_scans(all_scans):
    """Affiche les cibles dont les scans sont les plus anciens."""
    try:
        with open('targets.txt', 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Le fichier 'targets.txt' est introuvable. Veuillez le créer.")
        return

    last_scan_dates = {}
    for target in targets:
        most_recent_scan = next((s for s in sorted(all_scans, key=lambda x: x['date'], reverse=True) if s['domain'] == target), None)
        last_scan_dates[target] = most_recent_scan['date'] if most_recent_scan else None

    # Trie les cibles par date de dernier scan, les non-scannées en premier
    sorted_targets = sorted(last_scan_dates.items(), key=lambda item: item[1] if item[1] is not None else datetime.min)

    print("🕒 Scans les plus anciens (par cible) :")
    for target, date in sorted_targets:
        if date:
            print(f"  - {target.ljust(25)} Dernier scan: {date.strftime('%Y-%m-%d')}")
        else:
            print(f"  - {target.ljust(25)} Dernier scan: JAMAIS (Priorité haute)")

QUICK_WIN_REMEDIATION_IDS = {
    "HSTS_MISSING", "XFO_MISSING", "XCTO_MISSING", "CSP_MISSING",
    "COOKIE_NO_SECURE", "COOKIE_NO_HTTPONLY", "COOKIE_NO_SAMESITE",
    "SERVER_HEADER_VISIBLE"
}

def _get_quick_wins(scan_data):
    """Retourne un set de vulnérabilités 'quick win' à partir des données d'un scan."""
    if not scan_data:
        return set()
    vulns = _extract_vulnerabilities(scan_data)
    return {v for v in vulns if any(rem_id in v for rem_id in QUICK_WIN_REMEDIATION_IDS)}

def _count_critical_vulnerabilities(scan_data):
    """Compte le nombre de vulnérabilités critiques ou élevées dans les données d'un scan."""
    if not scan_data:
        return 0
    count = 0

    def find_critical_issues(data):
        nonlocal count
        if isinstance(data, dict):
            # Une vulnérabilité critique est un dictionnaire qui a une criticité haute/critique
            # et qui n'est pas un cas de succès.
            if data.get('criticite') in ['CRITICAL', 'HIGH']:
                is_successful_case = data.get('present') is True or data.get('statut') == 'SUCCESS'
                if not is_successful_case:
                    count += 1

            for value in data.values():
                find_critical_issues(value)
        elif isinstance(data, list):
            for item in data:
                find_critical_issues(item)

    find_critical_issues(scan_data)
    return count

def display_quick_wins(all_scans, domain_filter):
    """Identifie et affiche les vulnérabilités 'quick win'."""

    target_domains = []
    if domain_filter == 'all':
        target_domains = sorted(list({s['domain'] for s in all_scans}))
    else:
        target_domains = [domain_filter]

    print("🚀 Quick Wins (vulnérabilités faciles à corriger) :\n")

    found_any = False
    for domain in target_domains:
        most_recent_scan = next((s for s in sorted(all_scans, key=lambda x: x['date'], reverse=True) if s['domain'] == domain), None)

        if not most_recent_scan:
            if domain_filter != 'all':
                print(f"Aucun scan trouvé pour '{domain}'.")
            continue

        quick_wins = _get_quick_wins(most_recent_scan['data'])

        if quick_wins:
            found_any = True
            print(f"--- {domain} (Scan du {most_recent_scan['date'].strftime('%Y-%m-%d')}) ---")
            for v in sorted(list(quick_wins)):
                print(f"  - {v}")
            print()

    if not found_any:
        print("Aucun 'quick win' identifié dans les derniers scans.")


def display_expiring_certificates(all_scans, days_threshold):
    """Affiche les certificats SSL/TLS qui expirent bientôt."""
    today = datetime.now()
    expiring_certs = []

    # Obtenir la liste des domaines uniques à partir des scans
    unique_domains = sorted(list({s['domain'] for s in all_scans}))

    for domain in unique_domains:
        # Trouver le scan le plus récent pour ce domaine
        most_recent_scan = next((s for s in sorted(all_scans, key=lambda x: x['date'], reverse=True) if s['domain'] == domain), None)
        if not most_recent_scan:
            continue

        cert_info = most_recent_scan['data'].get('ssl_certificate', {})
        exp_date_str = cert_info.get('date_expiration')

        if not exp_date_str:
            continue

        try:
            exp_date = datetime.strptime(exp_date_str, '%Y-%m-%d')
            days_left = (exp_date - today).days

            if 0 <= days_left <= days_threshold:
                expiring_certs.append({
                    "domain": domain,
                    "exp_date": exp_date,
                    "days_left": days_left
                })
        except ValueError:
            print(f"Avertissement : Format de date invalide pour le certificat de '{domain}': '{exp_date_str}'")
            continue

    print(f"📜 Certificats expirant dans les {days_threshold} prochains jours :\n")

    if not expiring_certs:
        print("Aucun certificat n'expire dans la période spécifiée. ✅")
        return

    # Trie les certificats par date d'expiration (le plus proche en premier)
    expiring_certs.sort(key=lambda x: x['days_left'])

    for cert in expiring_certs:
        date_str = cert['exp_date'].strftime('%d %B %Y')
        days = cert['days_left']
        plural_s = 's' if days > 1 else ''
        print(f"  - {cert['domain'].ljust(30)} Expire le: {date_str} (dans {days} jour{plural_s})")


def generate_vulnerability_report(all_scans, report_types):
    """Génère un rapport listant les sites affectés par des vulnérabilités spécifiques."""

    # Gérer le mot-clé 'all'
    if 'all' in [rt.lower() for rt in report_types]:
        reports_to_run = list(SUPPORTED_REPORTS.keys())
    else:
        # Valider les types de rapports demandés
        reports_to_run = []
        for rt in report_types:
            if rt.lower() in SUPPORTED_REPORTS:
                reports_to_run.append(rt.lower())
            else:
                print(f"Avertissement : Le type de rapport '{rt}' n'est pas supporté. Les types supportés sont : {', '.join(SUPPORTED_REPORTS.keys())}")
        if not reports_to_run:
            print("Aucun rapport valide à générer.")
            return

    print(f"🔎 Génération du rapport d'actions pour : {', '.join(reports_to_run)}\n")

    # Obtenir la liste des domaines uniques à partir des scans
    unique_domains = sorted(list({s['domain'] for s in all_scans}))

    # Structurer les résultats par type de vulnérabilité
    results = {report_type: [] for report_type in reports_to_run}

    for domain in unique_domains:
        # Trouver le scan le plus récent pour ce domaine
        most_recent_scan = next((s for s in sorted(all_scans, key=lambda x: x['date'], reverse=True) if s['domain'] == domain), None)
        if not most_recent_scan:
            continue

        # Extraire les vulnérabilités de ce scan
        vulnerabilities = _extract_vulnerabilities(most_recent_scan['data'])

        # Vérifier si le domaine est affecté par les vulnérabilités demandées
        for report_type in reports_to_run:
            remediation_id = SUPPORTED_REPORTS[report_type]
            # Nous vérifions si un identifiant de vulnérabilité contient le remediation_id
            # C'est plus flexible que une égalité stricte
            if any(remediation_id in v_id for v_id in vulnerabilities):
                results[report_type].append(domain)

    # Afficher le rapport
    found_any_issue = False
    for report_type, affected_domains in results.items():
        remediation_id = SUPPORTED_REPORTS[report_type]
        advice = REMEDIATION_ADVICE.get(remediation_id, {}).get('default', 'Aucun conseil de remédiation disponible.')

        print(f"--- Rapport pour : {report_type.upper()} ---")
        print(f"    Action recommandée : {advice}\n")

        if affected_domains:
            found_any_issue = True
            print("    Sites affectés :")
            for domain in sorted(affected_domains):
                print(f"      - {domain}")
        else:
            print("    ✅ Aucun site affecté pour ce type de vulnérabilité.")
        print("-" * (20 + len(report_type)))
        print()

    if not found_any_issue:
        print("🎉 Félicitations ! Aucun des problèmes recherchés n'a été trouvé sur les derniers scans de vos domaines.")


def generate_html_summary(all_scans):
    """Génère un rapport de synthèse HTML pour tous les sites cibles."""

    try:
        with open('targets.txt', 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Le fichier 'targets.txt' est introuvable. Veuillez le créer pour générer le rapport de synthèse.")
        return

    summary_data = []
    today = datetime.now()

    for target in targets:
        scans_for_domain = sorted([s for s in all_scans if s['domain'] == target], key=lambda x: x['date'], reverse=True)

        if scans_for_domain:
            most_recent_scan = scans_for_domain[0]
            cert_info = most_recent_scan['data'].get('ssl_certificate', {})
            exp_date_str = cert_info.get('date_expiration')
            exp_date_obj = None
            days_left = None
            if exp_date_str:
                try:
                    exp_date_obj = datetime.strptime(exp_date_str, '%Y-%m-%d')
                    days_left = (exp_date_obj - today).days
                except ValueError:
                    pass # La date est invalide, on la laisse à None

            # Calcul de la tendance
            trend = "➡️"
            if len(scans_for_domain) > 1:
                score_new = most_recent_scan['data'].get('score_final', 0)
                score_old = scans_for_domain[1]['data'].get('score_final', 0)
                if score_new < score_old:
                    trend = "⬇️" # Amélioration
                elif score_new > score_old:
                    trend = "⬆️" # Régression

            # Calculer les nouvelles métriques
            critical_vulns_count = _count_critical_vulnerabilities(most_recent_scan['data'])
            quick_wins_count = len(_get_quick_wins(most_recent_scan['data']))

            # Vérifier l'existence du rapport HTML détaillé
            detailed_report_name = f"{target}_{most_recent_scan['date'].strftime('%d%m%y')}.html"
            detailed_report_path = os.path.join(SCAN_REPORTS_DIR, detailed_report_name)
            if not os.path.exists(detailed_report_path):
                detailed_report_path = None


            summary_data.append({
                "domain": target,
                "last_scan": most_recent_scan['date'].strftime('%Y-%m-%d'),
                "score": most_recent_scan['data'].get('score_final', 'N/A'),
                "grade": most_recent_scan['data'].get('note', 'N/A'),
                "trend": trend,
                "critical_vulns": critical_vulns_count,
                "quick_wins": quick_wins_count,
                "cert_exp": exp_date_obj,
                "cert_days_left": days_left,
                "detailed_report_path": detailed_report_path
            })
        else:
            summary_data.append({
                "domain": target,
                "last_scan": "Jamais",
                "score": "N/A",
                "grade": "N/A",
                "trend": "N/A",
                "critical_vulns": "N/A",
                "quick_wins": "N/A",
                "cert_exp": None,
                "cert_days_left": None,
                "detailed_report_path": None
            })

    # Générer le HTML
    html = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="utf-8">
        <title>Rapport de Synthèse de Sécurité</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f9; margin: 0; padding: 20px; }
            h1 { color: #2c3e50; text-align: center; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 15px rgba(0,0,0,0.1); background-color: #fff; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #4a69bd; color: white; cursor: pointer; user-select: none; }
            th:hover { background-color: #3b5998; }
            th .sort-indicator { float: right; color: #a9bce8; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            tr:hover { background-color: #e2e8f0; }
            .grade { font-weight: bold; padding: 5px 10px; border-radius: 15px; color: white; text-align: center; display: inline-block; min-width: 30px; }
            .grade-A-plus { background-color: #27ae60; }
            .grade-A { background-color: #2ecc71; }
            .grade-B { background-color: #f1c40f; }
            .grade-C { background-color: #e67e22; }
            .grade-D { background-color: #d35400; }
            .grade-F { background-color: #c0392b; }
            .trend { font-size: 1.2em; text-align: center; }
            .trend-up { color: #c0392b; }
            .trend-down { color: #27ae60; }
            .trend-stable { color: #7f8c8d; }
            .report-btn { display: inline-block; padding: 4px 10px; border-radius: 5px; color: white; text-decoration: none; font-size: 0.9em; }
            .report-btn-active { background-color: #5d6d7e; }
            .report-btn-active:hover { background-color: #34495e; }
            .report-btn-disabled { background-color: #bdc3c7; cursor: not-allowed; }
            .count-badge { display: inline-block; padding: 4px 10px; border-radius: 15px; color: white; font-size: 0.9em; font-weight: bold; }
            .count-critical { background-color: #c0392b; }
            .count-quickwin { background-color: #3498db; }
            .cert-badge { display: inline-block; padding: 4px 12px; border-radius: 15px; color: white; font-size: 0.9em; }
            .cert-status-ok { background-color: #27ae60; }
            .cert-status-warn { background-color: #f39c12; }
            .cert-status-danger { background-color: #c0392b; }
            .cert-status-na { background-color: #bdc3c7; }
            .footer { text-align: center; margin-top: 20px; font-size: 0.9em; color: #7f8c8d; }
        </style>
    </head>
    <body>
        <h1>Rapport de Synthèse de Sécurité</h1>
        <p class="footer">Généré le """ + today.strftime('%d %B %Y à %H:%M:%S') + """</p>
        <table>
            <thead>
                <tr>
                    <th style="cursor: default;">Rapport</th>
                    <th>Domaine<span class="sort-indicator"></span></th>
                    <th>Dernier Scan<span class="sort-indicator"></span></th>
                    <th>Score<span class="sort-indicator"></span></th>
                    <th>Note<span class="sort-indicator"></span></th>
                    <th>Tendance<span class="sort-indicator"></span></th>
                    <th>Vulns Crit/High<span class="sort-indicator"></span></th>
                    <th>Quick Wins<span class="sort-indicator"></span></th>
                    <th>Expiration du Certificat<span class="sort-indicator"></span></th>
                </tr>
            </thead>
            <tbody>
    """

    for item in summary_data:
        grade_class = "grade-" + item['grade'].replace('+', '-plus') if item['grade'] != 'N/A' else ""

        trend_class = "trend-stable"
        if item['trend'] == '⬆️':
            trend_class = "trend-up"
        elif item['trend'] == '⬇️':
            trend_class = "trend-down"

        cert_status_class = 'cert-status-na'
        cert_text = "N/A"
        if item['cert_days_left'] is not None:
            date_str = item['cert_exp'].strftime('%Y-%m-%d')
            days_left = item['cert_days_left']

            if days_left < 0:
                cert_status_class = 'cert-status-danger'
                cert_text = f"Expiré depuis {-days_left} jours"
            else:
                plural_s = 's' if days_left > 1 else ''
                cert_text = f"{date_str} ({days_left} jour{plural_s})"
                if days_left <= 15:
                    cert_status_class = 'cert-status-danger'
                elif days_left <= 60:
                    cert_status_class = 'cert-status-warn'
                else:
                    cert_status_class = 'cert-status-ok'

        report_button = ""
        if item['detailed_report_path']:
            report_button = f'<a href="{item["detailed_report_path"]}" class="report-btn report-btn-active" target="_blank">Voir</a>'
        else:
            report_button = f'<span class="report-btn report-btn-disabled">N/A</span>'

        html += f"""
                <tr>
                    <td style="text-align: center;">{report_button}</td>
                    <td><a href="https://{item['domain']}" target="_blank"><strong>{item['domain']}</strong></a></td>
                    <td>{item['last_scan']}</td>
                    <td>{item['score']}</td>
                    <td><span class="grade {grade_class}">{item['grade']}</span></td>
                    <td class="trend {trend_class}">{item['trend']}</td>
                    <td style="text-align: center;"><span class="count-badge count-critical">{item['critical_vulns']}</span></td>
                    <td style="text-align: center;"><span class="count-badge count-quickwin">{item['quick_wins']}</span></td>
                    <td><span class="cert-badge {cert_status_class}">{cert_text}</span></td>
                </tr>
        """

    html += """
            </tbody>
        </table>
    </body>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        const getCellValue = (tr, idx) => {
            const cell = tr.children[idx];
            if (!cell) return '';
            const sortValue = cell.dataset.sortValue;
            if (sortValue) return sortValue;
            return cell.innerText || cell.textContent;
        };

        const gradeOrder = { 'A+': 0, 'A': 1, 'B': 2, 'C': 3, 'D': 4, 'F': 5, 'N/A': 99 };

        const comparer = (idx, asc) => (a, b) => {
            const v1 = getCellValue(a, idx);
            const v2 = getCellValue(b, idx);
            const direction = asc ? 1 : -1;

            if (idx === 4) { // Grade column
                return (gradeOrder[v1] - gradeOrder[v2]) * direction;
            }

            if ([3, 6, 7].includes(idx)) { // Numeric columns
                const num1 = parseFloat(v1);
                const num2 = parseFloat(v2);
                const isNum1NaN = isNaN(num1);
                const isNum2NaN = isNaN(num2);

                if (isNum1NaN && isNum2NaN) return 0;
                if (isNum1NaN) return 1;
                if (isNum2NaN) return -1;
                return (num1 - num2) * direction;
            }

            return v1.localeCompare(v2) * direction;
        };

        document.querySelectorAll('th').forEach(th => {
            if (th.style.cursor === 'default') return;

            th.addEventListener('click', () => {
                const table = th.closest('table');
                const tbody = table.querySelector('tbody');
                const thIndex = Array.from(th.parentNode.children).indexOf(th);

                // Determine the new sort direction
                const newDirectionIsAsc = th.dataset.sortDir !== 'asc';

                // Sort the rows
                Array.from(tbody.querySelectorAll('tr'))
                    .sort(comparer(thIndex, newDirectionIsAsc))
                    .forEach(tr => tbody.appendChild(tr));

                // Update headers state and indicators
                table.querySelectorAll('th').forEach(otherTh => {
                    const indicator = otherTh.querySelector('.sort-indicator');
                    if (indicator) {
                        indicator.textContent = '';
                    }
                    delete otherTh.dataset.sortDir;
                });
                th.querySelector('.sort-indicator').textContent = newDirectionIsAsc ? ' ▲' : ' ▼';
                th.dataset.sortDir = newDirectionIsAsc ? 'asc' : 'desc';
            });
        });
    });
    </script>
    </html>
    """

    try:
        with open('summary_report.html', 'w', encoding='utf-8') as f:
            f.write(html)
        print("✅ Rapport de synthèse HTML 'summary_report.html' généré avec succès.")
    except IOError as e:
        print(f"❌ Erreur lors de l'écriture du rapport HTML : {e}")


def generate_evolution_graph(all_scans, domain):
    """Génère un graphique d'évolution du score pour un domaine spécifique."""
    scans_for_domain = sorted(
        [s for s in all_scans if s['domain'] == domain],
        key=lambda x: x['date']
    )

    if len(scans_for_domain) < 2:
        print(f"Moins de deux scans trouvés pour '{domain}'. Impossible de générer un graphique d'évolution.")
        return

    dates = [s['date'] for s in scans_for_domain]
    scores = [s['data'].get('score_final', 0) for s in scans_for_domain]

    plt.figure(figsize=(10, 6))
    plt.plot(dates, scores, marker='o', linestyle='-', color='b')

    plt.title(f"Évolution du Score de Sécurité pour {domain}")
    plt.xlabel("Date du Scan")
    plt.ylabel("Score de Dangerosité (plus bas = mieux)")
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.ylim(bottom=0, top=max(scores) + 10) # Y-axis starts at 0
    plt.gcf().autofmt_xdate() # Format dates nicely

    filename = f"{domain}_evolution.png"
    try:
        plt.savefig(filename, bbox_inches='tight')
        print(f"✅ Graphique d'évolution '{filename}' généré avec succès.")
    except IOError as e:
        print(f"❌ Erreur lors de la sauvegarde du graphique : {e}")
    plt.close()


if __name__ == "__main__":
    main()

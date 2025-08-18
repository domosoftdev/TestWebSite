#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Outil de consolidation et d'analyse pour les rapports de sécurité JSON.
"""

import argparse
import json
import os
from datetime import datetime

SCAN_REPORTS_DIR = "scans/"

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
            # Si un item a un 'statut' et un 'remediation_id', on le considère comme une vulnérabilité potentielle
            if 'statut' in data and data['statut'] in ['ERROR', 'WARNING'] and 'remediation_id' in data:
                # Créer un identifiant unique pour la vulnérabilité
                vuln_id = f"{path}.{data['remediation_id']}"
                vulnerabilities.add(vuln_id)

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

def display_quick_wins(all_scans, domain_filter):
    """Identifie et affiche les vulnérabilités 'quick win'."""

    target_domains = []
    if domain_filter == 'all':
        # Obtenir la liste unique de domaines depuis les scans
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

        vulns = _extract_vulnerabilities(most_recent_scan['data'])
        quick_wins = {v for v in vulns if any(rem_id in v for rem_id in QUICK_WIN_REMEDIATION_IDS)}

        if quick_wins:
            found_any = True
            print(f"--- {domain} (Scan du {most_recent_scan['date'].strftime('%Y-%m-%d')}) ---")
            for v in sorted(list(quick_wins)):
                print(f"  - {v}")
            print()

    if not found_any:
        print("Aucun 'quick win' identifié dans les derniers scans.")


if __name__ == "__main__":
    main()

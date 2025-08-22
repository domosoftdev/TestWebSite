#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Algorithme de Calcul de Score de Parking de Domaine.
Ce script peut être exécuté de manière autonome pour obtenir le score de parking d'un domaine.
"""

import argparse
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import dns.resolver
import uuid
import whois
from datetime import datetime, timedelta

# --- CONSTANTES ---

KEYWORDS_FOR_SALE = [
    "domain for sale", "domaine à vendre", "buy this domain", "acheter ce domaine",
    "make an offer", "faire une offre", "this domain is available",
    "premium domain", "inquire about this domain"
]
KEYWORDS_PARKING_GENERIC = [
    "domain parking", "parked domain", "sedo", "bodis", "dan.com", "afternic",
    "domain name", "related searches", "sponsored listings", "ads by",
    "coming soon", "en construction"
]
KNOWN_PARKING_HOSTNAMES = [
    "sedo.com", "bodis.com", "dan.com", "afternic.com", "hugedomains.com",
    "uniregistry.com", "above.com", "parkingcrew.net", "domainsponsor.com"
]
KNOWN_PARKING_NAMESERVERS = [
    "sedoparking.com", "bodis.com", "parkingcrew.net", "above.com", "abovedomains.com",
    "uniregistrymarket.link", "huge-domains.com", "afternic.com", "dan.com"
]
KNOWN_PARKING_IP_RANGES = []

# --- FONCTIONS D'ANALYSE ---

def analyserContenu(domaine: str, verbose: bool = False) -> int:
    """Analyse le contenu HTTP d'un domaine. Score: 0-40."""
    if verbose: print("\n--- Analyse du Contenu (max 40 pts) ---")
    score = 0
    urls_a_tester = [f"https://www.{domaine}", f"https://{domaine}", f"http://{domaine}"]
    page_html, url_finale = "", ""
    session = requests.Session()
    session.max_redirects = 5
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    for url in urls_a_tester:
        try:
            if verbose: print(f"  [i] Test de l'URL : {url}")
            reponse = session.get(url, timeout=10, headers=headers)
            if reponse.status_code == 200:
                page_html, url_finale = reponse.text, reponse.url
                if verbose: print(f"  [+] Connexion réussie à : {url_finale}")
                break
        except requests.exceptions.RequestException as e:
            if verbose: print(f"  [!] Échec de la connexion : {e}")
            continue

    if not page_html:
        if verbose: print("  [!] Impossible de récupérer le contenu de la page.")
        return 0

    hostname_final = urlparse(url_finale).hostname
    if hostname_final:
        for parking_host in KNOWN_PARKING_HOSTNAMES:
            if (hostname_final and hostname_final.endswith(parking_host)) or (parking_host in page_html):
                if verbose: print(f"  [+] Le contenu ou l'URL finale correspond à un service de parking connu ({parking_host}) : +20 pts")
                score += 20
                break # On donne les points une seule fois

    soup = BeautifulSoup(page_html, 'html.parser')
    lines = (line.strip() for line in soup.stripped_strings)
    all_text = " ".join(line.lower() for line in lines if line)
    for meta in soup.find_all('meta', attrs={'name': ['description', 'keywords']}):
        if meta.get('content'): all_text += " " + meta.get('content').lower()

    found_sale_keyword = False
    for keyword in KEYWORDS_FOR_SALE:
        if keyword in all_text:
            if verbose: print(f"  [+] Mot-clé de vente trouvé ('{keyword}') : +10 pts")
            score += 10
            found_sale_keyword = True
            break
    if not found_sale_keyword and verbose: print("  [-] Aucun mot-clé de vente explicite trouvé.")

    found_generic_keyword = False
    for keyword in KEYWORDS_PARKING_GENERIC:
        if keyword in all_text:
            if verbose: print(f"  [+] Mot-clé de parking générique trouvé ('{keyword}') : +10 pts")
            score += 10
            found_generic_keyword = True
            break
    if not found_generic_keyword and verbose: print("  [-] Aucun mot-clé de parking générique trouvé.")

    return score

def analyserTechnique(domaine: str, verbose: bool = False) -> int:
    """Analyse les enregistrements DNS. Score: 0-30."""
    if verbose: print("\n--- Analyse Technique (max 30 pts) ---")
    score = 0
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout, resolver.lifetime = 5, 5

    try:
        ns_records = resolver.resolve(domaine, 'NS')
        ns_match_found = False
        for record in ns_records:
            ns_str = str(record.target).lower()
            if verbose: print(f"  [i] Serveur de noms trouvé : {ns_str.rstrip('.')}")
            for known_ns in KNOWN_PARKING_NAMESERVERS:
                if ns_str.startswith(known_ns.rstrip('.')) or ns_str.endswith(known_ns + '.'):
                    if verbose: print(f"  [+] Le serveur de noms correspond à un service de parking connu ({known_ns}) : +15 pts")
                    score += 15
                    ns_match_found = True
                    break
            if ns_match_found: break
        if not ns_match_found and verbose: print("  [-] Aucun serveur de noms de parking connu trouvé.")
    except Exception as e:
        if verbose: print(f"  [!] Erreur lors de la résolution NS : {e}")

    try:
        ip_racine_answers = resolver.resolve(domaine, 'A')
        ip_racine = {str(r) for r in ip_racine_answers}
        if verbose: print(f"  [i] Adresses IP trouvées pour {domaine} : {ip_racine}")
        sous_domaine_aleatoire = f"test-wildcard-{uuid.uuid4().hex[:8]}.{domaine}"
        ip_aleatoire_answers = resolver.resolve(sous_domaine_aleatoire, 'A')
        ip_aleatoire = {str(r) for r in ip_aleatoire_answers}
        if verbose: print(f"  [i] Adresses IP trouvées pour {sous_domaine_aleatoire} : {ip_aleatoire}")
        if ip_racine and ip_aleatoire == ip_racine:
            if verbose: print("  [+] Un enregistrement DNS Wildcard a été détecté : +5 pts")
            score += 5
        elif verbose: print("  [-] Pas de DNS Wildcard détecté.")
    except Exception as e:
        if verbose: print(f"  [!] Pas de DNS Wildcard détecté ou erreur : {e}")

    return score

def analyserContextuel(domaine: str, verbose: bool = False) -> int:
    """Analyse les données WHOIS. Score: 0-30."""
    if verbose: print("\n--- Analyse Contextuelle (max 30 pts) ---")
    score = 0
    try:
        data = whois.whois(domaine)
    except Exception as e:
        if verbose: print(f"  [!] Échec de la requête WHOIS : {e}")
        return 0

    if not data or not data.get('creation_date'):
        if verbose: print("  [!] Données WHOIS invalides ou incomplètes.")
        return 0

    privacy_keywords = ["privacy", "whoisguard", "redacted", "protection", "proxy"]
    registrant_info = str(data.get('registrant_name', '')) + str(data.get('org', ''))
    if any(keyword in registrant_info.lower() for keyword in privacy_keywords):
        if verbose: print("  [+] Protection de la confidentialité WHOIS détectée : +5 pts")
        score += 5
    elif verbose: print("  [-] Pas de protection de confidentialité détectée.")

    now = datetime.now()
    updated_date = data.get('updated_date')
    if isinstance(updated_date, list): updated_date = updated_date[0]
    creation_date = data.get('creation_date')
    if isinstance(creation_date, list): creation_date = creation_date[0]

    if updated_date and (now - updated_date) < timedelta(days=30):
        if verbose: print(f"  [+] Domaine mis à jour récemment ({updated_date.date()}) : +10 pts")
        score += 10
    elif creation_date and (now - creation_date) < timedelta(days=90):
        if verbose: print(f"  [+] Domaine créé récemment ({creation_date.date()}) : +5 pts")
        score += 5
    elif verbose: print("  [-] Pas de mise à jour ou création récente.")

    domain_status = data.get('status', [])
    if isinstance(domain_status, str): domain_status = [domain_status]
    found_hold = False
    for s in domain_status:
        if "clienthold" in s.lower():
            if verbose: print(f"  [+] Statut 'clientHold' trouvé : +10 pts")
            score += 10
            found_hold = True
            break
    if not found_hold and verbose: print("  [-] Aucun statut 'clientHold' trouvé.")

    return score

def calculerScoreParking(domaine: str, verbose: bool = False) -> int:
    """Orchestre les analyses et calcule le score final."""
    score_contenu = analyserContenu(domaine, verbose=verbose)
    score_technique = analyserTechnique(domaine, verbose=verbose)
    score_contextuel = analyserContextuel(domaine, verbose=verbose)
    score_total = score_contenu + score_technique + score_contextuel
    return min(score_total, 100)

# --- BLOC D'EXÉCUTION AUTONOME ---

def main():
    """Point d'entrée pour l'exécution en ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Calcule le score de parking d'un nom de domaine.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("domaine", help="Le nom de domaine à analyser (ex: exemple.com).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Affiche le détail des tests et des points attribués.")
    args = parser.parse_args()

    if '.' not in args.domaine:
        print(f"Erreur : '{args.domaine}' ne semble pas être un nom de domaine valide.", file=sys.stderr)
        sys.exit(1)

    print(f"Calcul du score de parking pour {args.domaine}...")
    score = calculerScoreParking(args.domaine, verbose=args.verbose)
    print(f"\nScore de parking final pour {args.domaine}: {score}/100")

if __name__ == "__main__":
    main()

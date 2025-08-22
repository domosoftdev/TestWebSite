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

def analyserContenu(domaine: str) -> int:
    """Analyse le contenu HTTP d'un domaine. Score: 0-40."""
    urls_a_tester = [f"https://www.{domaine}", f"https://{domaine}", f"http://{domaine}"]
    page_html, url_finale = "", ""
    session = requests.Session()
    session.max_redirects = 5
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    for url in urls_a_tester:
        try:
            reponse = session.get(url, timeout=10, headers=headers)
            if reponse.status_code == 200:
                page_html, url_finale = reponse.text, reponse.url
                break
        except requests.exceptions.RequestException:
            continue

    if not page_html:
        return 0

    hostname_final = urlparse(url_finale).hostname
    if hostname_final:
        for parking_host in KNOWN_PARKING_HOSTNAMES:
            if (hostname_final and hostname_final.endswith(parking_host)) or (parking_host in page_html):
                return 20 # This is a strong signal, so we can still exit early here.

    score_keywords = 0
    soup = BeautifulSoup(page_html, 'html.parser')
    lines = (line.strip() for line in soup.stripped_strings)
    all_text = " ".join(line.lower() for line in lines if line)
    for meta in soup.find_all('meta', attrs={'name': ['description', 'keywords']}):
        if meta.get('content'): all_text += " " + meta.get('content').lower()

    for keyword in KEYWORDS_FOR_SALE:
        if keyword in all_text:
            score_keywords += 10
            break

    for keyword in KEYWORDS_PARKING_GENERIC:
        if keyword in all_text:
            score_keywords += 10
            break

    return score_keywords

def analyserTechnique(domaine: str) -> int:
    """Analyse les enregistrements DNS. Score: 0-30."""
    score = 0
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout, resolver.lifetime = 5, 5

    try:
        ns_records = resolver.resolve(domaine, 'NS')
        ns_match_found = False
        for record in ns_records:
            ns_str = str(record.target).lower()
            for known_ns in KNOWN_PARKING_NAMESERVERS:
                if ns_str.startswith(known_ns.rstrip('.')) or ns_str.endswith(known_ns + '.'):
                    score += 15
                    ns_match_found = True
                    break
            if ns_match_found: break
    except Exception:
        pass

    try:
        ip_racine_answers = resolver.resolve(domaine, 'A')
        ip_racine = {str(r) for r in ip_racine_answers}
        sous_domaine_aleatoire = f"test-wildcard-{uuid.uuid4().hex[:8]}.{domaine}"
        ip_aleatoire_answers = resolver.resolve(sous_domaine_aleatoire, 'A')
        ip_aleatoire = {str(r) for r in ip_aleatoire_answers}
        if ip_racine and ip_aleatoire == ip_racine:
            score += 5
    except Exception:
        pass

    return score

def analyserContextuel(domaine: str) -> int:
    """Analyse les données WHOIS. Score: 0-30."""
    score = 0
    try:
        data = whois.whois(domaine)
    except Exception:
        return 0

    if not data or not data.get('creation_date'):
        return 0

    privacy_keywords = ["privacy", "whoisguard", "redacted", "protection", "proxy"]
    registrant_info = str(data.get('registrant_name', '')) + str(data.get('org', ''))
    if any(keyword in registrant_info.lower() for keyword in privacy_keywords):
        score += 5

    now = datetime.now()
    updated_date = data.get('updated_date')
    if isinstance(updated_date, list): updated_date = updated_date[0]
    creation_date = data.get('creation_date')
    if isinstance(creation_date, list): creation_date = creation_date[0]

    if updated_date and (now - updated_date) < timedelta(days=30):
        score += 10
    elif creation_date and (now - creation_date) < timedelta(days=90):
        score += 5

    domain_status = data.get('status', [])
    if isinstance(domain_status, str): domain_status = [domain_status]
    for s in domain_status:
        if "clienthold" in s.lower():
            score += 10
            break

    return score

def calculerScoreParking(domaine: str) -> int:
    """Orchestre les analyses et calcule le score final."""
    score_contenu = analyserContenu(domaine)
    score_technique = analyserTechnique(domaine)
    score_contextuel = analyserContextuel(domaine)
    score_total = score_contenu + score_technique + score_contextuel
    return min(score_total, 100)

# --- BLOC D'EXÉCUTION AUTONOME ---

def main():
    """Point d'entrée pour l'exécution en ligne de commande."""
    parser = argparse.ArgumentParser(description="Calcule le score de parking d'un nom de domaine.")
    parser.add_argument("domaine", help="Le nom de domaine à analyser (ex: exemple.com).")
    args = parser.parse_args()

    if '.' not in args.domaine:
        print(f"Erreur : '{args.domaine}' ne semble pas être un nom de domaine valide.", file=sys.stderr)
        sys.exit(1)

    print(f"Calcul du score de parking pour {args.domaine}...")
    score = calculerScoreParking(args.domaine)
    print(f"Score de parking final pour {args.domaine}: {score}/100")

if __name__ == "__main__":
    main()

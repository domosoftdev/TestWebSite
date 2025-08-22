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

# Listes de mots-clés (en minuscules pour faciliter la comparaison)
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

# Listes de services de parking connus
KNOWN_PARKING_HOSTNAMES = [
    "sedo.com", "bodis.com", "dan.com", "afternic.com", "hugedomains.com",
    "uniregistry.com", "above.com", "parkingcrew.net", "domainsponsor.com"
]

KNOWN_PARKING_NAMESERVERS = [
    "sedoparking.com", "bodis.com", "parkingcrew.net", "above.com",
    "uniregistrymarket.link", "huge-domains.com", "afternic.com", "dan.com"
]

# (Optionnel, plus difficile à maintenir) Plages d'IP de parking connues
KNOWN_PARKING_IP_RANGES = []

# --- FONCTIONS D'ANALYSE ---

def analyserContenu(domaine: str) -> int:
    """
    Analyse le contenu HTTP d'un domaine pour détecter des signes de parking.
    Score: 0 à 40 points.
    """
    urls_a_tester = [f"https://www.{domaine}", f"https://{domaine}", f"http://{domaine}"]
    page_html = ""
    url_finale = ""

    session = requests.Session()
    session.max_redirects = 5
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    for url in urls_a_tester:
        try:
            reponse = session.get(url, timeout=10, headers=headers)
            if reponse.status_code == 200:
                page_html = reponse.text
                url_finale = reponse.url
                break
        except requests.exceptions.RequestException:
            continue

    if not page_html:
        return 0

    hostname_final = urlparse(url_finale).hostname
    if hostname_final:
        for parking_host in KNOWN_PARKING_HOSTNAMES:
            if hostname_final.endswith(parking_host):
                return 20

    score_keywords = 0
    soup = BeautifulSoup(page_html, 'html.parser')

    # Utiliser stripped_strings pour une extraction de texte plus propre et fiable
    lines = (line.strip() for line in soup.stripped_strings)
    all_text = " ".join(line.lower() for line in lines if line)

    # Ajouter également le contenu des balises meta, qui n'est pas inclus dans stripped_strings
    for meta in soup.find_all('meta', attrs={'name': ['description', 'keywords']}):
        if meta.get('content'):
            all_text += " " + meta.get('content').lower()

    # Recherche de mots-clés de vente explicites (10 points)
    for keyword in KEYWORDS_FOR_SALE:
        if keyword in all_text:
            score_keywords += 10
            break

    # Recherche de mots-clés de parking génériques (10 points)
    for keyword in KEYWORDS_PARKING_GENERIC:
        if keyword in all_text:
            score_keywords += 10
            break

    return score_keywords

def analyserTechnique(domaine: str) -> int:
    """
    Analyse les enregistrements DNS d'un domaine pour des signes techniques de parking.
    Score: 0 à 30 points.
    """
    score_technique = 0
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        ns_records = resolver.resolve(domaine, 'NS')
        for ns_record in ns_records:
            ns_str = str(ns_record.target).lower()
            for known_ns in KNOWN_PARKING_NAMESERVERS:
                if ns_str.endswith(known_ns + '.'):
                    score_technique += 15
                    return score_technique
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        pass

    if KNOWN_PARKING_IP_RANGES:
        try:
            resolver.resolve(domaine, 'A')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass

    try:
        ip_racine_answers = resolver.resolve(domaine, 'A')
        ip_racine = {str(r) for r in ip_racine_answers}
        sous_domaine_aleatoire = f"test-wildcard-{uuid.uuid4().hex[:8]}.{domaine}"
        ip_aleatoire_answers = resolver.resolve(sous_domaine_aleatoire, 'A')
        ip_aleatoire = {str(r) for r in ip_aleatoire_answers}
        if ip_racine and ip_aleatoire == ip_racine:
            score_technique += 5
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        pass

    return score_technique

def analyserContextuel(domaine: str) -> int:
    """
    Analyse les données WHOIS d'un domaine pour des indices contextuels de parking.
    Score: 0 à 30 points.
    """
    score_contextuel = 0
    try:
        donnees_whois = whois.whois(domaine)
    except Exception:
        return 0

    if not donnees_whois or not donnees_whois.get('creation_date'):
        return 0

    privacy_keywords = ["privacy", "whoisguard", "redacted", "protection"]
    registrant_info_str = str(donnees_whois.get('registrant_name', '')) + str(donnees_whois.get('org', ''))
    if any(keyword in registrant_info_str.lower() for keyword in privacy_keywords):
        score_contextuel += 5

    now = datetime.now()
    updated_date = donnees_whois.get('updated_date')
    if isinstance(updated_date, list): updated_date = updated_date[0]
    if updated_date and (now - updated_date) < timedelta(days=30):
        score_contextuel += 10
    else:
        creation_date = donnees_whois.get('creation_date')
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if creation_date and (now - creation_date) < timedelta(days=90):
            score_contextuel += 5

    domain_status = donnees_whois.get('status', [])
    if isinstance(domain_status, str):
        domain_status = [domain_status]
    for statut in domain_status:
        if "clienthold" in statut.lower():
            score_contextuel += 10
            break

    return score_contextuel

def calculerScoreParking(domaine: str) -> int:
    """
    Orchestre les différentes analyses et calcule le score de parking final.
    """
    score_contenu = analyserContenu(domaine)
    score_technique = analyserTechnique(domaine)
    score_contextuel = analyserContextuel(domaine)
    score_total = score_contenu + score_technique + score_contextuel
    return min(score_total, 100)

# --- BLOC D'EXÉCUTION AUTONOME ---

def main():
    """
    Point d'entrée pour l'exécution en ligne de commande.
    """
    parser = argparse.ArgumentParser(description="Calcule le score de parking d'un nom de domaine.")
    parser.add_argument("domaine", help="Le nom de domaine à analyser (ex: exemple.com).")
    args = parser.parse_args()

    if '.' not in args.domaine:
        print(f"Erreur : '{args.domaine}' ne semble pas être un nom de domaine valide.", file=sys.stderr)
        sys.exit(1)

    print(f"Calcul du score de parking pour {args.domaine}...")
    score = calculerScoreParking(args.domaine)
    print(f"Score de parking pour {args.domaine}: {score}/100")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Outil d'analyse de sécurité de site web.
Vérifie les certificats SSL/TLS et les en-têtes de sécurité HTTP.
"""

import argparse
import socket
import ssl
import sys
import requests
from datetime import datetime

def check_host_exists(hostname):
    """Vérifie si un nom d'hôte existe via une résolution DNS."""
    try:
        socket.gethostbyname_ex(hostname)
        return True
    except socket.gaierror:
        return False

def get_hostname(url):
    """Extrait le nom d'hôte d'une URL."""
    if url.startswith('https://'):
        url = url[8:]
    if url.startswith('http://'):
        url = url[7:]
    if '/' in url:
        url = url.split('/')[0]
    return url

def check_ssl_certificate(hostname):
    """Vérifie le certificat SSL/TLS d'un hôte."""
    print("\n--- Analyse du certificat SSL/TLS ---")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                print(f"  Sujet du certificat : {subject.get('commonName', 'N/A')}")
                print(f"  Émetteur : {issuer.get('commonName', 'N/A')}")
                
                exp_date_str = cert['notAfter']
                exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                print(f"  Date d'expiration : {exp_date.strftime('%Y-%m-%d')}")
                
                if exp_date < datetime.now():
                    print("  ATTENTION : Le certificat a expiré !")
                else:
                    print("  Le certificat est valide.")

    except Exception as e:
        print(f"  Erreur lors de la vérification du certificat : {e}")

def check_security_headers(hostname):
    """Vérifie la présence des en-têtes de sécurité HTTP en utilisant requests."""
    print("\n--- Analyse des en-têtes de sécurité HTTP ---")
    try:
        url = f"https://{hostname}"
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        security_headers_to_check = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "Content-Security-Policy-Report-Only",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        print(f"  Analyse des en-têtes pour l'URL finale : {response.url}")

        print("\n  En-têtes de sécurité trouvés :")
        found_any = False
        for header in security_headers_to_check:
            if header in headers:
                print(f"    - {header}: Trouvé")
                # print(f"      Valeur: {headers[header]}") # Optionnel: décommenter pour voir la valeur
                found_any = True
        
        if not found_any:
            print("    Aucun des en-têtes de sécurité majeurs n'a été trouvé.")

    except requests.exceptions.RequestException as e:
        print(f"  Erreur lors de la récupération des en-têtes : {e}")

def main():
    """Fonction principale du script."""
    parser = argparse.ArgumentParser(description="Analyseur de sécurité de site web.")
    parser.add_argument("url", help="L'URL du site web à analyser (ex: google.com).")
    args = parser.parse_args()

    hostname = get_hostname(args.url)
    
    print(f"Vérification de l'existence de l'hôte : {hostname}")
    if not check_host_exists(hostname):
        print(f"Erreur : L'hôte '{hostname}' est introuvable. Veuillez vérifier le nom de domaine.")
        sys.exit(1)
    
    print(f"Hôte trouvé. Début de l'analyse de : {hostname}")
    check_ssl_certificate(hostname)
    check_security_headers(hostname)

if __name__ == "__main__":
    main()

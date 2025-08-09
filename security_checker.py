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
import urllib.parse
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
        with socket.create_connection((hostname, 443), timeout=5) as sock:
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
                
                # Vérification de la version de TLS et du cipher
                tls_version = ssock.version()
                cipher_suite = ssock.cipher()
                print(f"  Version TLS négociée : {tls_version}")
                if tls_version in ["TLSv1.2", "TLSv1.3"]:
                    print("    ✅ SUCCÈS : La version de TLS est moderne et sécurisée.")
                else:
                    print(f"    ❌ ERREUR : La version de TLS ({tls_version}) est obsolète et non sécurisée.")
                print(f"  Suite de chiffrement : {cipher_suite[0]}")

    except ssl.SSLCertVerificationError as e:
        print(f"  ERREUR : La vérification du certificat a échoué ({e.reason}).")
        print("    Cause probable : Le serveur n'envoie pas la chaîne de certificats complète (certificat intermédiaire manquant) ou utilise un certificat auto-signé.")
        print("    Tentative de récupération des détails du certificat non approuvé...")
        try:
            insecure_context = ssl.create_default_context()
            insecure_context.check_hostname = False
            insecure_context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with insecure_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        print("    Le serveur n'a fourni aucun certificat lors de la connexion non sécurisée.")
                        return

                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    exp_date_str = cert.get('notAfter')
                    
                    print("    --- DÉTAILS DU CERTIFICAT NON APPROUVÉ ---")
                    print(f"      Sujet : {subject.get('commonName', 'N/A')}")
                    print(f"      Émetteur : {issuer.get('commonName', 'N/A')}")
                    
                    if exp_date_str:
                        exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                        print(f"      Expire le : {exp_date.strftime('%Y-%m-%d')}")
                    else:
                        print("      Date d'expiration : Information non disponible")
                    print("    -----------------------------------------")

        except Exception as inner_e:
            print(f"    Impossible de récupérer les détails du certificat non approuvé : {inner_e}")
    except socket.timeout:
        print("  ERREUR : La connexion au serveur a échoué (timeout).")
        print("    Cause probable : Le serveur ne répond pas sur le port 443, ou un pare-feu bloque la connexion.")
    except Exception as e:
        print(f"  Erreur inattendue lors de la vérification du certificat : {e}")

    print(f"\n  Pour une analyse SSL/TLS complète, consultez le rapport SSL Labs :")
    print(f"  https://www.ssllabs.com/ssltest/analyze.html?d={hostname}")

def check_http_to_https_redirect(hostname):
    """Vérifie si le site redirige automatiquement de HTTP vers HTTPS."""
    print("\n--- Analyse de la redirection HTTP vers HTTPS ---")
    try:
        url = f"http://{hostname}"
        response = requests.get(url, allow_redirects=False, timeout=10)

        if 300 <= response.status_code < 400:
            location = response.headers.get('Location', '')
            if location.startswith('https://'):
                print(f"  SUCCÈS : Le site redirige de HTTP vers HTTPS (Code: {response.status_code}).")
            else:
                print(f"  ERREUR : Le site redirige, mais pas directement vers HTTPS (vers: {location}).")
        else:
            print(f"  ERREUR : Le site ne redirige pas de HTTP vers HTTPS (Code: {response.status_code}).")

    except requests.exceptions.Timeout:
        print("  ERREUR : La connexion au serveur a échoué (timeout) lors du test de redirection.")
    except requests.exceptions.RequestException as e:
        print(f"  Erreur inattendue lors du test de redirection : {e}")

def check_security_headers(hostname):
    """Analyse les en-têtes de sécurité HTTP, y compris leurs valeurs."""
    print("\n--- Analyse des en-têtes de sécurité HTTP ---")
    try:
        url = f"https://{hostname}"
        response = requests.get(url, timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        print(f"  Analyse des en-têtes pour l'URL finale : {response.url}")

        # 1. Strict-Transport-Security (HSTS)
        print("\n  1. Strict-Transport-Security (HSTS) :")
        if 'strict-transport-security' in headers:
            value = headers['strict-transport-security']
            max_age_found = False
            if 'max-age' in value:
                max_age_val = int(value.split('max-age=')[1].split(';')[0])
                if max_age_val >= 15552000: # ~6 mois
                    print(f"    ✅ SUCCÈS : HSTS est activé avec un max-age long ({max_age_val}s).")
                    max_age_found = True
                else:
                    print(f"    ⚠️ AVERTISSEMENT : HSTS est activé, mais le max-age est court ({max_age_val}s). Recommandé : >= 15552000.")
            if not max_age_found:
                 print(f"    ⚠️ AVERTISSEMENT : L'en-tête HSTS est présent mais n'a pas de directive 'max-age'.")

            if 'includesubdomains' in value.lower():
                print("    ✅ SUCCÈS : La directive 'includeSubDomains' est présente.")
            else:
                print("    ⚠️ AVERTISSEMENT : La directive 'includeSubDomains' est recommandée mais absente.")
        else:
            print("    ❌ ERREUR : L'en-tête HSTS est manquant. Très recommandé.")

        # 2. X-Frame-Options
        print("\n  2. X-Frame-Options :")
        if 'x-frame-options' in headers:
            value = headers['x-frame-options'].upper()
            if value in ['DENY', 'SAMEORIGIN']:
                print(f"    ✅ SUCCÈS : X-Frame-Options est correctement configuré à '{value}'.")
            else:
                print(f"    ⚠️ AVERTISSEMENT : X-Frame-Options a une valeur non standard : '{value}'.")
        else:
            print("    ❌ ERREUR : L'en-tête X-Frame-Options est manquant. Recommandé pour prévenir le clickjacking.")
            
        # 3. X-Content-Type-Options
        print("\n  3. X-Content-Type-Options :")
        if 'x-content-type-options' in headers:
            value = headers['x-content-type-options'].lower()
            if value == 'nosniff':
                print(f"    ✅ SUCCÈS : X-Content-Type-Options est correctement configuré à 'nosniff'.")
            else:
                print(f"    ⚠️ AVERTISSEMENT : X-Content-Type-Options a une valeur inattendue : '{value}'.")
        else:
            print("    ❌ ERREUR : L'en-tête X-Content-Type-Options est manquant.")

        # 4. Content-Security-Policy (CSP)
        print("\n  4. Content-Security-Policy (CSP) :")
        if 'content-security-policy' in headers:
            print("    ✅ SUCCÈS : L'en-tête Content-Security-Policy est présent.")
            print(f"      Valeur : {headers['content-security-policy'][:100]}...") # Affiche les 100 premiers caractères
        else:
            print("    ⚠️ AVERTISSEMENT : L'en-tête Content-Security-Policy est manquant. Recommandé pour une défense en profondeur.")

    except requests.exceptions.Timeout:
        print("  ERREUR : La connexion au serveur a échoué (timeout) lors de la récupération des en-têtes.")
        print("    Cause probable : Le serveur est trop lent à répondre ou un pare-feu bloque la connexion.")
    except requests.exceptions.SSLError as e:
        print("  ERREUR : Une erreur SSL est survenue lors de la récupération des en-têtes.")
        print(f"    Cause probable : Le certificat du site n'est pas approuvé (auto-signé, chaîne incomplète, etc.). Détail : {e}")
    except requests.exceptions.RequestException as e:
        print(f"  Erreur inattendue lors de la récupération des en-têtes : {e}")

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
    check_http_to_https_redirect(hostname)
    check_security_headers(hostname)

if __name__ == "__main__":
    main()

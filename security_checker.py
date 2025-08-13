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
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.plugins.scan_commands import ScanCommand
import dns.resolver

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

def scan_tls_protocols(hostname):
    """Scanne les protocoles SSL/TLS supportés en utilisant sslyze."""
    print("\n--- Scan des protocoles SSL/TLS supportés ---")
    try:
        server_location = ServerNetworkLocation(hostname=hostname, port=443)

        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        print(f"  Scan en cours sur {hostname}, cela peut prendre un moment...")

        for server_scan_result in scanner.get_results():
            if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                print(f"  ERREUR : Impossible de se connecter à {hostname}: {server_scan_result.connectivity_error_trace}")
                return

            # Associer les résultats aux noms de protocoles
            scan_result = server_scan_result.scan_result
            protocol_results = {
                "SSL 2.0": scan_result.ssl_2_0_cipher_suites,
                "SSL 3.0": scan_result.ssl_3_0_cipher_suites,
                "TLS 1.0": scan_result.tls_1_0_cipher_suites,
                "TLS 1.1": scan_result.tls_1_1_cipher_suites,
                "TLS 1.2": scan_result.tls_1_2_cipher_suites,
                "TLS 1.3": scan_result.tls_1_3_cipher_suites,
            }

            for name, result_attempt in protocol_results.items():
                if result_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    print(f"    ⚠️  Le scan pour {name} a échoué : {result_attempt.error_reason}")
                    continue

                result = result_attempt.result
                if result.accepted_cipher_suites:
                    if name in ["TLS 1.2", "TLS 1.3"]:
                        print(f"    ✅ {name} : Supporté (CONFORME)")
                    else:
                        print(f"    ❌ {name} : Supporté (NON CONFORME - Vulnérable)")
                else:
                    print(f"    ✅ {name} : Non supporté (CONFORME)")
            break
    except ServerHostnameCouldNotBeResolved:
        print(f"  ERREUR : Le nom d'hôte '{hostname}' n'a pas pu être résolu.")
    except Exception as e:
        print(f"  Une erreur inattendue est survenue lors du scan sslyze : {e}")

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

def check_email_security_dns(hostname):
    """Vérifie la présence des enregistrements DNS de sécurité (NS, A, MX, DMARC, SPF)."""
    print("\n--- Analyse des enregistrements DNS et de sécurité e-mail ---")

    # 1. Vérification des serveurs de noms (NS)
    print("\n  1. Serveurs de noms (NS) :")
    try:
        answers = dns.resolver.resolve(hostname, 'NS')
        nameservers = [str(rdata.target) for rdata in answers]
        print(f"    ✅ SUCCÈS : {len(nameservers)} serveurs de noms trouvés.")
        for ns in nameservers:
            print(f"      - {ns}")
    except dns.resolver.NoAnswer:
        print("    ❌ ERREUR : Aucun enregistrement NS trouvé.")
    except Exception as e:
        print(f"    ⚠️ AVERTISSEMENT : Une erreur est survenue lors de la recherche des serveurs de noms : {e}")

    # 2. Vérification de l'enregistrement A
    print("\n  2. Enregistrement A (Adresse IP) :")
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        ips = [rdata.address for rdata in answers]
        print(f"    ✅ SUCCÈS : {len(ips)} adresse(s) IP trouvée(s).")
        for ip in ips:
            print(f"      - {ip}")
    except dns.resolver.NoAnswer:
        print("    ❌ ERREUR : Aucun enregistrement A trouvé.")
    except Exception as e:
        print(f"    ⚠️ AVERTISSEMENT : Une erreur est survenue lors de la recherche de l'enregistrement A : {e}")

    # 3. Vérification de l'enregistrement MX
    print("\n  3. Enregistrements MX (Serveurs de messagerie) :")
    try:
        answers = dns.resolver.resolve(hostname, 'MX')
        mx_records = sorted([(rdata.preference, str(rdata.exchange)) for rdata in answers])
        print(f"    ✅ SUCCÈS : {len(mx_records)} serveurs de messagerie trouvés.")
        for pref, exch in mx_records:
            print(f"      - Priorité {pref}: {exch}")
    except dns.resolver.NoAnswer:
        print("    ❌ ERREUR : Aucun enregistrement MX trouvé.")
    except Exception as e:
        print(f"    ⚠️ AVERTISSEMENT : Une erreur est survenue lors de la recherche des enregistrements MX : {e}")

    # 4. Vérification DMARC
    print("\n  4. Enregistrement DMARC :")
    try:
        dmarc_query = f"_dmarc.{hostname}"
        answers = dns.resolver.resolve(dmarc_query, 'TXT')
        dmarc_record = ' '.join([b.decode('utf-8') for b in answers[0].strings])
        print(f"    ✅ SUCCÈS : Enregistrement DMARC trouvé.")
        print(f"      Valeur : {dmarc_record}")
        if 'p=none' in dmarc_record.lower():
            print("      ℹ️ INFO : La politique est 'none'. C'est un bon début pour la surveillance. Pensez à passer à 'quarantine' ou 'reject' après avoir analysé les rapports.")
        if 'rua=' in dmarc_record.lower():
            print("      ℹ️ INFO : Assurez-vous de surveiller les rapports envoyés à l'adresse 'rua' pour identifier les problèmes d'envoi.")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        print("    ❌ ERREUR : Aucun enregistrement DMARC trouvé. Très recommandé.")
        print("\n      --- Comment corriger ---")
        print("      1. Créez un enregistrement DNS de type TXT avec le nom d'hôte '_dmarc'.")
        print("      2. Commencez avec une valeur simple pour surveiller, sans bloquer d'e-mails :")
        print("         v=DMARC1; p=none; rua=mailto:votre-adresse@exemple.com")
        print("      3. Remplacez 'votre-adresse@exemple.com' par une adresse où vous pouvez recevoir les rapports.")
        print("      ------------------------")
    except Exception as e:
        print(f"    ⚠️ AVERTISSEMENT : Une erreur est survenue lors de la recherche DMARC : {e}")

    # 5. Vérification SPF
    print("\n  5. Enregistrement SPF :")
    try:
        answers = dns.resolver.resolve(hostname, 'TXT')
        spf_record = None
        for record in answers:
            txt_record = ' '.join([b.decode('utf-8') for b in record.strings])
            if txt_record.startswith('v=spf1'):
                spf_record = txt_record
                break

        if spf_record:
            print(f"    ✅ SUCCÈS : Enregistrement SPF trouvé.")
            print(f"      Valeur : {spf_record}")
        else:
            print("    ❌ ERREUR : Aucun enregistrement SPF (v=spf1) trouvé dans les enregistrements TXT.")
            print("\n      --- Comment corriger ---")
            print("      1. Créez un enregistrement DNS de type TXT pour votre domaine principal.")
            print("      2. La valeur doit commencer par 'v=spf1' et inclure les adresses IP ou les domaines autorisés à envoyer des e-mails en votre nom.")
            print("         Exemple : v=spf1 ip4:192.168.0.1 include:_spf.google.com ~all")
            print("      3. '~all' ou '-all' à la fin indique comment traiter les e-mails non autorisés.")
            print("      ------------------------")
    except dns.resolver.NoAnswer:
        print("    ❌ ERREUR : Aucune réponse pour les enregistrements TXT du domaine (nécessaire pour SPF).")
    except Exception as e:
        print(f"    ⚠️ AVERTISSEMENT : Une erreur est survenue lors de la recherche SPF : {e}")

def check_cookie_security(hostname):
    """Analyse les attributs de sécurité des cookies définis par le serveur."""
    print("\n--- Analyse de la sécurité des cookies ---")
    try:
        url = f"https://{hostname}"
        response = requests.get(url, timeout=10)

        if not response.cookies:
            print("  Aucun cookie n'a été défini par le serveur sur la page d'accueil.")
            return

        # requests.cookies ne contient pas les attributs comme HttpOnly ou SameSite.
        # Il faut parser les en-têtes 'Set-Cookie' manuellement.
        raw_cookies = response.raw.headers.get_all('Set-Cookie', [])
        if not raw_cookies:
             # Fallback si get_all n'est pas dispo ou vide, on se base sur l'objet cookie
             if not response.cookies:
                print("  Aucun cookie n'a été défini par le serveur sur la page d'accueil.")
                return
             else: # On fait une analyse partielle
                for cookie in response.cookies:
                    print(f"\n  Analyse (partielle) du cookie : '{cookie.name}'")
                    if cookie.secure:
                        print("    ✅ SUCCÈS : L'attribut 'Secure' est présent.")
                    else:
                        print("    ❌ ERREUR : L'attribut 'Secure' est manquant.")
                    print("    ℹ️ INFO : L'analyse complète (HttpOnly, SameSite) a échoué, les en-têtes bruts sont indisponibles.")
                return


        for cookie_header in raw_cookies:
            parts = [p.strip() for p in cookie_header.split(';')]
            cookie_name = parts[0].split('=')[0]
            print(f"\n  Analyse du cookie : '{cookie_name}'")

            cookie_attributes = {p.lower() for p in parts[1:]}

            # Secure
            if 'secure' in cookie_attributes:
                print("    ✅ SUCCÈS : L'attribut 'Secure' est présent.")
            else:
                print("    ❌ ERREUR : L'attribut 'Secure' est manquant.")

            # HttpOnly
            if 'httponly' in cookie_attributes:
                print("    ✅ SUCCÈS : L'attribut 'HttpOnly' est présent.")
            else:
                print("    ⚠️ AVERTISSEMENT : L'attribut 'HttpOnly' est manquant.")

            # SameSite
            samesite_found = False
            for attr in cookie_attributes:
                if attr.startswith('samesite='):
                    value = attr.split('=')[1]
                    print(f"    ✅ SUCCÈS : L'attribut 'SameSite' est présent avec la valeur '{value}'.")
                    if value.lower() not in ['strict', 'lax']:
                        print("      ⚠️ AVERTISSEMENT : La valeur 'None' pour SameSite requiert l'attribut 'Secure'.")
                    samesite_found = True
                    break
            if not samesite_found:
                print("    ⚠️ AVERTISSEMENT : L'attribut 'SameSite' est manquant.")

    except requests.exceptions.RequestException as e:
        print(f"  Erreur lors de la récupération des cookies : {e}")

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
    scan_tls_protocols(hostname)
    check_http_to_https_redirect(hostname)
    check_security_headers(hostname)
    check_cookie_security(hostname)
    check_email_security_dns(hostname)

if __name__ == "__main__":
    main()

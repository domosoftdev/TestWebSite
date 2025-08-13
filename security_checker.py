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
import json
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
from bs4 import BeautifulSoup

SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
}

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
    """Vérifie le certificat SSL/TLS d'un hôte et retourne un dictionnaire de résultats."""
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
                    result.update({"statut": "ERROR", "message": "Le certificat a expiré.", "criticite": "CRITICAL", "remediation": "Renouvelez votre certificat SSL/TLS immédiatement."})
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
        return {"statut": "ERROR", "message": "La connexion au serveur a échoué (timeout).", "criticite": "HIGH", "remediation": "Assurez-vous que le port 443 est ouvert et accessible."}
    except Exception as e:
        return {"statut": "ERROR", "message": f"Erreur inattendue lors de la vérification du certificat : {e}", "criticite": "HIGH"}

def scan_tls_protocols(hostname):
    """Scanne les protocoles SSL/TLS supportés et retourne une liste de résultats."""
    results = []
    remediation_text = "Désactivez les protocoles SSL/TLS obsolètes sur votre serveur. Pour Nginx, utilisez 'ssl_protocols TLSv1.2 TLSv1.3;'. Pour Apache, 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'."
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
            for name, scan in proto_scans.items():
                if scan.status == ScanCommandAttemptStatusEnum.ERROR: continue
                if scan.result.accepted_cipher_suites:
                    crit = "HIGH" if name in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"] else "INFO"
                    res = {"protocole": name, "statut": "ERROR" if crit == "HIGH" else "SUCCESS", "message": "Supporté", "criticite": crit}
                    if crit == "HIGH": res["remediation"] = remediation_text
                    results.append(res)
                else:
                    results.append({"protocole": name, "statut": "SUCCESS", "message": "Non supporté", "criticite": "INFO"})
            return results
    except Exception as e:
        return [{"statut": "ERROR", "message": f"Erreur inattendue lors du scan sslyze: {e}", "criticite": "HIGH"}]

def check_http_to_https_redirect(hostname):
    """Vérifie si le site redirige automatiquement de HTTP vers HTTPS."""
    remediation_text = "Configurez votre serveur web pour forcer la redirection de tout le trafic HTTP vers HTTPS. Pour Nginx: 'return 301 https://$host$request_uri;'."
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
        return {"statut": "ERROR", "message": f"Erreur lors du test de redirection: {e}", "criticite": "HIGH"}

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
        dmarc_ans = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT')
        dmarc_rec = ' '.join([b.decode() for b in dmarc_ans[0].strings])
        results['dmarc'] = {"statut": "SUCCESS", "valeur": dmarc_rec, "criticite": "INFO"}
    except Exception:
        results['dmarc'] = {"statut": "ERROR", "message": "Aucun enregistrement DMARC trouvé.", "criticite": "HIGH", "remediation": "Ajoutez un enregistrement DMARC à votre zone DNS pour protéger contre l'usurpation d'e-mail."}
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
r
        else:
            results['spf'] = {"statut": "ERROR", "message": "Aucun enregistrement SPF trouvé.", "criticite": "HIGH", "remediation": "Ajoutez un enregistrement SPF à votre zone DNS pour spécifier les serveurs autorisés à envoyer des e-mails pour votre domaine."}
    except Exception:
        results['spf'] = {"statut": "ERROR", "message": "Aucun enregistrement TXT trouvé.", "criticite": "HIGH"}
    return results

def check_cookie_security(hostname):
    """Analyse les attributs de sécurité des cookies et retourne une liste de résultats."""
    results = []
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        raw_cookies = response.raw.headers.get_all('Set-Cookie', [])
        if not raw_cookies:
            return [{"statut": "INFO", "message": "Aucun cookie n'a été défini par le serveur.", "criticite": "INFO"}]

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
    """Analyse les en-têtes de sécurité HTTP et retourne un dictionnaire de résultats."""
    results = {"empreinte": [], "en-tetes_securite": {}}
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
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
            results['en-tetes_securite']['hsts'] = {"statut": "ERROR", "criticite": "HIGH", "remediation": "Implémentez l'en-tête HSTS avec un 'max-age' d'au moins 6 mois. Exemple pour Nginx: add_header Strict-Transport-Security 'max-age=15552000; includeSubDomains';"}

        xfo_header = headers.get('x-frame-options', '').upper()
        if xfo_header in ['DENY', 'SAMEORIGIN']:
            results['en-tetes_securite']['x-frame-options'] = {"statut": "SUCCESS", "criticite": "INFO"}
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
            results['en-tetes_securite']['x-content-type-options'] = {"statut": "ERROR", "criticite": "MEDIUM", "remediation": "Ajoutez l'en-tête 'X-Content-Type-Options: nosniff'."}

        csp_header = headers.get('content-security-policy')
        if csp_header:
            results['en-tetes_securite']['csp'] = {"statut": "SUCCESS", "criticite": "INFO"}
        else:
            results['en-tetes_securite']['csp'] = {"statut": "WARNING", "criticite": "LOW", "remediation": "Envisagez d'implémenter une Content Security Policy (CSP) pour une défense en profondeur contre les attaques XSS."}
            
        return results
    except Exception as e:
        return {"statut": "ERROR", "message": f"Erreur lors de la récupération des en-têtes: {e}", "criticite": "HIGH"}

def check_cms_footprint(hostname):
    """Recherche des empreintes de CMS via la balise meta et retourne un dictionnaire."""
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        soup = BeautifulSoup(response.content, 'lxml')
        gen_tag = soup.find('meta', attrs={'name': 'generator'})
        if gen_tag and gen_tag.get('content'):
            return {"statut": "INFO", "message": f"Balise 'generator' trouvée: {gen_tag.get('content')}", "criticite": "INFO"}
        return {"statut": "INFO", "message": "Aucune balise meta 'generator' trouvée.", "criticite": "INFO"}
    except Exception as e:
        return {"statut": "ERROR", "message": f"Erreur lors de l'analyse CMS: {e}", "criticite": "HIGH"}

def check_cms_paths(hostname):
    """Recherche des chemins de fichiers spécifiques à des CMS et retourne une liste de résultats."""
    results = []
    paths = {'WordPress': ['/wp-login.php', '/wp-admin/'], 'Joomla': ['/administrator/']}
    for cms, path_list in paths.items():
        for path in path_list:
            try:
                if requests.head(f"https://{hostname}{path}", timeout=3, allow_redirects=True).status_code in [200, 302, 301]:
                    results.append({"cms": cms, "path": path, "criticite": "INFO"})
            except requests.exceptions.RequestException: continue
    return results


def calculate_score(results):
    """Calcule le score de dangerosité et attribue une note."""
    total_score = 0
    
    def traverse_results(data):
        nonlocal total_score
        if isinstance(data, dict):
            if 'criticite' in data:
                total_score += SEVERITY_SCORES.get(data['criticite'], 0)
            for key, value in data.items():
                traverse_results(value)
        elif isinstance(data, list):
            for item in data:
                traverse_results(item)

    traverse_results(results)

    if total_score == 0:
        grade = "A+"
    elif total_score <= 10:
        grade = "A"
    elif total_score <= 20:
        grade = "B"
    elif total_score <= 40:
        grade = "C"
    elif total_score <= 60:
        grade = "D"
    else:
        grade = "F"
        
    return total_score, grade

def print_human_readable_report(results):
    """Affiche les résultats de l'analyse de manière lisible pour un humain."""
    
    STATUS_ICONS = {"SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}
    score, grade = calculate_score(results)

    print("\n" + "="*50)
    print(f" RAPPORT D'ANALYSE DE SÉCURITÉ POUR : {results['hostname']}")
    print(f" SCORE DE DANGEROSITÉ : {score} (Note : {grade})")
    print("="*50)

    # Helper to print severity
    def crit_str(criticite):
        return f"[{criticite}]" if criticite != "INFO" else ""

    # Certificat SSL
    print("\n--- Analyse du certificat SSL/TLS ---")
    ssl_cert = results.get('ssl_certificate', {})
    icon = STATUS_ICONS.get(ssl_cert.get('statut'), '❓')
    criticite = ssl_cert.get('criticite', '')
    print(f"  {icon} {crit_str(criticite)} {ssl_cert.get('message', 'Aucune donnée.')}")
    if ssl_cert.get('statut') == "SUCCESS":
        print(f"    Sujet    : {ssl_cert.get('sujet')}\n    Émetteur : {ssl_cert.get('emetteur')}\n    Expire le: {ssl_cert.get('date_expiration')}")
    if 'remediation' in ssl_cert:
        print(f"    -> Action : {ssl_cert['remediation']}")

    # Protocoles TLS
    print("\n--- Scan des protocoles SSL/TLS supportés ---")
    for proto in results.get('tls_protocols', []):
        icon = STATUS_ICONS.get(proto.get('statut'), '❓')
        criticite = proto.get('criticite', '')
        print(f"  {icon} {crit_str(criticite)} {proto.get('protocole', '')} : {proto.get('message', '')}")
        if 'remediation' in proto:
            print(f"    -> Action : {proto['remediation']}")

    # Redirection HTTP
    print("\n--- Analyse de la redirection HTTP vers HTTPS ---")
    redirect = results.get('http_redirect', {})
    icon = STATUS_ICONS.get(redirect.get('statut'), '❓')
    criticite = redirect.get('criticite', '')
    print(f"  {icon} {crit_str(criticite)} {redirect.get('message', 'Aucune donnée.')}")
    if 'remediation' in redirect:
        print(f"    -> Action : {redirect['remediation']}")

    # En-têtes de sécurité
    print("\n--- Analyse des en-têtes de sécurité HTTP ---")
    headers = results.get('security_headers', {})
    if headers.get("statut") == "ERROR":
        icon = STATUS_ICONS.get(headers.get('statut'), '❓')
        print(f"  {icon} {crit_str(headers.get('criticite'))} {headers.get('message')}")
    else:
        print(f"  [Empreinte Technologique]")
        for fp in headers.get('empreinte', []):
            print(f"    {STATUS_ICONS['INFO']} {crit_str(fp.get('criticite'))} {fp.get('header', '').title()} : {fp.get('valeur')}")
            if 'remediation' in fp:
                print(f"      -> Action : {fp['remediation']}")
        print("\n  [En-têtes de sécurité]")
        for name, data in headers.get('en-tetes_securite', {}).items():
            icon = STATUS_ICONS.get(data.get('statut'), '❓')
            message = data.get('valeur') if data.get('statut') == 'SUCCESS' else data.get('message')
            print(f"    {icon} {crit_str(data.get('criticite'))} {name.replace('_', '-').title()} : {message}")
            if 'remediation' in data:
                print(f"      -> Action : {data['remediation']}")

    # Sécurité des Cookies
    print("\n--- Analyse de la sécurité des cookies ---")
    cookies = results.get('cookie_security', [])
    if not cookies or cookies[0].get('criticite') == "INFO":
        print(f"  {STATUS_ICONS['INFO']} {cookies[0].get('message') if cookies else 'Aucune information sur les cookies.'}")
    else:
        for cookie in cookies:
            print(f"\n  Analyse du cookie : '{cookie.get('nom')}'")
            for name in ['secure', 'httponly', 'samesite']:
                attr = cookie.get(name, {})
                icon = "✅" if attr.get('present') else "❌"
                status_text = 'Présent' if attr.get('present') else 'Manquant'
                print(f"    {icon} {crit_str(attr.get('criticite'))} {name.title()} : {status_text}")
                if not attr.get('present') and 'remediation' in attr:
                    print(f"      -> Action : {attr['remediation']}")

    # Empreinte CMS
    print("\n--- Analyse d'empreinte CMS ---")
    cms_meta = results.get('cms_footprint_meta', {})
    print(f"  {STATUS_ICONS['INFO']} {crit_str(cms_meta.get('criticite'))} [Meta Generator] {cms_meta.get('message')}")
    cms_paths = results.get('cms_footprint_paths', [])
    if not cms_paths:
        print(f"  {STATUS_ICONS['INFO']} [Chemins Connus] Aucun chemin spécifique à un CMS commun n'a été trouvé.")
    else:
        for path in cms_paths:
            print(f"  {STATUS_ICONS['INFO']} {crit_str(path.get('criticite'))} [Chemins Connus] Indice de '{path['cms']}' trouvé sur le chemin '{path['path']}'")

    # Sécurité DNS
    print("\n--- Analyse des enregistrements DNS et de sécurité e-mail ---")
    dns_results = results.get('dns_security', {})
    for name, data in dns_results.items():
        icon = STATUS_ICONS.get(data.get('statut'), '❓')
        valeurs = data.get('valeur', data.get('message', ''))
        print(f"  {icon} {crit_str(data.get('criticite'))} {name.upper()} : {valeurs}")

    # Légende
    print("\n" + "="*50)
    print(" LÉGENDE DE LA NOTE :")
    print("  A+ : Excellent (0 points)")
    print("  A  : Bon (1-10 points)")
    print("  B  : Moyen (11-20 points)")
    print("  C  : Médiocre (21-40 points)")
    print("  D  : Mauvais (41-60 points)")
    print("  F  : Critique (>60 points)")
    print("="*50)


def main():
    """Fonction principale du script."""
    parser = argparse.ArgumentParser(description="Analyseur de sécurité de site web.")
    parser.add_argument("url", help="L'URL du site web à analyser (ex: google.com).")
    parser.add_argument(
        "--rapport",
        nargs='?',
        const="DEFAULT_FILENAME",
        help="Génère un rapport JSON. Si aucun nom de fichier n'est fourni, un nom par défaut sera utilisé."
    )
    args = parser.parse_args()

    hostname = get_hostname(args.url)
    
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

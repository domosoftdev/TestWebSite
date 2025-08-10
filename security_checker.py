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
                exp_date_str = cert['notAfter']
                exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')

                result = {
                    "sujet": subject.get('commonName', 'N/A'),
                    "emetteur": issuer.get('commonName', 'N/A'),
                    "date_expiration": exp_date.strftime('%Y-%m-%d'),
                }
                
                if exp_date < datetime.now():
                    result['statut'] = "ERROR"
                    result['message'] = "Le certificat a expiré."
                else:
                    result['statut'] = "SUCCESS"
                    result['message'] = "Le certificat est valide."
                return result

    except ssl.SSLCertVerificationError as e:
        return {
            "statut": "ERROR",
            "message": f"La vérification du certificat a échoué ({e.reason}).",
            "correction": "Cause probable : Le serveur n'envoie pas la chaîne de certificats complète (certificat intermédiaire manquant) ou utilise un certificat auto-signé."
        }
    except socket.timeout:
        return {
            "statut": "ERROR",
            "message": "La connexion au serveur a échoué (timeout).",
            "correction": "Le serveur ne répond pas sur le port 443, ou un pare-feu bloque la connexion."
        }
    except Exception as e:
        return {
            "statut": "ERROR",
            "message": f"Erreur inattendue lors de la vérification du certificat : {e}"
        }

def scan_tls_protocols(hostname):
    """Scanne les protocoles SSL/TLS supportés et retourne une liste de résultats."""
    results = []
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

        for server_scan_result in scanner.get_results():
            if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                return [{"statut": "ERROR", "message": f"Impossible de se connecter à {hostname} pour le scan TLS."}]

            scan_result = server_scan_result.scan_result
            protocol_scans = {
                "SSL 2.0": scan_result.ssl_2_0_cipher_suites, "SSL 3.0": scan_result.ssl_3_0_cipher_suites,
                "TLS 1.0": scan_result.tls_1_0_cipher_suites, "TLS 1.1": scan_result.tls_1_1_cipher_suites,
                "TLS 1.2": scan_result.tls_1_2_cipher_suites, "TLS 1.3": scan_result.tls_1_3_cipher_suites,
            }

            for name, scan_attempt in protocol_scans.items():
                if scan_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    results.append({"protocole": name, "statut": "ERROR", "message": f"Le scan a échoué: {scan_attempt.error_reason}"})
                    continue

                if scan_attempt.result.accepted_cipher_suites:
                    if name in ["TLS 1.2", "TLS 1.3"]:
                        results.append({"protocole": name, "statut": "SUCCESS", "message": "Supporté (CONFORME)"})
                    else:
                        results.append({"protocole": name, "statut": "ERROR", "message": "Supporté (NON CONFORME - Vulnérable)"})
                else:
                    results.append({"protocole": name, "statut": "SUCCESS", "message": "Non supporté (CONFORME)"})
            return results
        return results # Retourne une liste vide si la boucle ne s'exécute pas

    except ServerHostnameCouldNotBeResolved:
        return [{"statut": "ERROR", "message": f"Le nom d'hôte '{hostname}' n'a pas pu être résolu pour le scan TLS."}]
    except Exception as e:
        return [{"statut": "ERROR", "message": f"Une erreur inattendue est survenue lors du scan sslyze : {e}"}]

def check_http_to_https_redirect(hostname):
    """Vérifie si le site redirige automatiquement de HTTP vers HTTPS."""
    try:
        url = f"http://{hostname}"
        response = requests.get(url, allow_redirects=False, timeout=10)
        if 300 <= response.status_code < 400:
            location = response.headers.get('Location', '')
            if location.startswith('https://'):
                return {"statut": "SUCCESS", "message": f"Le site redirige de HTTP vers HTTPS (Code: {response.status_code})."}
            else:
                return {"statut": "ERROR", "message": f"Le site redirige, mais pas directement vers HTTPS (vers: {location})."}
        else:
            return {"statut": "ERROR", "message": f"Le site ne redirige pas de HTTP vers HTTPS (Code: {response.status_code})."}
    except requests.exceptions.Timeout:
        return {"statut": "ERROR", "message": "La connexion au serveur a échoué (timeout) lors du test de redirection."}
    except requests.exceptions.RequestException as e:
        return {"statut": "ERROR", "message": f"Erreur inattendue lors du test de redirection : {e}"}

def check_email_security_dns(hostname):
    """Vérifie la présence des enregistrements DNS de sécurité et retourne un dictionnaire de résultats."""
    results = {}
    # NS Records
    try:
        answers = dns.resolver.resolve(hostname, 'NS')
        results['ns_records'] = {"statut": "SUCCESS", "valeurs": [str(r.target) for r in answers]}
    except Exception as e:
        results['ns_records'] = {"statut": "ERROR", "message": str(e)}
    # A Records
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        results['a_records'] = {"statut": "SUCCESS", "valeurs": [r.address for r in answers]}
    except Exception as e:
        results['a_records'] = {"statut": "ERROR", "message": str(e)}
    # MX Records
    try:
        answers = dns.resolver.resolve(hostname, 'MX')
        results['mx_records'] = {"statut": "SUCCESS", "valeurs": sorted([f"Prio {r.preference}: {r.exchange}" for r in answers])}
    except Exception as e:
        results['mx_records'] = {"statut": "ERROR", "message": str(e)}
    # DMARC Record
    try:
        answers = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT')
        dmarc_record = ' '.join([b.decode() for b in answers[0].strings])
        results['dmarc'] = {"statut": "SUCCESS", "valeur": dmarc_record}
        if 'p=none' in dmarc_record.lower():
            results['dmarc']['commentaire'] = "La politique 'none' est une politique de surveillance. Pensez à passer à 'quarantine' ou 'reject'."
    except Exception:
        results['dmarc'] = {"statut": "ERROR", "message": "Aucun enregistrement DMARC trouvé."}
    # SPF Record
    try:
        answers = dns.resolver.resolve(hostname, 'TXT')
        spf_record = next((s for s in [' '.join([b.decode() for b in r.strings]) for r in answers] if s.startswith('v=spf1')), None)
        if spf_record:
            results['spf'] = {"statut": "SUCCESS", "valeur": spf_record}
        else:
            results['spf'] = {"statut": "ERROR", "message": "Aucun enregistrement SPF trouvé."}
    except Exception:
        results['spf'] = {"statut": "ERROR", "message": "Aucun enregistrement TXT trouvé pour le domaine (nécessaire pour SPF)."}

    return results

def check_cookie_security(hostname):
    """Analyse les attributs de sécurité des cookies et retourne une liste de résultats."""
    results = []
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        raw_cookies = response.raw.headers.get_all('Set-Cookie', [])
        if not raw_cookies:
            return [{"statut": "INFO", "message": "Aucun cookie n'a été défini par le serveur sur la page d'accueil."}]

        for header in raw_cookies:
            parts = [p.strip().lower() for p in header.split(';')]
            cookie_name = parts[0].split('=')[0]
            attributes = set(parts[1:])

            cookie_result = {"nom": cookie_name, "attributs": {}}
            # Secure
            cookie_result['attributs']['secure'] = {"present": 'secure' in attributes, "statut": "SUCCESS" if 'secure' in attributes else "ERROR"}
            # HttpOnly
            cookie_result['attributs']['httponly'] = {"present": 'httponly' in attributes, "statut": "SUCCESS" if 'httponly' in attributes else "WARNING"}
            # SameSite
            samesite_val = next((attr for attr in attributes if attr.startswith('samesite=')), None)
            if samesite_val:
                cookie_result['attributs']['samesite'] = {"present": True, "valeur": samesite_val.split('=')[1], "statut": "SUCCESS"}
            else:
                cookie_result['attributs']['samesite'] = {"present": False, "statut": "WARNING"}
            results.append(cookie_result)
        return results
    except requests.exceptions.RequestException as e:
        return [{"statut": "ERROR", "message": f"Erreur lors de la récupération des cookies : {e}"}]

def check_security_headers(hostname):
    """Analyse les en-têtes de sécurité HTTP et retourne un dictionnaire de résultats."""
    results = {"empreinte": [], "en-tetes_securite": {}}
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}
        results['url_finale'] = response.url

        # Footprinting
        footprint_map = {'server': 'Serveur Web', 'x-powered-by': 'Technologie (backend)'}
        for h, desc in footprint_map.items():
            if h in headers:
                results['empreinte'].append({"description": desc, "valeur": headers[h]})

        # HSTS
        hsts_header = headers.get('strict-transport-security')
        if hsts_header:
            max_age = next((int(p.split('=')[1]) for p in hsts_header.split(';') if 'max-age' in p), 0)
            status = "SUCCESS" if max_age >= 15552000 else "WARNING"
            results['en-tetes_securite']['hsts'] = {"statut": status, "valeur": hsts_header}
        else:
            results['en-tetes_securite']['hsts'] = {"statut": "ERROR", "message": "En-tête manquant."}

        # X-Frame-Options
        xfo_header = headers.get('x-frame-options', '').upper()
        if xfo_header in ['DENY', 'SAMEORIGIN']:
            results['en-tetes_securite']['x-frame-options'] = {"statut": "SUCCESS", "valeur": xfo_header}
        else:
            results['en-tetes_securite']['x-frame-options'] = {"statut": "ERROR", "message": "En-tête manquant ou mal configuré."}
            
        # X-Content-Type-Options
        xcto_header = headers.get('x-content-type-options', '').lower()
        if xcto_header == 'nosniff':
            results['en-tetes_securite']['x-content-type-options'] = {"statut": "SUCCESS", "valeur": xcto_header}
        else:
            results['en-tetes_securite']['x-content-type-options'] = {"statut": "ERROR", "message": "En-tête manquant ou mal configuré."}

        # CSP
        csp_header = headers.get('content-security-policy')
        if csp_header:
            results['en-tetes_securite']['csp'] = {"statut": "SUCCESS", "valeur": csp_header[:100] + "..."}
        else:
            results['en-tetes_securite']['csp'] = {"statut": "WARNING", "message": "En-tête manquant."}

        return results
    except requests.exceptions.RequestException as e:
        return {"statut": "ERROR", "message": f"Erreur lors de la récupération des en-têtes : {e}"}

def check_cms_footprint(hostname):
    """Recherche des empreintes de CMS via la balise meta et retourne un dictionnaire."""
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        soup = BeautifulSoup(response.content, 'lxml')
        generator_tag = soup.find('meta', attrs={'name': 'generator'})
        if generator_tag and generator_tag.get('content'):
            return {"statut": "INFO", "type": "meta_generator", "message": f"Balise 'generator' trouvée : {generator_tag.get('content')}"}
        return {"statut": "INFO", "message": "Aucune balise meta 'generator' trouvée."}
    except requests.exceptions.RequestException as e:
        return {"statut": "ERROR", "message": f"Erreur lors de la récupération de la page pour l'analyse CMS : {e}"}

def check_cms_paths(hostname):
    """Recherche des chemins de fichiers spécifiques à des CMS et retourne une liste de résultats."""
    results = []
    cms_paths = {
        'WordPress': ['/wp-login.php', '/wp-admin/'], 'Joomla': ['/administrator/'],
        'Drupal': ['/user/login'], 'Magento': ['/downloader/']
    }
    for cms, paths in cms_paths.items():
        for path in paths:
            try:
                response = requests.head(f"https://{hostname}{path}", timeout=5, allow_redirects=True)
                if response.status_code in [200, 302, 301]:
                    results.append({"statut": "INFO", "type": "known_path", "cms": cms, "path": path, "code_statut": response.status_code})
            except requests.exceptions.RequestException:
                continue
    return results


def print_human_readable_report(results):
    """Affiche les résultats de l'analyse de manière lisible pour un humain."""

    STATUS_ICONS = {
        "SUCCESS": "✅",
        "ERROR": "❌",
        "WARNING": "⚠️",
        "INFO": "ℹ️",
    }

    print(f"\n Hôte analysé : {results['hostname']}")
    print("="*40)

    # Certificat SSL
    print("\n--- Analyse du certificat SSL/TLS ---")
    ssl_cert = results.get('ssl_certificate', {})
    icon = STATUS_ICONS.get(ssl_cert.get('statut'), '❓')
    print(f"  {icon} {ssl_cert.get('message', 'Aucune donnée.')}")
    if ssl_cert.get('statut') == "SUCCESS":
        print(f"    Sujet    : {ssl_cert.get('sujet')}")
        print(f"    Émetteur : {ssl_cert.get('emetteur')}")
        print(f"    Expire le: {ssl_cert.get('date_expiration')}")
    if 'correction' in ssl_cert:
        print(f"    Correction : {ssl_cert['correction']}")

    # Protocoles TLS
    print("\n--- Scan des protocoles SSL/TLS supportés ---")
    tls_protocols = results.get('tls_protocols', [])
    for proto in tls_protocols:
        icon = STATUS_ICONS.get(proto.get('statut'), '❓')
        print(f"  {icon} {proto.get('protocole', '')} : {proto.get('message', '')}")

    # Redirection HTTP
    print("\n--- Analyse de la redirection HTTP vers HTTPS ---")
    redirect = results.get('http_redirect', {})
    icon = STATUS_ICONS.get(redirect.get('statut'), '❓')
    print(f"  {icon} {redirect.get('message', 'Aucune donnée.')}")

    # En-têtes de sécurité
    print("\n--- Analyse des en-têtes de sécurité HTTP ---")
    headers = results.get('security_headers', {})
    if headers.get("statut") == "ERROR":
        icon = STATUS_ICONS.get(headers.get('statut'), '❓')
        print(f"  {icon} {headers.get('message')}")
    else:
        print(f"  URL finale analysée : {headers.get('url_finale')}")
        # Empreinte
        print("\n  [Empreinte Technologique]")
        if headers.get('empreinte'):
            for fp in headers['empreinte']:
                print(f"    ℹ️ {fp['description']} : {fp['valeur']}")
        else:
            print("    ℹ️ Aucune empreinte technologique évidente trouvée.")
        # En-têtes
        print("\n  [En-têtes de sécurité]")
        for name, data in headers.get('en-tetes_securite', {}).items():
            icon = STATUS_ICONS.get(data.get('statut'), '❓')
            valeur = data.get('valeur', data.get('message', ''))
            print(f"    {icon} {name.replace('_', '-').title()} : {valeur}")

    # Sécurité des Cookies
    print("\n--- Analyse de la sécurité des cookies ---")
    cookies = results.get('cookie_security', [])
    if not cookies or cookies[0].get('statut') == "INFO":
        print(f"  ℹ️ {cookies[0].get('message') if cookies else 'Aucune information sur les cookies.'}")
    else:
        for cookie in cookies:
            print(f"\n  Analyse du cookie : '{cookie.get('nom')}'")
            for name, attr in cookie['attributs'].items():
                icon = STATUS_ICONS.get(attr.get('statut'), '❓')
                status_text = "Présent" if attr.get('present') else "Manquant"
                print(f"    {icon} {name.title()} : {status_text}")

    # Empreinte CMS
    print("\n--- Analyse d'empreinte CMS ---")
    cms_meta = results.get('cms_footprint_meta', {})
    icon = STATUS_ICONS.get(cms_meta.get('statut'), '❓')
    print(f"  {icon} [Meta Generator] {cms_meta.get('message')}")

    cms_paths = results.get('cms_footprint_paths', [])
    if not cms_paths:
        print("  ℹ️ [Chemins Connus] Aucun chemin spécifique à un CMS commun n'a été trouvé.")
    else:
        for path in cms_paths:
            print(f"  ℹ️ [Chemins Connus] Indice de '{path['cms']}' trouvé sur le chemin '{path['path']}'")

    # Sécurité DNS
    print("\n--- Analyse des enregistrements DNS et de sécurité e-mail ---")
    dns_results = results.get('dns_security', {})
    for name, data in dns_results.items():
        icon = STATUS_ICONS.get(data.get('statut'), '❓')
        valeurs = data.get('valeurs', [data.get('valeur', data.get('message', ''))])
        print(f"\n  {icon} {name.replace('_', ' ').upper()}")
        for v in valeurs:
            print(f"    - {v}")
        if 'commentaire' in data:
            print(f"    ℹ️ {data['commentaire']}")


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

    all_results = {'hostname': hostname}

    print(f"Analyse de {hostname} en cours...")

    all_results['ssl_certificate'] = check_ssl_certificate(hostname)
    all_results['tls_protocols'] = scan_tls_protocols(hostname)
    all_results['http_redirect'] = check_http_to_https_redirect(hostname)
    all_results['security_headers'] = check_security_headers(hostname)
    all_results['cookie_security'] = check_cookie_security(hostname)
    all_results['cms_footprint_meta'] = check_cms_footprint(hostname)
    all_results['cms_footprint_paths'] = check_cms_paths(hostname)
    all_results['dns_security'] = check_email_security_dns(hostname)
    
    # Affichage sur la console
    print_human_readable_report(all_results)

    # Génération du rapport JSON
    if args.rapport:
        if args.rapport == "DEFAULT_FILENAME":
            date_str = datetime.now().strftime('%d%m%y')
            filename = f"{hostname}_{date_str}.json"
        else:
            filename = args.rapport

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(all_results, f, indent=4, ensure_ascii=False)
            print(f"\n✅ Rapport JSON généré avec succès : {filename}")
        except IOError as e:
            print(f"\n❌ Erreur lors de l'écriture du rapport JSON : {e}")

if __name__ == "__main__":
    main()

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
                exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                result = {
                    "sujet": subject.get('commonName', 'N/A'),
                    "emetteur": issuer.get('commonName', 'N/A'),
                    "date_expiration": exp_date.strftime('%Y-%m-%d'),
                }
                if exp_date < datetime.now():
                    result.update({"statut": "ERROR", "message": "Le certificat a expiré.", "criticite": "CRITICAL", "remediation": "Renouvelez votre certificat SSL/TLS immédiatement."})
                else:
                    result.update({"statut": "SUCCESS", "message": "Le certificat est valide.", "criticite": "INFO"})
                return result
    except ssl.SSLCertVerificationError as e:
        return {"statut": "ERROR", "message": f"La vérification du certificat a échoué ({e.reason}).", "criticite": "HIGH", "remediation": "Vérifiez que votre chaîne de certificats est complète (certificats intermédiaires) et que le certificat n'est pas auto-signé."}
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
        for result in scanner.get_results():
            if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                return [{"statut": "ERROR", "message": f"Impossible de se connecter à {hostname} pour le scan TLS.", "criticite": "HIGH"}]
            
            proto_scans = {
                "SSL 2.0": result.scan_result.ssl_2_0_cipher_suites, "SSL 3.0": result.scan_result.ssl_3_0_cipher_suites,
                "TLS 1.0": result.scan_result.tls_1_0_cipher_suites, "TLS 1.1": result.scan_result.tls_1_1_cipher_suites,
                "TLS 1.2": result.scan_result.tls_1_2_cipher_suites, "TLS 1.3": result.scan_result.tls_1_3_cipher_suites,
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
        response = requests.get(f"http://{hostname}", allow_redirects=False, timeout=10)
        if 300 <= response.status_code < 400 and response.headers.get('Location', '').startswith('https://'):
            return {"statut": "SUCCESS", "message": "Redirection correcte vers HTTPS.", "criticite": "INFO"}
        return {"statut": "ERROR", "message": "La redirection de HTTP vers HTTPS n'est pas correctement configurée.", "criticite": "MEDIUM", "remediation": remediation_text}
    except Exception as e:
        return {"statut": "ERROR", "message": f"Erreur lors du test de redirection: {e}", "criticite": "HIGH"}

def check_email_security_dns(hostname):
    """Vérifie la présence des enregistrements DNS de sécurité et retourne un dictionnaire de résultats."""
    results = {}
    try:
        dmarc_ans = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT')
        dmarc_rec = ' '.join([b.decode() for b in dmarc_ans[0].strings])
        results['dmarc'] = {"statut": "SUCCESS", "valeur": dmarc_rec, "criticite": "INFO"}
    except Exception:
        results['dmarc'] = {"statut": "ERROR", "message": "Aucun enregistrement DMARC trouvé.", "criticite": "HIGH", "remediation": "Ajoutez un enregistrement DMARC à votre zone DNS pour protéger contre l'usurpation d'e-mail."}
    try:
        txt_ans = dns.resolver.resolve(hostname, 'TXT')
        spf_rec = next((s for s in [' '.join([b.decode() for r in txt_ans]) for r in txt_ans] if s.startswith('v=spf1')), None)
        if spf_rec:
            results['spf'] = {"statut": "SUCCESS", "valeur": spf_rec, "criticite": "INFO"}
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

        for header in raw_cookies:
            parts = [p.strip().lower() for p in header.split(';')]
            cookie_name = parts[0].split('=')[0]
            attributes = set(parts[1:])
            
            cookie_res = {"nom": cookie_name}
            secure_ok = 'secure' in attributes
            httponly_ok = 'httponly' in attributes
            samesite_ok = any(a.startswith('samesite=') for a in attributes)

            cookie_res["secure"] = {"present": secure_ok, "criticite": "INFO" if secure_ok else "HIGH", "remediation": "Ajoutez l'attribut 'Secure' à vos cookies."}
            cookie_res["httponly"] = {"present": httponly_ok, "criticite": "INFO" if httponly_ok else "MEDIUM", "remediation": "Ajoutez l'attribut 'HttpOnly' pour empêcher l'accès aux cookies via JavaScript."}
            cookie_res["samesite"] = {"present": samesite_ok, "criticite": "INFO" if samesite_ok else "MEDIUM", "remediation": "Ajoutez l'attribut 'SameSite=Strict' ou 'SameSite=Lax' pour protéger contre les attaques CSRF."}
            results.append(cookie_res)
        return results
    except Exception as e:
        return [{"statut": "ERROR", "message": f"Erreur lors de la récupération des cookies: {e}", "criticite": "HIGH"}]

def check_security_headers(hostname):
    """Analyse les en-têtes de sécurité HTTP et retourne un dictionnaire de résultats."""
    results = {"empreinte": [], "en-tetes_securite": {}}
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}
        results['url_finale'] = response.url

        for h in ['server', 'x-powered-by', 'x-aspnet-version']:
            if h in headers:
                results['empreinte'].append({"header": h, "valeur": headers[h], "criticite": "LOW", "remediation": f"Supprimez l'en-tête '{h}' de vos réponses HTTP pour ne pas divulguer d'informations sur votre infrastructure."})

        hsts_header = headers.get('strict-transport-security')
        if hsts_header and 'max-age' in hsts_header and int(hsts_header.split('max-age=')[1].split(';')[0]) >= 15552000:
            results['en-tetes_securite']['hsts'] = {"statut": "SUCCESS", "criticite": "INFO"}
        else:
            results['en-tetes_securite']['hsts'] = {"statut": "ERROR", "criticite": "HIGH", "remediation": "Implémentez l'en-tête HSTS avec un 'max-age' d'au moins 6 mois. Exemple pour Nginx: add_header Strict-Transport-Security 'max-age=15552000; includeSubDomains';"}

        xfo_header = headers.get('x-frame-options', '').upper()
        if xfo_header in ['DENY', 'SAMEORIGIN']:
            results['en-tetes_securite']['x-frame-options'] = {"statut": "SUCCESS", "criticite": "INFO"}
        else:
            results['en-tetes_securite']['x-frame-options'] = {"statut": "ERROR", "criticite": "MEDIUM", "remediation": "Ajoutez l'en-tête 'X-Frame-Options: SAMEORIGIN' ou 'DENY' pour vous protéger du clickjacking."}

        xcto_header = headers.get('x-content-type-options', '').lower()
        if xcto_header == 'nosniff':
            results['en-tetes_securite']['x-content-type-options'] = {"statut": "SUCCESS", "criticite": "INFO"}
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
    
    # Calcul du score final
    score, grade = calculate_score(all_results)
    all_results['score_final'] = score
    all_results['note'] = grade

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

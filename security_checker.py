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
import csv
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
import re
from packaging import version
import whois

SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0
}

REMEDIATION_ADVICE = {
    "CERT_EXPIRED": { "default": "Renouvelez votre certificat SSL/TLS immédiatement." },
    "CERT_VERIFY_FAILED": { "default": "Vérifiez que votre chaîne de certificats est complète (certificats intermédiaires) et que le certificat n'est pas auto-signé." },
    "TLS_OBSOLETE": { "description": "Désactivez les protocoles SSL/TLS obsolètes.", "nginx": "Dans votre bloc server, utilisez : ssl_protocols TLSv1.2 TLSv1.3;", "apache": "Dans votre configuration SSL, utilisez : SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", "default": "Consultez la documentation de votre serveur pour désactiver SSLv3, TLSv1.0 et TLSv1.1." },
    "NO_HTTPS_REDIRECT": { "nginx": "Dans votre bloc server pour le port 80, utilisez : return 301 https://$host$request_uri;", "apache": "Utilisez mod_rewrite pour forcer la redirection vers HTTPS.", "default": "Configurez votre serveur web pour forcer la redirection de tout le trafic HTTP vers HTTPS." },
    "DMARC_MISSING": { "default": "Ajoutez un enregistrement DMARC à votre zone DNS pour protéger contre l'usurpation d'e-mail. Exemple : 'v=DMARC1; p=none; rua=mailto:dmarc-reports@votre-domaine.com;'" },
    "SPF_MISSING": { "default": "Ajoutez un enregistrement SPF à votre zone DNS pour spécifier les serveurs autorisés à envoyer des e-mails pour votre domaine. Exemple : 'v=spf1 include:_spf.google.com ~all'" },
    "COOKIE_NO_SECURE": { "default": "Ajoutez l'attribut 'Secure' à tous vos cookies pour vous assurer qu'ils ne sont envoyés que sur des connexions HTTPS." },
    "COOKIE_NO_HTTPONLY": { "default": "Ajoutez l'attribut 'HttpOnly' à vos cookies de session pour empêcher leur accès via JavaScript." },
    "COOKIE_NO_SAMESITE": { "default": "Ajoutez l'attribut 'SameSite=Strict' ou 'SameSite=Lax' à vos cookies pour vous protéger contre les attaques CSRF." },
    "HSTS_MISSING": { "nginx": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';", "apache": "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'", "default": "Implémentez l'en-tête HSTS avec un 'max-age' d'au moins 6 mois (15552000 secondes)." },
    "XFO_MISSING": { "nginx": "add_header X-Frame-Options 'SAMEORIGIN';", "apache": "Header always set X-Frame-Options 'SAMEORIGIN'", "default": "Ajoutez l'en-tête 'X-Frame-Options: SAMEORIGIN' ou 'DENY' pour vous protéger du clickjacking." },
    "XCTO_MISSING": { "nginx": "add_header X-Content-Type-Options 'nosniff';", "apache": "Header always set X-Content-Type-Options 'nosniff'", "default": "Ajoutez l'en-tête 'X-Content-Type-Options: nosniff'." },
    "CSP_MISSING": { "default": "Envisagez d'implémenter une Content Security Policy (CSP) pour une défense en profondeur contre les attaques par injection de script (XSS)." },
    "SERVER_HEADER_VISIBLE": { "nginx": "Dans votre configuration nginx, ajoutez 'server_tokens off;'.", "apache": "Dans votre configuration apache, ajoutez 'ServerTokens Prod'.", "default": "Supprimez ou masquez les en-têtes qui révèlent la version de votre serveur." },
    "JS_LIB_OBSOLETE": { "default": "Une ou plusieurs bibliothèques JavaScript sont obsolètes. Mettez-les à jour vers leur dernière version stable pour corriger les vulnérabilités connues." },
    "WP_CONFIG_BAK_EXPOSED": { "default": "Supprimez immédiatement le fichier de sauvegarde de configuration WordPress exposé publiquement." },
    "WP_USER_ENUM_ENABLED": { "default": "Empêchez l'énumération des utilisateurs sur WordPress, par exemple en utilisant un plugin de sécurité ou en ajoutant des règles de réécriture." }
}

OSV_API_URL = "https://api.osv.dev/v1/query"
KNOWN_JS_LIBRARIES = { "jquery": {"latest": "3.7.1", "ecosystem": "jQuery"}, "react": {"latest": "18.2.0", "ecosystem": "npm"}, "angular": {"latest": "1.7.9", "ecosystem": "npm"} }

def query_osv_api(package_name, version, ecosystem):
    query = { "version": version, "package": { "name": package_name, "ecosystem": ecosystem } }
    try:
        response = requests.post(OSV_API_URL, json=query, timeout=15)
        if response.status_code == 200 and response.json().get('vulns'):
            return response.json()['vulns']
    except requests.exceptions.RequestException:
        return None
    return None

def check_host_exists(hostname):
    try:
        socket.gethostbyname_ex(hostname)
        return True
    except socket.gaierror:
        return False

def get_hostname(url):
    if url.startswith('https://'): url = url[8:]
    if url.startswith('http://'): url = url[7:]
    if '/' in url: url = url.split('/')[0]
    return url

def check_ssl_certificate(hostname):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert.get('issuer', []))
                exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                jours_restants = (exp_date - datetime.now()).days
                result = {"sujet": subject.get('commonName', 'N/A'), "emetteur": issuer.get('commonName', 'N/A'), "date_expiration": exp_date.strftime('%Y-%m-%d'), "jours_restants": jours_restants}
                if jours_restants < 0:
                    result.update({"statut": "ERROR", "message": "Le certificat a expiré.", "criticite": "CRITICAL", "remediation_id": "CERT_EXPIRED"})
                else:
                    result.update({"statut": "SUCCESS", "message": "Le certificat est valide.", "criticite": "INFO"})
                return result
    except ssl.SSLCertVerificationError as e:
        return {"statut": "ERROR", "message": f"La vérification du certificat a échoué ({e.reason}).", "criticite": "HIGH", "remediation_id": "CERT_VERIFY_FAILED"}
    except socket.timeout:
        return {"statut": "ERROR", "message": "La connexion au serveur a échoué (timeout).", "criticite": "HIGH"}
    except Exception as e:
        return {"statut": "ERROR", "message": f"Erreur inattendue lors de la vérification du certificat : {e}", "criticite": "HIGH"}

def scan_tls_protocols(hostname):
    results = []
    try:
        server_location = ServerNetworkLocation(hostname=hostname, port=443)
        scan_request = ServerScanRequest(server_location=server_location, scan_commands={ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES})
        scanner = Scanner()
        scanner.queue_scans([scan_request])
        for result in scanner.get_results():
            if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                return [{"statut": "ERROR", "message": f"Impossible de se connecter à {hostname} pour le scan TLS.", "criticite": "HIGH"}]
            proto_scans = {"SSL 2.0": result.scan_result.ssl_2_0_cipher_suites, "SSL 3.0": result.scan_result.ssl_3_0_cipher_suites, "TLS 1.0": result.scan_result.tls_1_0_cipher_suites, "TLS 1.1": result.scan_result.tls_1_1_cipher_suites, "TLS 1.2": result.scan_result.tls_1_2_cipher_suites, "TLS 1.3": result.scan_result.tls_1_3_cipher_suites}
            for name, scan in proto_scans.items():
                if scan.status == ScanCommandAttemptStatusEnum.ERROR: continue
                if scan.result.accepted_cipher_suites:
                    crit = "HIGH" if name in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"] else "INFO"
                    res = {"protocole": name, "statut": "ERROR" if crit == "HIGH" else "SUCCESS", "message": "Supporté", "criticite": crit}
                    if crit == "HIGH": res["remediation_id"] = "TLS_OBSOLETE"
                    results.append(res)
                else:
                    results.append({"protocole": name, "statut": "SUCCESS", "message": "Non supporté", "criticite": "INFO"})
            return results
    except Exception as e:
        return [{"statut": "ERROR", "message": f"Erreur inattendue lors du scan sslyze: {e}", "criticite": "HIGH"}]

def check_http_to_https_redirect(hostname):
    try:
        response = requests.get(f"http://{hostname}", allow_redirects=False, timeout=10)
        if 300 <= response.status_code < 400 and response.headers.get('Location', '').startswith('https://'):
            return {"statut": "SUCCESS", "message": "Redirection correcte vers HTTPS.", "criticite": "INFO"}
        return {"statut": "ERROR", "message": "La redirection de HTTP vers HTTPS n'est pas correctement configurée.", "criticite": "MEDIUM", "remediation_id": "NO_HTTPS_REDIRECT"}
    except Exception as e:
        return {"statut": "ERROR", "message": f"Erreur lors du test de redirection: {e}", "criticite": "HIGH"}

def check_dns_records(hostname):
    results = {}
    try:
        ns_ans = dns.resolver.resolve(hostname, 'NS'); results['ns'] = {"statut": "SUCCESS", "valeurs": [str(r.target) for r in ns_ans], "criticite": "INFO"}
    except Exception as e: results['ns'] = {"statut": "ERROR", "message": f"Impossible de récupérer les enregistrements NS ({e})", "criticite": "LOW"}
    try:
        a_ans = dns.resolver.resolve(hostname, 'A'); results['a'] = {"statut": "SUCCESS", "valeurs": [r.address for r in a_ans], "criticite": "INFO"}
    except Exception as e: results['a'] = {"statut": "ERROR", "message": f"Impossible de récupérer les enregistrements A ({e})", "criticite": "LOW"}
    try:
        mx_ans = dns.resolver.resolve(hostname, 'MX'); mx_records = sorted([(r.preference, str(r.exchange)) for r in mx_ans]); results['mx'] = {"statut": "SUCCESS", "valeurs": [f"Prio {p}: {e}" for p, e in mx_records], "criticite": "INFO"}
    except Exception as e: results['mx'] = {"statut": "ERROR", "message": f"Impossible de récupérer les enregistrements MX ({e})", "criticite": "LOW"}
    try:
        dmarc_ans = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT'); dmarc_rec = ' '.join([b.decode() for b in dmarc_ans[0].strings]); results['dmarc'] = {"statut": "SUCCESS", "valeur": dmarc_rec, "criticite": "INFO"}
    except Exception: results['dmarc'] = {"statut": "ERROR", "message": "Aucun enregistrement DMARC trouvé.", "criticite": "HIGH", "remediation_id": "DMARC_MISSING"}
    try:
        txt_ans = dns.resolver.resolve(hostname, 'TXT'); spf_rec = next((s for s in [' '.join([b.decode() for r in txt_ans]) for r in txt_ans] if s.startswith('v=spf1')), None)
        if spf_rec: results['spf'] = {"statut": "SUCCESS", "valeur": spf_rec, "criticite": "INFO"}
        else: results['spf'] = {"statut": "ERROR", "message": "Aucun enregistrement SPF trouvé.", "criticite": "HIGH", "remediation_id": "SPF_MISSING"}
    except Exception: results['spf'] = {"statut": "ERROR", "message": "Aucun enregistrement TXT trouvé.", "criticite": "HIGH"}
    return results

def check_cookie_security(hostname):
    results = []
    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        raw_cookies = response.raw.headers.get_all('Set-Cookie', [])
        if not raw_cookies: return [{"statut": "INFO", "message": "Aucun cookie n'a été défini par le serveur.", "criticite": "INFO"}]
        for header in raw_cookies:
            parts = [p.strip().lower() for p in header.split(';')]
            cookie_name = parts[0].split('=')[0]; attributes = set(parts[1:])
            cookie_res = {"nom": cookie_name}; secure_ok = 'secure' in attributes; httponly_ok = 'httponly' in attributes; samesite_ok = any(a.startswith('samesite=') for a in attributes)
            cookie_res["secure"] = {"present": secure_ok, "criticite": "INFO" if secure_ok else "HIGH", "remediation_id": "COOKIE_NO_SECURE"}
            cookie_res["httponly"] = {"present": httponly_ok, "criticite": "INFO" if httponly_ok else "MEDIUM", "remediation_id": "COOKIE_NO_HTTPONLY"}
            cookie_res["samesite"] = {"present": samesite_ok, "criticite": "INFO" if samesite_ok else "MEDIUM", "remediation_id": "COOKIE_NO_SAMESITE"}
            results.append(cookie_res)
        return results
    except Exception as e:
        return [{"statut": "ERROR", "message": f"Erreur lors de la récupération des cookies: {e}", "criticite": "HIGH"}]

def check_security_headers(hostname):
    results = {"empreinte": [], "en-tetes_securite": {}}
    try:
        response = requests.get(f"https://{hostname}", timeout=10); headers = {k.lower(): v for k, v in response.headers.items()}; results['url_finale'] = response.url
        for h in ['server', 'x-powered-by', 'x-aspnet-version']:
            if h in headers: results['empreinte'].append({"header": h, "valeur": headers[h], "criticite": "LOW", "remediation_id": "SERVER_HEADER_VISIBLE"})
        hsts_header = headers.get('strict-transport-security')
        if hsts_header and 'max-age' in hsts_header and int(hsts_header.split('max-age=')[1].split(';')[0]) >= 15552000: results['en-tetes_securite']['hsts'] = {"statut": "SUCCESS", "criticite": "INFO"}
        else: results['en-tetes_securite']['hsts'] = {"statut": "ERROR", "criticite": "HIGH", "remediation_id": "HSTS_MISSING"}
        xfo_header = headers.get('x-frame-options', '').upper()
        if xfo_header in ['DENY', 'SAMEORIGIN']: results['en-tetes_securite']['x-frame-options'] = {"statut": "SUCCESS", "criticite": "INFO"}
        else: results['en-tetes_securite']['x-frame-options'] = {"statut": "ERROR", "criticite": "MEDIUM", "remediation_id": "XFO_MISSING"}
        xcto_header = headers.get('x-content-type-options', '').lower()
        if xcto_header == 'nosniff': results['en-tetes_securite']['x-content-type-options'] = {"statut": "SUCCESS", "criticite": "INFO"}
        else: results['en-tetes_securite']['x-content-type-options'] = {"statut": "ERROR", "criticite": "MEDIUM", "remediation_id": "XCTO_MISSING"}
        csp_header = headers.get('content-security-policy')
        if csp_header: results['en-tetes_securite']['csp'] = {"statut": "SUCCESS", "criticite": "INFO"}
        else: results['en-tetes_securite']['csp'] = {"statut": "WARNING", "criticite": "LOW", "remediation_id": "CSP_MISSING"}
        return results
    except Exception as e:
        return {"statut": "ERROR", "message": f"Erreur lors de la récupération des en-têtes: {e}", "criticite": "HIGH"}

def check_cms_footprint(hostname):
    try:
        response = requests.get(f"https://{hostname}", timeout=10); soup = BeautifulSoup(response.content, 'lxml'); gen_tag = soup.find('meta', attrs={'name': 'generator'})
        if gen_tag and gen_tag.get('content'): return {"statut": "INFO", "message": f"Balise 'generator' trouvée: {gen_tag.get('content')}", "criticite": "INFO"}
        return {"statut": "INFO", "message": "Aucune balise meta 'generator' trouvée.", "criticite": "INFO"}
    except Exception as e:
        return {"statut": "ERROR", "message": f"Erreur lors de l'analyse CMS: {e}", "criticite": "HIGH"}

def check_cms_paths(hostname):
    results = []; paths = {'WordPress': ['/wp-login.php', '/wp-admin/'], 'Joomla': ['/administrator/']}
    for cms, path_list in paths.items():
        for path in path_list:
            try:
                if requests.head(f"https://{hostname}{path}", timeout=3, allow_redirects=True).status_code in [200, 302, 301]: results.append({"cms": cms, "path": path, "criticite": "INFO"})
            except requests.exceptions.RequestException: continue
    return results

def check_js_libraries(hostname):
    """
    Scans a given hostname for known JavaScript libraries using two methods:
    1. Regex matching on script filenames (for versioned files).
    2. Signature matching within inline script content.
    """
    results = []
    detected_libs = {}  # Use a dict to store findings and prevent duplicates

    try:
        response = requests.get(f"https://{hostname}", timeout=10)
        soup = BeautifulSoup(response.content, 'lxml')

        # --- METHOD 1: Scan external script filenames ---
        # This method is fast and precise if the library includes its version in the filename.
        for script in soup.find_all('script', src=True):
            src = script['src']
            # Flexible, non-greedy regex to find patterns like 'jquery-3.7.1.min.js'
            match = re.search(r'([a-zA-Z0-9.-]+?)[._-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:[._-]min)?\.js', src)
            if match:
                lib_name = match.group(1).lower()
                detected_version_str = match.group(2)
                # If it's a known library and we haven't found it yet, store it.
                if lib_name in KNOWN_JS_LIBRARIES and lib_name not in detected_libs:
                    detected_libs[lib_name] = {"version": detected_version_str, "source": "filename"}

        # --- METHOD 2: Scan inline script content for signatures ---
        # This method is broader and can find libraries that are bundled or loaded dynamically,
        # but it often cannot determine the exact version number.
        for script in soup.find_all('script'):
            content = script.string
            if not content:
                continue
            
            # Signature for jQuery: presence of 'jQuery' or the '$(' function call.
            if 'jquery' not in detected_libs and ('jQuery' in content or re.search(r'\$\s*\(', content)):
                detected_libs['jquery'] = {"version": "inconnu", "source": "inline content"}
            # Signature for React: presence of 'React.createElement'.
            if 'react' not in detected_libs and 'React.createElement' in content:
                detected_libs['react'] = {"version": "inconnu", "source": "inline content"}
            # Signature for AngularJS: presence of 'angular.module'.
            if 'angular' not in detected_libs and 'angular.module' in content:
                detected_libs['angular'] = {"version": "inconnu", "source": "inline content"}

        # --- Consolidate and format results ---
        for lib_name, data in detected_libs.items():
            lib_info = KNOWN_JS_LIBRARIES[lib_name]
            latest_version_str = lib_info["latest"]
            detected_version_str = data["version"]

            result_entry = {"bibliotheque": lib_name, "version_detectee": detected_version_str, "derniere_version": latest_version_str, "vulnerabilities": []}

            # Handle cases where the version could not be determined.
            if detected_version_str == "inconnu":
                result_entry.update({"statut": "WARNING", "criticite": "LOW", "message": "Bibliothèque détectée mais version inconnue."})
            else:
                # If version is known, compare it to the latest known version.
                try:
                    detected_v = version.parse(detected_version_str)
                    latest_v = version.parse(latest_version_str)
                    if detected_v < latest_v:
                        result_entry.update({"statut": "WARNING", "criticite": "MEDIUM", "remediation_id": "JS_LIB_OBSOLETE"})
                        # Check for known vulnerabilities in the old version.
                        vulns = query_osv_api(lib_name, detected_version_str, lib_info["ecosystem"])
                        if vulns:
                            result_entry["criticite"] = "HIGH"
                            for v in vulns: result_entry["vulnerabilities"].append({"id": v.get('id'), "summary": v.get('summary', 'Pas de résumé.'), "details": v.get('details', '')})
                    else:
                        result_entry.update({"statut": "SUCCESS", "criticite": "INFO"})
                except version.InvalidVersion:
                    continue # Skip if the detected version string is invalid.
            results.append(result_entry)

    except Exception as e:
        # Return a generic error if the scan fails for any reason (e.g., network issues).
        return [{"statut": "ERROR", "message": f"Erreur lors de l'analyse des bibliothèques JS: {e}", "criticite": "HIGH"}]
    return results
    
def check_wordpress_specifics(hostname):
    results = {}; base_url = f"https://{hostname}"
    try:
        url = f"{base_url}/wp-config.php.bak"; response = requests.head(url, timeout=5, allow_redirects=False)
        if response.status_code == 200: results['config_backup'] = {"statut": "ERROR", "criticite": "CRITICAL", "message": f"Le fichier de sauvegarde {url} est exposé publiquement.", "remediation_id": "WP_CONFIG_BAK_EXPOSED"}
        else: results['config_backup'] = {"statut": "SUCCESS", "criticite": "INFO", "message": "Le fichier wp-config.php.bak n'a pas été trouvé."}
    except requests.exceptions.RequestException: results['config_backup'] = {"statut": "INFO", "criticite": "INFO", "message": "Erreur réseau lors de la vérification de wp-config.php.bak."}
    try:
        url = f"{base_url}/?author=1"; response = requests.get(url, timeout=5, allow_redirects=False); location = response.headers.get('Location', '')
        if 300 <= response.status_code < 400 and '/author/' in location:
            username = location.split('/author/')[1].split('/')[0]; results['user_enum'] = {"statut": "ERROR", "criticite": "MEDIUM", "message": f"L'énumération d'utilisateurs est possible. Nom d'utilisateur trouvé : '{username}'.", "remediation_id": "WP_USER_ENUM_ENABLED"}
        else: results['user_enum'] = {"statut": "SUCCESS", "criticite": "INFO", "message": "L'énumération d'utilisateurs via ?author=1 ne semble pas possible."}
    except requests.exceptions.RequestException: results['user_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Erreur réseau lors de la vérification de l'énumération d'utilisateurs."}
    try:
        response = requests.get(base_url, timeout=10); soup = BeautifulSoup(response.content, 'lxml'); plugin_pattern = re.compile(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/'); found_plugins = set()
        for tag in soup.find_all(['link', 'script'], href=True) + soup.find_all('script', src=True):
            url = tag.get('href') or tag.get('src')
            if url:
                match = plugin_pattern.search(url)
                if match: found_plugins.add(match.group(1))
        if found_plugins: results['plugin_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Plugins détectés", "plugins": list(found_plugins)}
        else: results['plugin_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Aucun plugin détecté depuis la page d'accueil."}
    except requests.exceptions.RequestException: results['plugin_enum'] = {"statut": "INFO", "criticite": "INFO", "message": "Erreur réseau lors de l'énumération des plugins."}
    return results

# Constantes pour la détection de domaine parqué
PARKING_KEYWORDS = [
    "domain parked", "domain for sale", "buy this domain", "under construction",
    "domaine à vendre", "domaine en vente", "domaine parké", "en construction"
]
PARKING_NS_KEYWORDS = ["park", "sedo", "bodis", "afternic", "domain.com", "godaddy", "namecheap"]
PARKING_URL_KEYWORDS = ["sedo.com", "dan.com", "bodis.com", "afternic.com"]


def check_domain_parking(hostname, dns_results, whois_info):
    """
    Tente de déterminer si un domaine est "parké" en utilisant une heuristique et un système de score.
    """
    parking_score = 0
    reasons = []

    # 1. Analyse des serveurs de noms (NS)
    ns_servers = dns_results.get('ns', {}).get('valeurs', [])
    if ns_servers and any(park_kw in ns.lower() for ns in ns_servers for park_kw in PARKING_NS_KEYWORDS):
        parking_score += 3
        reasons.append("Les serveurs de noms semblent appartenir à un service de parking.")

    # 2. Analyse des serveurs mail (MX)
    mx_records = dns_results.get('mx', {}).get('valeurs', [])
    if not mx_records:
        parking_score += 2
        reasons.append("Aucun enregistrement MX trouvé, le domaine n'est probablement pas utilisé pour les e-mails.")

    # 3. Analyse du contenu de la page
    try:
        response = requests.get(f"http://{hostname}", timeout=10, allow_redirects=True)
        final_url = response.url.lower()

        # 3a. Vérification de l'URL finale
        if any(url_kw in final_url for url_kw in PARKING_URL_KEYWORDS):
            parking_score += 5
            reasons.append(f"L'URL finale ({response.url}) est un service de parking connu.")

        # 3b. Analyse du contenu HTML
        soup = BeautifulSoup(response.content, 'lxml')
        page_text = (soup.title.string if soup.title else "") + " " + soup.get_text()
        page_text = page_text.lower()

        if any(kw in page_text for kw in PARKING_KEYWORDS):
            parking_score += 5
            reasons.append("Le contenu de la page contient des mots-clés typiques des domaines parkés.")

        # 3c. Contenu minimal
        if len(soup.get_text()) < 200: # Seuil arbitraire pour contenu très court
            parking_score += 1
            reasons.append("Le contenu textuel de la page est très court.")

    except requests.exceptions.RequestException:
        # Si le site n'est pas joignable, cela peut aussi être un signe, mais on ne peut pas être sûr.
        parking_score += 1
        reasons.append("Impossible de se connecter au domaine via HTTP.")

    # 4. Analyse WHOIS
    if whois_info.get('statut') == 'SUCCESS':
        creation_date_str = whois_info.get('creation_date', '').split(',')[0]
        if creation_date_str != 'N/A':
            try:
                creation_date = datetime.fromisoformat(creation_date_str)
                if (datetime.now() - creation_date).days < 90: # Moins de 3 mois
                    parking_score += 1
                    reasons.append("Le domaine a été enregistré récemment.")
            except ValueError:
                pass

    is_parked = parking_score >= 5
    result = {
        "is_parked": is_parked,
        "score": parking_score,
        "reasons": reasons,
        "criticite": "INFO" if not is_parked else "WARNING"
    }
    return result


def _format_whois_value(value):
    """Helper pour formater les valeurs WHOIS qui peuvent être des listes ou des datetimes."""
    if isinstance(value, list):
        # Convertir les datetimes dans la liste en chaînes
        return ", ".join([v.isoformat() if isinstance(v, datetime) else str(v) for v in value])
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value is not None else "N/A"

def check_whois_info(hostname):
    """
    Récupère les informations WHOIS pour un nom de domaine donné.
    """
    try:
        w = whois.whois(hostname)

        # Vérifier si le WHOIS a retourné des données ou un message d'erreur
        if not hasattr(w, 'domain_name') or w.domain_name is None:
            # Souvent un signe que le TLD n'est pas supporté ou que le domaine n'existe pas
            return {
                "statut": "ERROR",
                "message": "Aucune donnée WHOIS trouvée. Le domaine est peut-être invalide ou le TLD non supporté.",
                "criticite": "LOW"
            }

        registrant_address = [
            _format_whois_value(w.get('address')),
            _format_whois_value(w.get('city')),
            _format_whois_value(w.get('state')),
            _format_whois_value(w.get('zipcode')),
            _format_whois_value(w.get('country'))
        ]

        return {
            "statut": "SUCCESS",
            "criticite": "INFO",
            "registrar": _format_whois_value(w.get('registrar')),
            "creation_date": _format_whois_value(w.get('creation_date')),
            "expiration_date": _format_whois_value(w.get('expiration_date')),
            "updated_date": _format_whois_value(w.get('updated_date')),
            "domain_status": _format_whois_value(w.get('status')),
            "name_servers": _format_whois_value(w.get('name_servers')),
            "dnssec": "Activé" if w.get('dnssec') else "Désactivé ou non trouvé",
            "registrant_name": _format_whois_value(w.get('name')),
            "registrant_org": _format_whois_value(w.get('org')),
            "registrant_address": ", ".join(filter(lambda x: x and x != "N/A", registrant_address)) or "N/A",
        }
    except Exception as e:
        return {
            "statut": "ERROR",
            "message": f"Impossible de récupérer les informations WHOIS : {e}",
            "criticite": "LOW"
        }

def generate_csv_report(results, hostname):
    date_str = datetime.now().strftime('%d%m%y'); filename = f"{hostname}_{date_str}.csv"
    header = ['Catégorie', 'Sous-catégorie', 'Statut', 'Criticité', 'Description', 'Vulnérabilités']
    rows = []

    # Cas spécial pour le certificat SSL pour l'inclure toujours dans le CSV
    ssl_cert = results.get('ssl_certificate')
    if ssl_cert:
        jours = ssl_cert.get('jours_restants')
        desc = f"Expire le {ssl_cert.get('date_expiration')}"
        if jours is not None:
            desc += f" (dans {jours} jours)" if jours >= 0 else f" (expiré depuis {-jours} jours)"
        rows.append({
            'Catégorie': 'Certificat SSL',
            'Sous-catégorie': 'Détails du certificat',
            'Statut': ssl_cert.get('statut'),
            'Criticité': ssl_cert.get('criticite'),
            'Description': desc,
            'Vulnérabilités': ''
        })

    # Cas spécial pour les informations WHOIS
    whois_info = results.get('whois_info')
    if whois_info:
        if whois_info.get('statut') == 'SUCCESS':
            for key, value in whois_info.items():
                if key in ['statut', 'criticite']: continue
                rows.append({
                    'Catégorie': 'WHOIS',
                    'Sous-catégorie': key.replace('_', ' ').title(),
                    'Statut': 'INFO',
                    'Criticité': 'INFO',
                    'Description': str(value),
                    'Vulnérabilités': ''
                })
        else:  # Gérer le cas d'erreur
            rows.append({
                'Catégorie': 'WHOIS',
                'Sous-catégorie': 'Erreur de récupération',
                'Statut': whois_info.get('statut'),
                'Criticité': whois_info.get('criticite'),
                'Description': whois_info.get('message'),
                'Vulnérabilités': ''
            })

    parking_info = results.get('domain_parking', {})
    if parking_info.get('is_parked'):
        rows.append({
            'Catégorie': 'Domaine Parké',
            'Sous-catégorie': 'Détection',
            'Statut': 'WARNING',
            'Criticité': parking_info.get('criticite', 'INFO'),
            'Description': f"Le domaine est probablement parké (Score: {parking_info.get('score', 0)}). Raisons: {'; '.join(parking_info.get('reasons', []))}",
            'Vulnérabilités': ''
        })

    def flatten_data(category, sub_category, data):
        if isinstance(data, list):
            for item in data: flatten_data(category, sub_category, item)
        elif isinstance(data, dict):
            if 'statut' in data and data['statut'] in ['ERROR', 'WARNING']:
                vuln_ids = ", ".join([v['id'] for v in data['vulnerabilities']]) if 'vulnerabilities' in data and data['vulnerabilities'] else ""
                rows.append({'Catégorie': category, 'Sous-catégorie': data.get('protocole') or data.get('nom') or data.get('bibliotheque') or sub_category, 'Statut': data.get('statut'), 'Criticité': data.get('criticite'), 'Description': data.get('message') or f"Version: {data.get('version_detectee')} (Dernière: {data.get('derniere_version')})" or "Détail non disponible", 'Vulnérabilités': vuln_ids})
                if sub_category == 'plugin_enum' and data.get('plugins'): rows[-1]['Description'] = f"Plugins détectés: {', '.join(data['plugins'])}"
            if 'en-tetes_securite' in data:
                for k, v in data['en-tetes_securite'].items(): flatten_data(category, k, v)
            if 'wordpress_specifics' in data:
                for k, v in data['wordpress_specifics'].items(): flatten_data(category, k, v)
            if 'secure' in data:
                if not data['secure']['present']: flatten_data(category, f"{data['nom']} - secure", data['secure'])
                if not data['httponly']['present']: flatten_data(category, f"{data['nom']} - httponly", data['httponly'])
                if not data['samesite']['present']: flatten_data(category, f"{data['nom']} - samesite", data['samesite'])

    for key, res in results.items():
        if key in ['hostname', 'score_final', 'note', 'ssl_certificate', 'whois_info']: continue
        flatten_data(key.replace('_', ' ').title(), key, res)
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header); writer.writeheader(); writer.writerows(rows)
        print(f"\n✅ Rapport CSV généré avec succès : {filename}")
    except IOError as e: print(f"\n❌ Erreur lors de l'écriture du rapport CSV : {e}")

def generate_html_report(results, hostname):
    date_str = datetime.now().strftime('%d%m%y'); filename = f"{hostname}_{date_str}.html"
    score = results.get('score_final', 0); grade = results.get('note', 'N/A')
    html_style = "<style>body{font-family:sans-serif;margin:2em}h1,h2,h3{color:#333}.report-card{border:1px solid #ddd;border-radius:5px;margin-bottom:1em;padding:1em}.severity-CRITICAL{background-color:#d32f2f;color:white}.severity-HIGH{background-color:#f44336;color:white}.severity-MEDIUM{background-color:#ff9800}.severity-LOW{background-color:#ffc107}.severity-INFO{background-color:#f0f0f0}.finding{padding:.5em;border-left:5px solid;margin-bottom:.5em}.finding-CRITICAL{border-color:#d32f2f}.finding-HIGH{border-color:#f44336}.finding-MEDIUM{border-color:#ff9800}.finding-LOW{border-color:#ffc107}.finding-INFO{border-color:#ccc}.remediation{font-style:italic;color:#555}</style>"
    html_content = f"<!DOCTYPE html><html><head><title>Rapport de Sécurité - {hostname}</title>{html_style}</head><body><h1>Rapport d'Analyse de Sécurité pour {hostname}</h1><div class='report-card severity-{grade if grade != 'A+' else 'INFO'}'><h2 style='margin-top:0;'>Score de Dangerosité : {score} (Note: {grade})</h2></div>"
    for category, data in results.items():
        if category in ['hostname', 'score_final', 'note']: continue
        html_content += f"<div class='report-card'><h2>{category.replace('_', ' ').title()}</h2>"
        # Cas spécial pour le certificat SSL, qui est un dictionnaire unique et non une liste.
        if category == 'ssl_certificate':
            crit = data.get('criticite', 'INFO')
            html_content += f"<div class='finding finding-{crit}'>"
            html_content += f"<strong>Statut</strong>: {data.get('message', 'N/A')}<br>"
            if data.get('statut') == 'SUCCESS':
                jours_restants = data.get('jours_restants')
                expiration_text = data.get('date_expiration', 'N/A')
                if jours_restants is not None:
                    expiration_text += f" (dans {jours_restants} jours)"
                html_content += f"<strong>Sujet</strong>: {data.get('sujet', 'N/A')}<br>"
                html_content += f"<strong>Émetteur</strong>: {data.get('emetteur', 'N/A')}<br>"
                html_content += f"<strong>Expire le</strong>: {expiration_text}"
            remediation_id = data.get('remediation_id')
            if remediation_id and remediation_id in REMEDIATION_ADVICE:
                html_content += f"<p class='remediation'>Action: {REMEDIATION_ADVICE[remediation_id].get('default', '')}</p>"
            html_content += "</div>"
        elif category == 'whois_info':
            crit = data.get('criticite', 'INFO')
            html_content += f"<div class='finding finding-{crit}'>"
            if data.get('statut') == 'SUCCESS':
                html_content += "<strong>Informations WHOIS récupérées</strong><br>"
                html_content += f"<strong>Registrar:</strong> {data.get('registrar', 'N/A')}<br>"
                html_content += f"<strong>Propriétaire:</strong> {data.get('registrant_name', 'N/A')} ({data.get('registrant_org', 'N/A')})<br>"
                html_content += f"<strong>Adresse:</strong> {data.get('registrant_address', 'N/A')}<br>"
                html_content += f"<strong>Date de création:</strong> {data.get('creation_date', 'N/A')}<br>"
                html_content += f"<strong>Date d'expiration:</strong> {data.get('expiration_date', 'N/A')}<br>"
                html_content += f"<strong>Dernière mise à jour:</strong> {data.get('updated_date', 'N/A')}<br>"
                html_content += f"<strong>Statut:</strong> {data.get('domain_status', 'N/A')}<br>"
                html_content += f"<strong>Serveurs DNS:</strong> {data.get('name_servers', 'N/A')}<br>"
                html_content += f"<strong>DNSSEC:</strong> {data.get('dnssec', 'N/A')}"
            else:
                html_content += f"<strong>Erreur WHOIS:</strong> {data.get('message', 'Erreur inconnue')}"
            html_content += "</div>"
        elif isinstance(data, list):
            for item in data:
                crit = item.get('criticite', 'INFO'); html_content += f"<div class='finding finding-{crit}'>"; html_content += f"<strong>{item.get('protocole') or item.get('nom') or item.get('bibliotheque', 'Élément')}</strong>: {item.get('message', '')}<br>"
                if 'version_detectee' in item: html_content += f"Version détectée: {item['version_detectee']}, dernière version: {item['derniere_version']}<br>"
                if item.get('vulnerabilities'):
                    html_content += "<strong>Vulnérabilités connues:</strong><ul>"
                    for vuln in item['vulnerabilities']: html_content += f"<li>{vuln['id']}: {vuln['summary']}</li>"
                    html_content += "</ul>"
                remediation_id = item.get('remediation_id')
                if remediation_id and remediation_id in REMEDIATION_ADVICE: html_content += f"<p class='remediation'>Action: {REMEDIATION_ADVICE[remediation_id].get('default', '')}</p>"
                html_content += "</div>"
        elif isinstance(data, dict):
             for key, sub_data in data.items():
                 if not isinstance(sub_data, dict) or 'criticite' not in sub_data: continue
                 crit = sub_data.get('criticite', 'INFO'); html_content += f"<div class='finding finding-{crit}'>"
                 html_content += f"<strong>{key.replace('_', ' ').title()}</strong>: {sub_data.get('message') or sub_data.get('valeur') or 'N/A'}<br>"
                 if key == 'plugin_enum' and sub_data.get('plugins'):
                     html_content += "<ul>"
                     for plugin in sub_data['plugins']: html_content += f"<li>{plugin}</li>"
                     html_content += "</ul>"
                 remediation_id = sub_data.get('remediation_id')
                 if remediation_id and remediation_id in REMEDIATION_ADVICE: html_content += f"<p class='remediation'>Action: {REMEDIATION_ADVICE[remediation_id].get('default', '')}</p>"
                 html_content += "</div>"
        html_content += "</div>"

    parking_info = results.get('domain_parking', {})
    if parking_info.get('is_parked'):
        html_content += "<div class='report-card'><h2>Détection de Domaine Parké</h2>"
        html_content += f"<div class='finding finding-WARNING'>"
        html_content += f"<strong>Statut:</strong> Ce domaine est probablement parké (Score: {parking_info.get('score', 0)})<br>"
        html_content += "<strong>Indices:</strong><ul>"
        for reason in parking_info.get('reasons', []):
            html_content += f"<li>{reason}</li>"
        html_content += "</ul></div></div>"

    html_content += "</body></html>"
    try:
        with open(filename, 'w', encoding='utf-8') as f: f.write(html_content)
        print(f"\n✅ Rapport HTML généré avec succès : {filename}")
    except IOError as e: print(f"\n❌ Erreur lors de l'écriture du rapport HTML : {e}")

def calculate_score(results):
    total_score = 0
    def traverse_results(data):
        nonlocal total_score
        if isinstance(data, dict):
            if 'criticite' in data: total_score += SEVERITY_SCORES.get(data['criticite'], 0)
            for key, value in data.items(): traverse_results(value)
        elif isinstance(data, list):
            for item in data: traverse_results(item)
    traverse_results(results)
    if total_score == 0: grade = "A+"
    elif total_score <= 10: grade = "A"
    elif total_score <= 20: grade = "B"
    elif total_score <= 40: grade = "C"
    elif total_score <= 60: grade = "D"
    else: grade = "F"
    return total_score, grade

def print_human_readable_report(results):
    STATUS_ICONS = {"SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️", "INFO": "ℹ️"}; score, grade = calculate_score(results)
    print("\n" + "="*50); print(f" RAPPORT D'ANALYSE DE SÉCURITÉ POUR : {results['hostname']}"); print(f" SCORE DE DANGEROSITÉ : {score} (Note : {grade})"); print("="*50)
    server_type = "default"
    if results.get('security_headers', {}).get('empreinte'):
        for fp in results['security_headers']['empreinte']:
            if fp['header'] == 'server':
                server_val = fp['valeur'].lower()
                if 'nginx' in server_val: server_type = 'nginx'
                elif 'apache' in server_val: server_type = 'apache'
                break
    def crit_str(criticite): return f"[{criticite}]" if criticite != "INFO" else ""
    def print_remediation(data):
        remediation_id = data.get('remediation_id')
        if remediation_id and remediation_id in REMEDIATION_ADVICE:
            advice = REMEDIATION_ADVICE[remediation_id]; advice_text = advice.get(server_type, advice.get('default', ''))
            if advice_text: print(f"    -> Action : {advice_text}")
    print("\n--- Analyse du certificat SSL/TLS ---"); ssl_cert = results.get('ssl_certificate', {}); icon = STATUS_ICONS.get(ssl_cert.get('statut'), '❓'); print(f"  {icon} {crit_str(ssl_cert.get('criticite'))} {ssl_cert.get('message', 'Aucune donnée.')}")
    if ssl_cert.get('statut') == "SUCCESS":
        jours_restants = ssl_cert.get('jours_restants')
        expiration_text = f"    Expire le: {ssl_cert.get('date_expiration')}"
        if jours_restants is not None:
            expiration_text += f" (dans {jours_restants} jours)"
        print(f"    Sujet    : {ssl_cert.get('sujet')}\n    Émetteur : {ssl_cert.get('emetteur')}\n{expiration_text}"); print_remediation(ssl_cert)
    print("\n--- Scan des protocoles SSL/TLS supportés ---")
    for proto in results.get('tls_protocols', []): icon = STATUS_ICONS.get(proto.get('statut'), '❓'); print(f"  {icon} {crit_str(proto.get('criticite'))} {proto.get('protocole', '')} : {proto.get('message', '')}"); print_remediation(proto)
    print("\n--- Analyse de la redirection HTTP vers HTTPS ---"); redirect = results.get('http_redirect', {}); icon = STATUS_ICONS.get(redirect.get('statut'), '❓'); print(f"  {icon} {crit_str(redirect.get('criticite'))} {redirect.get('message', 'Aucune donnée.')}"); print_remediation(redirect)
    print("\n--- Analyse des en-têtes de sécurité HTTP ---"); headers = results.get('security_headers', {})
    if headers.get("statut") == "ERROR": icon = STATUS_ICONS.get(headers.get('statut'), '❓'); print(f"  {icon} {crit_str(headers.get('criticite'))} {headers.get('message')}")
    else:
        print(f"  [Empreinte Technologique]")
        for fp in headers.get('empreinte', []): print(f"    {STATUS_ICONS['INFO']} {crit_str(fp.get('criticite'))} {fp.get('header', '').title()} : {fp.get('valeur')}"); print_remediation(fp)
        print("\n  [En-têtes de sécurité]")
        for name, data in headers.get('en-tetes_securite', {}).items(): icon = STATUS_ICONS.get(data.get('statut'), '❓'); message = data.get('valeur') if data.get('statut') == 'SUCCESS' else data.get('message'); print(f"    {icon} {crit_str(data.get('criticite'))} {name.replace('_', '-').title()} : {message}"); print_remediation(data)
    print("\n--- Analyse de la sécurité des cookies ---"); cookies = results.get('cookie_security', [])
    if not cookies or cookies[0].get('criticite') == "INFO": print(f"  {STATUS_ICONS['INFO']} {cookies[0].get('message') if cookies else 'Aucune information sur les cookies.'}")
    else:
        for cookie in cookies:
            print(f"\n  Analyse du cookie : '{cookie.get('nom')}'")
            for name in ['secure', 'httponly', 'samesite']:
                attr = cookie.get(name, {})
                icon = "✅" if attr.get('present') else "❌"
                print(f"    {icon} {crit_str(attr.get('criticite'))} {name.title()} : {'Présent' if attr.get('present') else 'Manquant'}")
                if not attr.get('present'):
                    print_remediation(attr)
    print("\n--- Analyse des enregistrements DNS ---"); dns_results = results.get('dns_records', {})
    dns_order = [('ns', 'Serveurs de noms (NS)'), ('a', 'Adresses IP (A)'), ('mx', 'Serveurs de messagerie (MX)'), ('dmarc', 'Enregistrement DMARC'), ('spf', 'Enregistrement SPF')]
    for key, title in dns_order:
        data = dns_results.get(key)
        if not data: continue
        print(f"\n  {title} :"); icon = STATUS_ICONS.get(data.get('statut'), '❓')
        if data.get('statut') == 'SUCCESS':
            if 'valeurs' in data:
                for val in data['valeurs']: print(f"    {icon} {val}")
            elif 'valeur' in data: print(f"    {icon} {data['valeur']}")
        else: print(f"    {icon} {crit_str(data.get('criticite'))} {data.get('message', 'Erreur inconnue.')}")
        print_remediation(data)
    print("\n--- Analyse des bibliothèques JavaScript ---"); js_libs = results.get('js_libraries', [])
    if not js_libs: print(f"  {STATUS_ICONS['INFO']} Aucune bibliothèque JS connue n'a été détectée.")
    else:
        for lib in js_libs:
            icon = STATUS_ICONS.get(lib.get('statut'), '❓')
            if 'bibliotheque' in lib:
                message = f"{lib['bibliotheque']} (Version: {lib['version_detectee']})"
                if lib.get('statut') == 'WARNING': message += f" - Obsolète (Dernière version: {lib['derniere_version']})"
                print(f"  {icon} {crit_str(lib.get('criticite'))} {message}")
                if lib.get('vulnerabilities'):
                    print("    Vulnérabilités connues :")
                    for vuln in lib['vulnerabilities']: print(f"      - {vuln['id']}: {vuln['summary']}")
            else: message = lib.get('message', 'Information non disponible.'); print(f"  {icon} {crit_str(lib.get('criticite'))} {message}")
            print_remediation(lib)
    if 'wordpress_specifics' in results:
        print("\n--- Analyse spécifique à WordPress ---"); wp_results = results['wordpress_specifics']
        for key, data in wp_results.items():
            if not data: continue
            icon = STATUS_ICONS.get(data.get('statut'), '❓'); print(f"  {icon} {crit_str(data.get('criticite'))} {data.get('message', '')}")
            if 'plugins' in data:
                for plugin in data['plugins']: print(f"    - {plugin}")
    if 'whois_info' in results:
        print("\n--- Informations WHOIS ---")
        whois_info = results['whois_info']
        icon = STATUS_ICONS.get(whois_info.get('statut'), '❓')
        message = whois_info.get('message', 'Données WHOIS récupérées.')
        print(f"  {icon} {crit_str(whois_info.get('criticite'))} {message}")
        if whois_info.get('statut') == 'SUCCESS':
            print(f"    Registrar            : {whois_info.get('registrar', 'N/A')}")
            print(f"    Nom du propriétaire  : {whois_info.get('registrant_name', 'N/A')}")
            print(f"    Organisation         : {whois_info.get('registrant_org', 'N/A')}")
            print(f"    Adresse              : {whois_info.get('registrant_address', 'N/A')}")
            print(f"    Date de création     : {whois_info.get('creation_date', 'N/A')}")
            print(f"    Date d'expiration    : {whois_info.get('expiration_date', 'N/A')}")
            print(f"    Dernière mise à jour : {whois_info.get('updated_date', 'N/A')}")
            print(f"    Statut du domaine    : {whois_info.get('domain_status', 'N/A')}")
            print(f"    Serveurs DNS         : {whois_info.get('name_servers', 'N/A')}")
            print(f"    DNSSEC               : {whois_info.get('dnssec', 'N/A')}")

    parking_info = results.get('domain_parking', {})
    if parking_info.get('is_parked'):
        print("\n--- Détection de Domaine Parké ---")
        icon = STATUS_ICONS.get('WARNING', '❓')
        print(f"  {icon} [WARNING] Ce domaine semble être parké (score: {parking_info.get('score', 0)}).")
        print("    Indices détectés :")
        for reason in parking_info.get('reasons', []):
            print(f"      - {reason}")

    print("\n" + "="*50); print(" LÉGENDE DE LA NOTE :"); print("  A+ : Excellent (0 points)"); print("  A  : Bon (1-10 points)"); print("  B  : Moyen (11-20 points)"); print("  C  : Médiocre (21-40 points)"); print("  D  : Mauvais (41-60 points)"); print("  F  : Critique (>60 points)"); print("="*50)

def generate_json_report(results, hostname):
    date_str = datetime.now().strftime('%d%m%y'); filename = f"{hostname}_{date_str}.json"
    try:
        with open(filename, 'w', encoding='utf-8') as f: json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"\n✅ Rapport JSON généré avec succès : {filename}")
    except IOError as e: print(f"\n❌ Erreur lors de l'écriture du rapport JSON : {e}")

def main():
    parser = argparse.ArgumentParser(description="Analyseur de sécurité de site web.")
    parser.add_argument("url", help="L'URL du site web à analyser (ex: google.com).")
    parser.add_argument("--formats", type=str, default="", help="Génère des rapports dans les formats spécifiés, séparés par des virgules (ex: json,html,csv).")
    args = parser.parse_args()
    hostname = get_hostname(args.url)
    if not check_host_exists(hostname): print(f"Erreur : L'hôte '{hostname}' est introuvable. Veuillez vérifier le nom de domaine."); sys.exit(1)
    all_results = {'hostname': hostname}
    print(f"Analyse de {hostname} en cours...")
    all_results['ssl_certificate'] = check_ssl_certificate(hostname)
    all_results['tls_protocols'] = scan_tls_protocols(hostname)
    all_results['http_redirect'] = check_http_to_https_redirect(hostname)
    all_results['security_headers'] = check_security_headers(hostname)
    all_results['cookie_security'] = check_cookie_security(hostname)
    all_results['cms_footprint_meta'] = check_cms_footprint(hostname)
    all_results['cms_footprint_paths'] = check_cms_paths(hostname)
    is_wordpress = any(path.get('cms') == 'WordPress' for path in all_results.get('cms_footprint_paths', []))
    if is_wordpress: all_results['wordpress_specifics'] = check_wordpress_specifics(hostname)
    all_results['dns_records'] = check_dns_records(hostname)
    all_results['js_libraries'] = check_js_libraries(hostname)
    all_results['whois_info'] = check_whois_info(hostname)
    all_results['domain_parking'] = check_domain_parking(hostname, all_results.get('dns_records', {}), all_results.get('whois_info', {}))
    score, grade = calculate_score(all_results); all_results['score_final'] = score; all_results['note'] = grade
    print_human_readable_report(all_results)
    formats = [f.strip() for f in args.formats.lower().split(',') if f.strip()]
    if 'json' in formats: generate_json_report(all_results, hostname)
    if 'csv' in formats: generate_csv_report(all_results, hostname)
    if 'html' in formats: generate_html_report(all_results, hostname)

if __name__ == "__main__":
    main()
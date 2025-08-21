# Web Security Checker

Un outil simple en ligne de commande pour effectuer des vérifications de sécurité de base sur un site web.

## Description

Ce script Python analyse une URL donnée pour évaluer certains aspects de sa configuration de sécurité. C'est un outil de base destiné à fournir un aperçu rapide de la posture de sécurité d'un serveur web.

## Fonctionnalités

Le script effectue actuellement les vérifications suivantes :

1.  **Vérification de la chaîne de confiance et de l'expiration du certificat SSL/TLS**
    *   C'est le point de départ. Si le certificat est invalide ou expiré, tout le reste est compromis. Un certificat non valide empêche la connexion sécurisée, ce qui expose les données des utilisateurs. Le vérifier en premier garantit que la communication entre le client et le serveur est sécurisée.

2.  **Analyse des en-têtes de sécurité HTTP (Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options)**
    *   Ces en-têtes sont des mesures de sécurité défensives très efficaces et faciles à implémenter.
    *   **Strict-Transport-Security (HSTS)** force le navigateur à n'utiliser que des connexions HTTPS pour ce site, ce qui réduit le risque de man-in-the-middle.
    *   **X-Frame-Options** et **Content-Security-Policy (CSP)** protègent contre le clickjacking et l'injection de contenu malveillant en contrôlant comment le site peut être intégré dans d'autres pages.
    *   **X-Content-Type-Options** empêche les navigateurs d'interpréter le code de manière incorrecte, ce qui protège contre certaines attaques.

3.  **Redirections HTTP vers HTTPS**
    *   Une fois que vous savez que le certificat est valide, assurez-vous que toutes les requêtes non chiffrées sont automatiquement redirigées vers la version sécurisée du site. Si ce n'est pas le cas, un attaquant peut intercepter les premières requêtes des utilisateurs sur une connexion non chiffrée.

4.  **Scan des versions de protocoles SSL/TLS supportées**
    *   Le script scanne activement le serveur pour déterminer quelles versions de protocoles (de SSL 2.0 à TLS 1.3) sont activées. Il signale les protocoles obsolètes et vulnérables (SSLv2, SSLv3, TLS 1.0, TLS 1.1) comme étant non conformes, car leur utilisation expose à des risques de sécurité connus.

5.  **Vérification des enregistrements DNS de sécurité (A, MX, NS, DMARC, SPF)**
    *   Le script vérifie les enregistrements DNS fondamentaux (A, MX, NS) et ceux liés à la sécurité des e-mails (DMARC, SPF). Il fournit des conseils de correction si les enregistrements DMARC ou SPF sont manquants.

6.  **Analyse des attributs de cookies (HttpOnly, Secure, SameSite)**
    *   Des cookies mal configurés peuvent être volés, ce qui expose les sessions des utilisateurs. S'assurer qu'ils sont marqués `HttpOnly` (pour empêcher l'accès via JavaScript), `Secure` (pour forcer le chiffrement) et `SameSite` (pour prévenir les attaques CSRF) protège contre de nombreuses menaces.

7.  **Récupération des informations WHOIS**
    *   Le script tente de récupérer les informations publiques d'enregistrement du domaine (WHOIS), telles que le registrar, les dates de création et d'expiration, et le statut du domaine. Ces informations peuvent être utiles pour le suivi administratif (note : la disponibilité de ces données dépend du registrar et des politiques de confidentialité).

## Installation

1.  Assurez-vous d'avoir Python 3 installé sur votre système.
2.  Clonez ce dépôt ou téléchargez les fichiers `security_checker.py` et `requirements.txt`.
3.  Installez les dépendances nécessaires en utilisant pip :

    ```bash
    pip install -r requirements.txt
    ```

## Utilisation

Pour analyser un site web, exécutez le script depuis votre terminal en lui passant l'URL ou le nom de domaine comme argument.

```bash
python3 security_checker.py google.com
```

### Exemple de sortie

```
Analyse de l'hôte : google.com

--- Analyse du certificat SSL/TLS ---
  Sujet du certificat : *.google.com
  Émetteur : WR2
  Date d'expiration : 2025-09-29
  Le certificat est valide.

--- Analyse des en-têtes de sécurité HTTP ---
  Analyse des en-têtes pour l'URL finale : https://www.google.com/

  En-têtes de sécurité trouvés :
    - Content-Security-Policy-Report-Only: Trouvé
    - X-Frame-Options: Trouvé
```

---

## Outil de Consolidation (`consolidator.py`)

En plus du scanner principal, ce projet inclut `consolidator.py`, un outil puissant pour analyser les résultats de multiples scans sur la durée. Il vous permet de suivre l'évolution de la posture de sécurité de vos sites web.

### Mise en Place

1.  **Créez un fichier `targets.txt`** à la racine du projet. Listez-y les domaines que vous souhaitez surveiller, un par ligne.
    ```
    google.com
    github.com
    votresite.com
    ```

2.  **Créez un répertoire `scans/`** à la racine du projet. C'est ici que tous les rapports de scan JSON seront stockés.
    ```bash
    mkdir scans
    ```

### Génération des Rapports

Pour que le consolidateur fonctionne, il a besoin de données. Exécutez `security_checker.py` en utilisant l'argument `--formats json` pour générer un rapport JSON. Le script nommera automatiquement le fichier (`<domaine>_<date>.json`) et le placera dans le répertoire courant.

```bash
# Lancez le scan et générez le rapport JSON
python3 security_checker.py votresite.com --formats json

# Déplacez le rapport dans le répertoire des scans
mv votresite.com_180825.json scans/
```
Répétez cette opération régulièrement pour construire un historique des scans.

### Utilisation du Consolidateur

Voici les commandes disponibles pour l'outil de consolidation :

#### 1. Voir l'état des scans (`--status`)
Affiche la liste des cibles de votre fichier `targets.txt` et indique si un scan a été trouvé pour chacune.
```bash
python3 consolidator.py --status
```
*Exemple de sortie :*
```
📊 État des scans cibles :
  [✅] google.com
  [❌] github.com

Total: 1 / 2 cibles scannées.
```

#### 2. Lister les scans pour un domaine (`--list-scans`)
Affiche tous les rapports de scan disponibles pour un domaine spécifique, triés par date.
```bash
python3 consolidator.py --list-scans google.com
```
*Exemple de sortie :*
```
🔎 Scans disponibles pour 'google.com':
  - Date: 2025-08-18, Score: 49, Note: D
  - Date: 2025-08-17, Score: 53, Note: D
```

#### 3. Comparer deux scans (`--compare`)
Analyse l'évolution de la sécurité d'un site entre deux dates.
```bash
python3 consolidator.py --compare google.com 2025-08-17 2025-08-18
```
*Exemple de sortie :*
```
🔄 Comparaison des scans pour 'google.com' entre 2025-08-17 et 2025-08-18

Score: 53 (à 2025-08-17) -> 49 (à 2025-08-18)
  -> ✅ Amélioration du score de 4 points.

--- Changements des vulnérabilités ---

[✅ VULNÉRABILITÉS CORRIGÉES]
  - security_headers.en-tetes_securite.x-frame-options.XFO_MISSING

[⚠️ 6 VULNÉRABILITÉS PERSISTANTES]
```

#### 4. Identifier les scans les plus anciens (`--oldest`)
Aide à prioriser les prochains scans en montrant les cibles qui n'ont pas été analysées depuis le plus longtemps.
```bash
python3 consolidator.py --oldest
```
*Exemple de sortie :*
```
🕒 Scans les plus anciens (par cible) :
  - github.com                Dernier scan: JAMAIS (Priorité haute)
  - google.com                Dernier scan: 2025-08-18
```

#### 5. Trouver les "Quick Wins" (`--quick-wins`)
Liste les vulnérabilités faciles à corriger (comme les en-têtes de sécurité manquants) pour un domaine spécifique ou pour tous les domaines scannés.
```bash
# Pour un domaine spécifique
python3 consolidator.py --quick-wins google.com
```

#### 6. Générer un rapport de synthèse HTML (`--summary-html`)
Crée un fichier `summary_report.html` qui affiche un tableau de bord de l'état de sécurité de toutes les cibles. Ce rapport inclut des indicateurs de tendance, des métriques clés et des colonnes triables.
```bash
python3 consolidator.py --summary-html
```

#### 7. Lister les certificats qui expirent (`--list-expiring-certs`)
Affiche la liste des certificats SSL/TLS qui expireront dans un nombre de jours donné (30 par défaut).
```bash
# Vérifie les certificats expirant dans les 30 prochains jours
python3 consolidator.py --list-expiring-certs

# Vérifie les certificats expirant dans les 90 prochains jours
python3 consolidator.py --list-expiring-certs 90
```

#### 8. Générer un graphique d'évolution (`--graph`)
Crée une image (`<domaine>_evolution.png`) montrant l'évolution du score de sécurité pour un domaine spécifique dans le temps.
```bash
python3 consolidator.py --graph google.com
```

#### 9. Rapport d'actions par vulnérabilité (`--report`)
Liste tous les domaines affectés par un ou plusieurs types de vulnérabilités, pour faciliter les campagnes de remédiation.
```bash
# Lister tous les sites sans HSTS
python3 consolidator.py --report hsts

# Lister tous les sites avec des problèmes de DMARC ou de SPF
python3 consolidator.py --report dmarc spf
```

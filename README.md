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

5.  **Vérification des enregistrements DMARC et SPF**
    *   Ces enregistrements DNS protègent le domaine contre l'usurpation d'e-mail (spoofing). SPF spécifie les serveurs autorisés à envoyer des e-mails, et DMARC définit la politique à appliquer en cas d'échec de ces vérifications.

6.  **Analyse des attributs de cookies (HttpOnly, Secure, SameSite)**
    *   Des cookies mal configurés peuvent être volés, ce qui expose les sessions des utilisateurs. S'assurer qu'ils sont marqués `HttpOnly` (pour empêcher l'accès via JavaScript), `Secure` (pour forcer le chiffrement) et `SameSite` (pour prévenir les attaques CSRF) protège contre de nombreuses menaces.

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

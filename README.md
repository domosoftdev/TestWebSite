# Web Security Checker

Un outil simple en ligne de commande pour effectuer des vérifications de sécurité de base sur un site web.

## Description

Ce script Python analyse une URL donnée pour évaluer certains aspects de sa configuration de sécurité. C'est un outil de base destiné à fournir un aperçu rapide de la posture de sécurité d'un serveur web.

## Fonctionnalités

Le script effectue actuellement les vérifications suivantes :

1.  **Analyse du Certificat SSL/TLS**
    *   Vérifie le **sujet** du certificat (le nom commun).
    *   Vérifie l'**émetteur** du certificat.
    *   Vérifie la **date d'expiration** et signale si le certificat est expiré.

2.  **Analyse des En-têtes de Sécurité HTTP**
    *   Détecte la présence des en-têtes de sécurité recommandés suivants :
        *   `Strict-Transport-Security`
        *   `Content-Security-Policy`
        *   `Content-Security-Policy-Report-Only`
        *   `X-Content-Type-Options`
        *   `X-Frame-Options`
        *   `Referrer-Policy`
        *   `Permissions-Policy`

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
Exemple de sortie
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
---
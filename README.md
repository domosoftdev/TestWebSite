# Web Security Checker

Un outil simple en ligne de commande pour effectuer des vérifications de sécurité de base sur un site web.

## Description

Ce script Python analyse une URL donnée pour évaluer certains aspects de sa configuration de sécurité. C'est un outil de base destiné à fournir un aperçu rapide de la posture de sécurité d'un serveur web.

## Fonctionnalités

Le script effectue les vérifications suivantes :

1.  **Analyse SSL/TLS** : Vérification de la validité du certificat et scan des protocoles supportés (de SSLv2 à TLS 1.3).
2.  **Analyse des En-têtes HTTP** : Recherche des en-têtes de sécurité fondamentaux (HSTS, X-Frame-Options, CSP, etc.).
3.  **Analyse de la Redirection** : S'assure que le site redirige bien de HTTP vers HTTPS.
4.  **Sécurité des Cookies** : Vérifie la présence des attributs `Secure`, `HttpOnly` et `SameSite`.
5.  **Sécurité DNS** : Contrôle la présence et la configuration des enregistrements `A`, `MX`, `NS`, `DMARC` et `SPF`.
6.  **Empreinte Technologique (Footprinting)** :
    *   Détecte les technologies du serveur web (ex: `nginx`, `Apache`) via les en-têtes HTTP.
    *   Identifie les CMS (ex: `WordPress`, `Joomla`) en analysant les balises `<meta>` et en testant des chemins connus (`/wp-admin`, etc.).
7.  **Rapports Flexibles** :
    *   Affiche un rapport clair et lisible directement dans la console.
    *   Génère un rapport détaillé au format **JSON** pour une intégration facile avec d'autres outils.

## Installation

1.  Assurez-vous d'avoir Python 3 et pip installés.
2.  Clonez ce dépôt ou téléchargez les fichiers.
3.  Installez les dépendances :
    ```bash
    pip install -r requirements.txt
    ```

## Utilisation

### Analyse de base

Pour lancer une analyse et afficher les résultats dans la console :
```bash
python3 security_checker.py exemple.com
```

### Génération d'un rapport JSON

Pour générer un rapport JSON en plus de l'affichage console, utilisez l'argument `--rapport`.

**1. Avec un nom de fichier par défaut :**
Le nom du fichier sera généré automatiquement (ex: `exemple.com_100825.json`).
```bash
python3 security_checker.py exemple.com --rapport
```

**2. Avec un nom de fichier spécifique :**
```bash
python3 security_checker.py exemple.com --rapport mon_rapport.json
```

### Exemple de sortie

La nouvelle sortie console est améliorée pour une meilleure lisibilité :
```
 Hôte analysé : google.com
========================================

--- Analyse du certificat SSL/TLS ---
  ✅ Le certificat est valide.
    Sujet    : *.google.com
    Émetteur : WR2
    Expire le: 2025-09-29

--- Scan des protocoles SSL/TLS supportés ---
  ✅ SSL 2.0 : Non supporté (CONFORME)
  ❌ TLS 1.0 : Supporté (NON CONFORME - Vulnérable)
  ✅ TLS 1.3 : Supporté (CONFORME)

--- Analyse de la redirection HTTP vers HTTPS ---
  ❌ Le site redirige, mais pas directement vers HTTPS (vers: http://www.google.com/).

--- Analyse des en-têtes de sécurité HTTP ---
  URL finale analysée : https://www.google.com/

  [Empreinte Technologique]
    ℹ️ Serveur Web : gws

  [En-têtes de sécurité]
    ❌ Hsts : En-tête manquant.
    ✅ X-Frame-Options : SAMEORIGIN

--- Analyse d'empreinte CMS ---
  ℹ️ [Meta Generator] Aucune balise meta 'generator' trouvée.
  ℹ️ [Chemins Connus] Aucun chemin spécifique à un CMS commun n'a été trouvé.
```

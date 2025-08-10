# Web Security Checker

Un outil simple en ligne de commande pour effectuer des vérifications de sécurité de base sur un site web.

## Description

Ce script Python analyse une URL donnée pour évaluer certains aspects de sa configuration de sécurité. C'est un outil de base destiné à fournir un aperçu rapide de la posture de sécurité d'un serveur web.

## Fonctionnalités

Le script effectue actuellement les vérifications suivantes :

1.  **Vérification de la chaîne de confiance et de l'expiration du certificat SSL/TLS**
2.  **Analyse des en-têtes de sécurité HTTP (HSTS, X-Frame-Options, etc.)**
3.  **Redirections HTTP vers HTTPS**
4.  **Scan des versions de protocoles SSL/TLS supportées**
5.  **Vérification des enregistrements DNS de sécurité (DMARC, SPF)**
6.  **Analyse des attributs de sécurité des cookies**
7.  **Identification du bureau d'enregistrement (Registrar)**

## Installation

1.  Assurez-vous d'avoir Python 3 installé sur votre système.
2.  Clonez ce dépôt ou téléchargez les fichiers.
3.  Installez les dépendances :

    ```bash
    pip install -r requirements.txt
    ```

## Utilisation

Pour analyser un site web, exécutez le script depuis votre terminal :

```bash
python3 security_checker.py google.com
```

### Générer un rapport

Vous pouvez sauvegarder la sortie de l'analyse dans un fichier en utilisant `--rapport`.

#### 1. Rapport au format Texte

C'est le format par défaut.

- **Nom de fichier personnalisé :**
  ```bash
  python3 security_checker.py google.com --rapport rapport_google.txt
  ```

- **Nom de fichier automatique :**
  ```bash
  python3 security_checker.py google.com --rapport
  ```
  (créera `google.com_jjmmaa.txt`)

#### 2. Rapport au format JSON

Utilisez l'option `--format json` pour un rapport structuré, idéal pour l'automatisation.

- **Nom de fichier personnalisé :**
  ```bash
  python3 security_checker.py google.com --rapport rapport.json --format json
  ```

- **Nom de fichier automatique :**
  ```bash
  python3 security_checker.py google.com --rapport --format json
  ```
  (créera `google.com_jjmmaa.json`)

### Exemple de sortie Console

```
Analyse de : google.com

--- Analyse du certificat SSL/TLS ---
  Sujet du certificat : *.google.com
  Émetteur : GTS CA 1P5
...
```

# Documentation de l'Outil : Web Security Checker

Ce document présente l'outil d'analyse de sécurité "Web Security Checker", son utilité, son fonctionnement et son mode d'emploi. Il est divisé en deux sections :
1.  **Présentation pour le Management** : Une vue d'ensemble non technique.
2.  **Guide pour l'Équipe Technique** : Des instructions détaillées pour l'installation, l'utilisation et l'interprétation des résultats.

---

## 1. Présentation pour le Management

### 1.1. Quel est l'objectif de cet outil ?

Le **Web Security Checker** est un outil en ligne de commande conçu pour réaliser un audit de premier niveau de la configuration de sécurité d'un site web. Son but est de fournir rapidement un aperçu clair et exploitable de la posture de sécurité d'une application web en analysant des points de contrôle critiques, sans nécessiter d'accès internes.

Il répond à la question : "Nos sites web respectent-ils les bonnes pratiques de sécurité fondamentales ?"

### 1.2. Quelle est la valeur ajoutée pour l'entreprise ?

*   **Gestion Proactive des Risques** : L'outil permet d'identifier et de corriger des vulnérabilités de configuration courantes avant qu'elles ne soient exploitées par des attaquants.
*   **Aide à la Conformité** : Il vérifie la mise en œuvre de standards de sécurité recommandés (chiffrement, en-têtes de sécurité), ce qui peut être un atout pour des audits de conformité (ex: RGPD, ISO 27001).
*   **Gain de Temps** : Il automatise des vérifications qui seraient autrement manuelles et chronophages, permettant aux équipes de se concentrer sur des problématiques de sécurité plus complexes.
*   **Indicateur de Santé** : Utilisé régulièrement, il sert d'indicateur de la "santé sécurité" de notre parc web, en signalant toute régression ou oubli lors de mises en production.

### 1.3. Quelles sont les fonctionnalités clés ?

L'outil évalue un site web sur plusieurs axes majeurs :

1.  **Validité du Chiffrement (Certificat SSL/TLS)** : S'assure que la communication entre le client et le site est sécurisée et que le certificat est valide et non expiré.
2.  **Robustesse du Chiffrement (Protocoles SSL/TLS)** : Vérifie que le serveur n'utilise pas de protocoles de chiffrement anciens et vulnérables (ex: SSLv3, TLS 1.0).
3.  **Protection contre le Détournement de Contenu (Clickjacking)** : Contrôle la présence d'en-têtes de sécurité (`X-Frame-Options`, `Content-Security-Policy`) qui empêchent un site malveillant d'intégrer et de détourner notre site.
4.  **Sécurité des Sessions Utilisateurs (Cookies)** : Analyse si les cookies sont correctement protégés pour ne pas être volés ou manipulés.
5.  **Protection contre l'Usurpation d'Email (DMARC/SPF)** : Vérifie que des enregistrements DNS sont en place pour empêcher des attaquants d'envoyer des emails frauduleux en notre nom.
6.  **Forçage de la Connexion Sécurisée** : S'assure que les utilisateurs sont automatiquement redirigés vers la version sécurisée (HTTPS) du site.

---

## 2. Guide pour l'Équipe Technique (Exploitation)

### 2.1. Description Technique

Le "Web Security Checker" est un script Python 3 autonome qui ne requiert aucune installation complexe. Il prend un nom de domaine en argument et exécute une série de tests à distance en se comportant comme un client web standard.

Il utilise les bibliothèques suivantes :
*   `requests` : Pour les requêtes HTTP et l'analyse des en-têtes.
*   `sslyze` : Pour l'analyse détaillée des protocoles SSL/TLS.
*   `dnspython` : Pour les requêtes DNS (MX, DMARC, SPF).

### 2.2. Prérequis et Installation

1.  **Python 3** : Assurez-vous que Python 3 et `pip` sont installés sur le poste depuis lequel vous lancez le script.
2.  **Dépendances** : Installez les bibliothèques nécessaires via le fichier `requirements.txt`.

    ```bash
    # Clonez le projet ou copiez les fichiers security_checker.py et requirements.txt
    # dans un répertoire dédié.
    pip install -r requirements.txt
    ```

### 2.3. Utilisation

Le script se lance depuis un terminal. L'unique argument requis est le nom de domaine à analyser.

**Syntaxe :**
```bash
python3 security_checker.py <nom_de_domaine>
```

**Exemple :**
```bash
python3 security_checker.py google.com
```

Le script affichera les résultats directement dans la console.

### 2.4. Description des Vérifications Techniques

*   **Analyse du certificat SSL/TLS** :
    *   Se connecte au port 443 pour récupérer le certificat.
    *   Vérifie la chaîne de confiance, le nom commun (`commonName`), l'émetteur et la date d'expiration.
    *   En cas d'échec de la vérification, il tente une connexion non sécurisée pour récupérer les détails du certificat (utile pour les certificats auto-signés).

*   **Scan des protocoles SSL/TLS** :
    *   Utilise `sslyze` pour scanner activement les protocoles supportés par le serveur (de SSLv2 à TLS 1.3).
    *   Signale comme `NON CONFORME` l'utilisation de SSLv2, SSLv3, TLS 1.0 et TLS 1.1.

*   **Analyse de la redirection HTTP vers HTTPS** :
    *   Effectue une requête `GET` sur `http://<domaine>` sans suivre les redirections (`allow_redirects=False`).
    *   Vérifie si la réponse est un code de redirection (3xx) et si l'en-tête `Location` pointe vers une URL en `https://`.

*   **Analyse des en-têtes de sécurité HTTP** :
    *   Effectue une requête `GET` sur `https://<domaine>`.
    *   Vérifie la présence et la bonne configuration des en-têtes suivants :
        *   `Strict-Transport-Security` (HSTS) : Cherche une directive `max-age` suffisamment longue.
        *   `X-Frame-Options` : Valide la présence de `DENY` ou `SAMEORIGIN`.
        *   `X-Content-Type-Options` : Valide la présence de `nosniff`.
        *   `Content-Security-Policy` (CSP) : Vérifie sa présence (recommandé).

*   **Analyse de la sécurité des cookies** :
    *   Récupère les cookies définis sur la page d'accueil via l'en-tête `Set-Cookie`.
    *   Pour chaque cookie, vérifie la présence des attributs :
        *   `Secure` : Le cookie ne doit être transmis qu'en HTTPS.
        *   `HttpOnly` : Le cookie ne doit pas être accessible via JavaScript.
        *   `SameSite` : Protection contre les attaques CSRF.

*   **Analyse des enregistrements DNS de sécurité** :
    *   `NS`, `A`, `MX` : Vérifie la présence de ces enregistrements DNS de base.
    *   `DMARC` : Fait une requête TXT sur `_dmarc.<domaine>`.
    *   `SPF` : Cherche un enregistrement TXT commençant par `v=spf1` sur le domaine.

### 2.5. Interprétation des Résultats

*   `✅ SUCCÈS` : La configuration est conforme aux bonnes pratiques.
*   `❌ ERREUR` : Un problème critique a été détecté et nécessite une correction. Le script fournit souvent des pistes de remédiation.
*   `⚠️ AVERTISSEMENT` : Une configuration pourrait être améliorée ou présente un risque modéré.
*   `ℹ️ INFO` : Information contextuelle utile pour l'analyse.

En cas d'erreur de connexion (`timeout`, `gaierror`), vérifiez que le nom d'hôte est correct et qu'aucun pare-feu ne bloque la connexion sortante depuis votre poste vers les ports 80/443 du serveur cible.

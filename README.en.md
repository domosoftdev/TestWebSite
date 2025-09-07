[Lire en français](README.md)

# Web Security Checker

A simple command-line tool to perform basic security checks on a website.

## Description

This Python script analyzes a given URL to assess certain aspects of its security configuration. It is a basic tool intended to provide a quick overview of a web server's security posture.

## Features

The script currently performs the following checks:

1.  **SSL/TLS Certificate Chain of Trust and Expiration Check**
    *   This is the starting point. If the certificate is invalid or expired, everything else is compromised. An invalid certificate prevents a secure connection, exposing user data. Checking this first ensures that communication between the client and server is secure.

2.  **Analysis of HTTP Security Headers (Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options)**
    *   These headers are highly effective and easy-to-implement defensive security measures.
    *   **Strict-Transport-Security (HSTS)** forces the browser to use only HTTPS connections for this site, reducing the risk of man-in-the-middle attacks.
    *   **X-Frame-Options** and **Content-Security-Policy (CSP)** protect against clickjacking and malicious content injection by controlling how the site can be embedded in other pages.
    *   **X-Content-Type-Options** prevents browsers from misinterpreting code, which protects against certain attacks.

3.  **HTTP to HTTPS Redirections**
    *   Once you know the certificate is valid, ensure that all unencrypted requests are automatically redirected to the secure version of the site. If not, an attacker can intercept users' initial requests over an unencrypted connection.

4.  **Scanning of Supported SSL/TLS Protocol Versions**
    *   The script actively scans the server to determine which protocol versions (from SSL 2.0 to TLS 1.3) are enabled. It flags obsolete and vulnerable protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) as non-compliant, as their use exposes known security risks.

5.  **Verification of Security-Related DNS Records (A, MX, NS, DMARC, SPF)**
    *   The script checks fundamental DNS records (A, MX, NS) and those related to email security (DMARC, SPF). It provides correction advice if DMARC or SPF records are missing.

6.  **Analysis of Cookie Attributes (HttpOnly, Secure, SameSite)**
    *   Poorly configured cookies can be stolen, exposing user sessions. Ensuring they are marked `HttpOnly` (to prevent access via JavaScript), `Secure` (to force encryption), and `SameSite` (to prevent CSRF attacks) protects against many threats.

7.  **Retrieval of WHOIS Information**
    *   The script attempts to retrieve public domain registration information (WHOIS), such as the registrar, creation and expiration dates, and domain status. This information can be useful for administrative tracking (note: the availability of this data depends on the registrar and privacy policies).

## Installation

1.  Make sure you have Python 3 installed on your system.
2.  Clone this repository or download the `security_checker.py` and `requirements.txt` files.
3.  Install the necessary dependencies using pip:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To analyze a website, run the script from your terminal, passing the URL or domain name as an argument.

```bash
python3 security_checker.py google.com
```

### Example Output

```
Analyzing host: google.com

--- SSL/TLS Certificate Analysis ---
  Certificate Subject: *.google.com
  Issuer: WR2
  Expiration Date: 2025-09-29
  The certificate is valid.

--- HTTP Security Headers Analysis ---
  Analyzing headers for the final URL: https://www.google.com/

  Security headers found:
    - Content-Security-Policy-Report-Only: Found
    - X-Frame-Options: Found
```

---

## Parking Score Tool (`parking_scorer.py`)

This project also includes a dedicated tool for calculating the "parking score" of a domain name. This score, on a scale of 0 to 100, evaluates the probability that a domain is "parked" (i.e., registered but not used for an active website, often displaying ads or a "for sale" page).

This score is automatically calculated and included in the main report of `security_checker.py`, but the `parking_scorer.py` script can also be used independently for a quick and targeted analysis.

### Standalone Usage

To get only the parking score of a domain:

```bash
python3 parking_scorer.py example.com
```

### Example Output

```
Calculating parking score for example.com...
Parking score for example.com: 85/100
```

---

## Consolidator Tool (`consolidator.py`)

In addition to the main scanner, this project includes `consolidator.py`, a powerful tool for analyzing the results of multiple scans over time. It allows you to track the evolution of your websites' security posture.

### Setup

1.  **Create a `targets.txt` file** in the project root. List the domains you want to monitor, one per line.
    ```
    google.com
    github.com
    yoursite.com
    ```

2.  **Create a `scans/` directory** in the project root. This is where all JSON scan reports will be stored.
    ```bash
    mkdir scans
    ```

### Generating Reports

For the consolidator to work, it needs data. Run `security_checker.py` using the `--formats json` argument to generate a JSON report. The script will automatically name the file (`<domain>_<date>.json`) and place it in the current directory.

```bash
# Run the scan and generate the JSON report
python3 security_checker.py yoursite.com --formats json

# Move the report to the scans directory
mv yoursite.com_180825.json scans/
```
Repeat this operation regularly to build a history of scans.

### Using the Consolidator

Here are the available commands for the consolidator tool:

#### 1. View Scan Status (`--status`)
Displays the list of targets from your `targets.txt` file and indicates whether a scan has been found for each.
```bash
python3 consolidator.py --status
```
*Example Output:*
```
📊 Target scan status:
  [✅] google.com
  [❌] github.com

Total: 1 / 2 targets scanned.
```

#### 2. List Scans for a Domain (`--list-scans`)
Displays all available scan reports for a specific domain, sorted by date.
```bash
python3 consolidator.py --list-scans google.com
```
*Example Output:*
```
🔎 Available scans for 'google.com':
  - Date: 2025-08-18, Score: 49, Grade: D
  - Date: 2025-08-17, Score: 53, Grade: D
```

#### 3. Compare Two Scans (`--compare`)
Analyzes the security evolution of a site between two dates.
```bash
python3 consolidator.py --compare google.com 2025-08-17 2025-08-18
```
*Example Output:*
```
🔄 Comparing scans for 'google.com' between 2025-08-17 and 2025-08-18

Score: 53 (on 2025-08-17) -> 49 (on 2025-08-18)
  -> ✅ Score improvement of 4 points.

--- Vulnerability Changes ---

[✅ FIXED VULNERABILITIES]
  - security_headers.security_headers.x-frame-options.XFO_MISSING

[⚠️ 6 PERSISTENT VULNERABILITIES]
```

#### 4. Identify the Oldest Scans (`--oldest`)
Helps prioritize the next scans by showing which targets have not been analyzed for the longest time.
```bash
python3 consolidator.py --oldest
```
*Example Output:*
```
🕒 Oldest scans (by target):
  - github.com                Last scan: NEVER (High priority)
  - google.com                Last scan: 2025-08-18
```

#### 5. Find "Quick Wins" (`--quick-wins`)
Lists easy-to-fix vulnerabilities (like missing security headers) for a specific domain or for all scanned domains.
```bash
# For a specific domain
python3 consolidator.py --quick-wins google.com
```

#### 6. Generate an HTML Summary Report (`--summary-html`)
Creates a `summary_report.html` file that displays a dashboard of the security status of all targets. This report includes trend indicators, key metrics, and sortable columns.
```bash
python3 consolidator.py --summary-html
```

#### 7. List Expiring Certificates (`--list-expiring-certs`)
Displays a list of SSL/TLS certificates that will expire within a given number of days (default is 30).
```bash
# Check for certificates expiring in the next 30 days
python3 consolidator.py --list-expiring-certs

# Check for certificates expiring in the next 90 days
python3 consolidator.py --list-expiring-certs 90
```

#### 8. Generate an Evolution Graph (`--graph`)
Creates an image (`<domain>_evolution.png`) showing the evolution of the security score for a specific domain over time.
```bash
python3 consolidator.py --graph google.com
```

#### 9. Action Report by Vulnerability (`--report`)
Lists all domains affected by one or more types of vulnerabilities to facilitate remediation campaigns.
```bash
# List all sites without HSTS
python3 consolidator.py --report hsts

# List all sites with DMARC or SPF issues
python3 consolidator.py --report dmarc spf
```

================================================================================
  __     __          _             
  \ \   / /__  _ __ | |_ _____  __ 
   \ \ / / _ \| '__|| __/ _ \ \/ /  [ ADVANCED RECON EDITION ]
    \ V / (_) | |   | ||  __/>  <   [ VERSION 1.0.0 ]
     \_/ \___/|_|    \__\___/_/\_\ 
                                     
      >> HIGH-PERFORMANCE WEB SECURITY SCANNER <<
================================================================================

[i] DEVELOPED BY: Mehmet Tezcan
[i] ROLE: Junior Penetration Tester & Computer Engineering Student
[i] PLATFORM: Linux / Python 3.13+

--------------------------------------------------------------------------------
1. PROJECT OVERVIEW
--------------------------------------------------------------------------------
Vortex is a high-performance, modular web security scanner developed for 
automated reconnaissance and vulnerability discovery. Built for speed and 
accuracy, it integrates subdomain enumeration, web crawling, and a 
multi-threaded engine to identify critical flaws like SQL Injection and XSS.

--------------------------------------------------------------------------------
2. CORE FEATURES
--------------------------------------------------------------------------------
[*] Subdomain Enumeration: Rapid discovery using custom wordlists.
[*] Intelligent Crawler: Automatically extracts HTML forms and input fields.
[*] Vulnerability Engine:
    - Error-Based SQLi (MySQL, Oracle, PostgreSQL, SQLite)
    - Reflected XSS (Multi-parameter reflection analysis)
[*] Performance: Optimized concurrency using ThreadPoolExecutor & Queue.
[*] Professional Reporting: High-quality HTML Dashboards and JSON data export.

--------------------------------------------------------------------------------
3. TECHNICAL ARCHITECTURE
--------------------------------------------------------------------------------
[ RECON ] ----> [ ANALYSIS ] ----> [ ATTACK ] ----> [ REPORTING ]
   |                |                 |                 |
   |-- Subdomain    |-- Form Mapping  |-- Parallel      |-- Sanitization
   |-- DNS Resolving|-- Parameter     |-- Payload       |-- Visual Output
       Check            Extraction        Testing           (HTML/JSON)

--------------------------------------------------------------------------------
4. INSTALLATION & SETUP
--------------------------------------------------------------------------------
# Clone the repository
$ git clone https://github.com/mtezcan0/VortexScanner.git
$ cd VortexScanner

# Create a virtual environment (Recommended for Kali 2026)
$ python3 -m venv venv
$ source venv/bin/activate

# Install dependencies and register the command
$ pip install -r requirements.txt
$ pip install -e . --break-system-packages

--------------------------------------------------------------------------------
5. USAGE GUIDE
--------------------------------------------------------------------------------
After installation, run 'vortexscan' from any directory:

$ vortexscan --help                      # Show help menu
$ vortexscan -d example.com              # Basic scan
$ vortexscan -d target.com -w common.txt -t 100 -o  # Advanced scan

+---------+-------------+------------------------------------+-----------+
| FLAG    | ARGUMENT    | DESCRIPTION                        | DEFAULT   |
+---------+-------------+------------------------------------+-----------+
| -d      | --domain    | Target domain (e.g., vulnweb.com)  | REQUIRED  |
| -w      | --wordlist  | Path to subdomain wordlist         | data/...  |
| -t      | --threads   | Number of concurrent threads       | 50        |
| -o      | --output    | Save results to HTML/JSON reports  | False     |
+---------+-------------+------------------------------------+-----------+

--------------------------------------------------------------------------------
6. PROJECT STRUCTURE
--------------------------------------------------------------------------------
VortexScanner/
├── main.py              # Main CLI Entry Point
├── setup.py             # Package Configuration
├── requirements.txt     # Python Dependencies
├── data/
│   ├── subdomains.txt   # Subdomain Wordlist
│   ├── sqli_payloads.txt# SQL Injection Payloads
│   └── xss_payloads.txt # XSS Payloads
├── modules/
│   ├── subdomain.py     # DNS Enumeration Logic
│   ├── crawler.py       # Web Form Extraction
│   ├── scanner.py       # Vulnerability Testing Engine
│   └── reporter.py      # Report Generation
└── reports/             # Generated Scan Results

--------------------------------------------------------------------------------
7. LEGAL DISCLAIMER
--------------------------------------------------------------------------------
Usage of Vortex for attacking targets without prior mutual consent is illegal. 
It is the end user's responsibility to obey all applicable laws. Developers 
assume no liability and are not responsible for any misuse or damage caused 
by this program. For educational and ethical hacking purposes only.
================================================================================
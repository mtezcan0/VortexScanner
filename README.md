# 🌀 Vortex Cyber Scanner (Advanced Recon Edition)

Vortex is a high-performance, modular web security scanner developed for automated reconnaissance and vulnerability discovery. Built for speed and accuracy, it integrates subdomain enumeration, web crawling, and a multi-threaded vulnerability engine to identify critical flaws like SQL Injection and Cross-Site Scripting (XSS).

[![Python Version](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red.svg)](https://www.kali.org/)

## 🚀 Key Features

* **Subdomain Enumeration:** Rapid discovery using custom wordlists and IDNA-safe DNS resolution.
* **Intelligent Form Crawler:** Automatically extracts HTML forms, input fields, and textareas from discovered services.
* **Vulnerability Engine:**
* **Error-Based SQLi:** Scans for database-specific error signatures (MySQL, Oracle, PostgreSQL, SQLite).
* **Reflected XSS:** Analyzes payload reflection across multiple input types.
* **Multi-threaded Performance:** Optimized using `ThreadPoolExecutor` and `Queue` for high-speed concurrent testing.
* **Professional Reporting:** Generates high-quality HTML dashboards for human analysis and JSON data for tool integration.

---

## 🛠️ Technical Architecture



1.  **Recon Phase:** Resolves subdomains and verifies active HTTP services (Status 200).
2.  **Analysis Phase:** Crawls discovered endpoints to map forms and interactive parameters.
3.  **Attack Phase:** Executes parallelized payload testing with randomized User-Agents to mimic real browsers.
4.  **Reporting Phase:** Sanitizes results and generates visual reports.

---

## 💻 Installation & Setup

Vortex is designed to run seamlessly on Kali Linux.

```bash
# Clone the repository
git clone [https://github.com/mtezcan0/VortexScanner.git](https://github.com/mtezcan0/VortexScanner.git)
cd VortexScanner

# Create a virtual environment (Recommended for Kali 2026)
python3 -m venv venv
source venv/bin/activate

# Install dependencies and register 'vortexscan' command globally
pip install -r requirements.txt
pip install -e . --break-system-packages

⚡ Usage

After installation, you can run Vortex from any directory using the vortexscan command:

# Display help menu
vortexscan --help

# Basic scan on a target
vortexscan -d example.com

# Advanced scan with custom threads and automated reporting
vortexscan -d target.com -w /usr/share/wordlists/dirb/common.txt -t 100 -o


Arguments Table

Flag,Argument,Description,Default
-d,--domain,"Target domain to scan (e.g., vulnweb.com)",Required
-w,--wordlist,Path to subdomain wordlist file,data/subdomains.txt
-t,--threads,Number of concurrent threads,50
-o,--output,Save results to HTML and JSON reports,False


📁 Project Structure


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
│   └── reporter.py      # HTML/JSON Report Generation
└── reports/             # Generated Scan Results


⚖️ Legal Disclaimer
Usage of Vortex for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. For educational and ethical hacking purposes only.






Developed by Mehmet Tezcan Junior Penetration Tester & Computer Engineering Student 
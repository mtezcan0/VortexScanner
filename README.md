🌀 Vortex Cyber Scanner (Advanced Recon Edition)
Vortex is a high-performance, modular web security scanner developed for automated reconnaissance and vulnerability discovery. Built with a focus on speed and accuracy, it integrates subdomain enumeration, web crawling, and a multi-threaded vulnerability engine to identify critical security flaws like SQL Injection and Cross-Site Scripting (XSS).

🚀 Features
Subdomain Enumeration: Fast discovery of subdomains using custom wordlists to expand the attack surface.

Form Crawler: Automatically extracts HTML forms and input fields from active web services to identify potential entry points.

High-Performance Scanning: Utilizes a multi-threaded engine (ThreadPoolExecutor) to test thousands of payloads concurrently.

Vulnerability Engine: Includes specialized modules for:

Error-Based SQL Injection: Detection via database-specific error signatures.

Reflected XSS: Identification through payload reflection analysis.

Dual-Reporting System:

HTML Dashboard: Professional, dark-themed visual reports for human analysis.

JSON Data: Machine-readable output for integration with other security tools.

🛠️ Technical Architecture
Vortex is designed using a modular architecture to ensure scalability and ease of maintenance:

Recon Phase: Resolves subdomains and checks for active HTTP services (Status 200).

Analysis Phase: Crawls discovered endpoints to map forms and parameters.

Attack Phase: Executes parallelized payload testing with a focus on bypassing basic WAFs via randomized User-Agents.

Reporting Phase: Sanitizes results using html.escape to prevent Self-XSS in the generated reports.

💻 Installation
Bash

# Clone the repository
git clone https://github.com/mtezcan0/VortexScanner.git
cd VortexScanner

# Install dependencies
pip install -r requirements.txt
⚡ Usage
Vortex provides a flexible Command Line Interface (CLI) powered by argparse:

Bash

# Basic usage
python main.py -d target.com

# Advanced usage with custom threads and wordlist
python main.py -d target.com -w data/custom_subdomains.txt -t 100
Arguments:

-d, --domain: Target domain to scan.

-w, --wordlist: Path to subdomain wordlist (Default: data/subdomains.txt).

-t, --threads: Number of concurrent threads (Default: 50).

📊 Sample Output (Test Case: vulnweb.com)
During initial testing on the vulnweb.com sandbox, Vortex successfully identified:

Total Vulnerabilities Found: 484

Vulnerability Types: SQLi (Time-based & Error-based), XSS (SVG, Script, Embed-based).

⚖️ Legal Disclaimer
Usage of Vortex for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. For educational and ethical hacking purposes only.


Developed by Mehmet Tezcan | Junior Penetration Tester & Computer Engineering Student



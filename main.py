#!/usr/bin/env python3
import os
import json
import argparse
import sys
from pyfiglet import Figlet
from colorama import init, Fore, Style
from modules.subdomain import start_subdomain_scan
from modules.crawler import extract_forms
from modules.reporter import generate_full_report 
from modules.scanner import check_vulnerability

init(autoreset=True)

def print_banner():
    f = Figlet(font='slant')
    print(Fore.CYAN + f.renderText('VORTEX'))
    print(f"{Fore.YELLOW}{Style.BRIGHT}Vortex Cyber Scanner - Advanced Recon Edition (2026)")
    print(f"{Fore.WHITE}Developed for Security Audits & CTF Challenges")
    print(f"{Fore.CYAN}{'='*60}\n")

def valid_file(path):
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(f"{Fore.RED}[!] Error: Wordlist file '{path}' not found!")
    return path

def clean_target(raw_url):
    return raw_url.replace("http://", "").replace("https://", "").split("/")[0].strip()

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Vortex Cyber Scanner - Multi-threaded Security Recon Tool",
        epilog="Example: vortexscan -d example.com -t 100 -o"
    )
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Subdomain wordlist path", default="data/subdomains.txt", type=valid_file)
    parser.add_argument("-t", "--threads", help="Concurrent threads for scanning", type=int, default=50)
    parser.add_argument("-o", "--output", help="Generate final reports (JSON/HTML)", action="store_true")

    args = parser.parse_args()

    if args.domain:
        target = clean_target(args.domain)
    else:
        raw_input = input(f"{Fore.YELLOW}[?] Enter Target Domain: {Fore.RESET}").strip()
        if not raw_input:
            print(f"{Fore.RED}[!] No target provided. Exiting.")
            sys.exit(1)
        target = clean_target(raw_input)

    wordlist_count = sum(1 for line in open(args.wordlist, 'r', encoding="utf-8") if line.strip())
    print(f"{Fore.BLUE}[*] Target: {Fore.WHITE}{target}")
    print(f"{Fore.BLUE}[*] Wordlist: {Fore.WHITE}{args.wordlist} ({wordlist_count} entries)")
    print(f"{Fore.BLUE}[*] Threads: {Fore.WHITE}{args.threads}")
    print(f"{Fore.CYAN}{'-'*60}")

    print(f"\n{Fore.MAGENTA}[PHASE 1] Subdomain Enumeration Started...")
    results = start_subdomain_scan(target, args.wordlist, args.threads)

    if results:
        print(f"\n{Fore.MAGENTA}[PHASE 2 & 3] Analyzing Active Targets (Forms & Vulns)...")
        
        for sub, data in results.items():
            if data.get('status') == 200:
                url = f"http://{sub}"
                print(f"\n{Fore.BLUE}🔎 Testing: {Fore.WHITE}{url}")
                
                results[sub]['forms'] = []
                results[sub]['vulnerabilities'] = []
                
                try:
                    forms = extract_forms(url)
                    results[sub]['forms'] = forms 
                    
                    if forms:
                        print(f"{Fore.GREEN}    [+] {len(forms)} forms detected. Starting automated payloads...")
                        for form in forms:
                            vulns = check_vulnerability(url, form)
                            if vulns:
                                for v in vulns:
                                    print(f"{Fore.RED}    [!] ALERT: {v} FOUND!")
                                results[sub]['vulnerabilities'].extend(vulns)
                    else:
                        print(f"{Fore.WHITE}    [i] No forms found on the landing page.")
                except Exception as e:
                    print(f"{Fore.RED}    [!] Error crawling {url}: {e}")

    if args.output or results:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}[PHASE 4] Generating Final Reports...")
        
        if not os.path.exists("reports"):
            os.makedirs("reports")
        
        json_path = f"reports/{target}_data.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"{Fore.GREEN}[+] Machine-readable data: {json_path}")

        try:
            report_path = generate_full_report(target, results)
            if report_path:
                print(f"{Fore.GREEN}[+] Human-readable HTML: {report_path}")
        except Exception as e:
            print(f"{Fore.RED}[!] Reporting Error: {e}")

    print(f"\n{Fore.YELLOW}[*] Scan Complete. Good luck, hacker!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
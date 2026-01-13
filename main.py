import os
import json 
import argparse 
import sys
from modules.subdomain import start_subdomain_scan
from modules.crawler import extract_forms
from modules.reporter import generate_full_report 
from modules.scanner import check_vulnerability
from colorama import init, Fore


init(autoreset=True)

def valid_file(path):
    """Dosya varlığını argparse seviyesinde kontrol eder."""
    if not os.path.exists(path):
        
        raise argparse.ArgumentTypeError(f"{Fore.RED}[!] Error: Wordlist file '{path}' not found!{Fore.RESET}")
    return path

def main():
    
    print(f"{Fore.CYAN}🌀 Vortex Cyber Scanner - Advanced Recon Edition{Fore.RESET}")
    
    parser = argparse.ArgumentParser(description="Vortex Cyber Scanner - Automated Security Recon")
    parser.add_argument("-d", "--domain", help="Target domain (eg: vulnweb.com)", required=False)
    
   
    parser.add_argument(
        "-w", "--wordlist", 
        help="Subdomain wordlist path", 
        default="data/subdomains.txt", 
        type=valid_file 
    )
    
    parser.add_argument("-t", "--threads", help="Thread count for scanning", type=int, default=50)
    args = parser.parse_args()

    
    if args.domain:
        target = args.domain.replace("http://", "").replace("https://", "").split("/")[0]
    else:
        raw_target = input(f"{Fore.YELLOW}Target Domain (eg: google.com): {Fore.RESET}").strip()
        target = raw_target.replace("http://", "").replace("https://", "").split("/")[0]

    wordlist = args.wordlist
    threads = args.threads

    
    with open(wordlist, 'r') as f:
        line_count = sum(1 for line in f if line.strip())

    print(f"{Fore.GREEN}[+] Wordlist Loaded: {Fore.WHITE}{wordlist} ({line_count} words)")
    print(f"{Fore.GREEN}[+] Threads: {Fore.WHITE}{threads}")

   
    print(f"\n{Fore.MAGENTA}--- PHASE 1: SUBDOMAIN ENUMERATION ---{Fore.RESET}")
    results = start_subdomain_scan(target, wordlist, threads)

   
    if results:
        print(f"\n{Fore.MAGENTA}--- PHASE 2 & 3: ANALYZING ACTIVE TARGETS ---{Fore.RESET}")
        
        for sub, data in results.items():
            
            if data['status'] == 200:
                url = f"http://{sub}"
                print(f"\n{Fore.BLUE}[*] Testing: {url}")
                
                results[sub]['forms'] = []
                results[sub]['vulnerabilities'] = []
                
                
                forms = extract_forms(url)
                results[sub]['forms'] = forms 
                
                if forms:
                    print(f"{Fore.GREEN}    [+] {len(forms)} forms detected. Starting automated tests...")
                    
                    
                    for form in forms:
                        vulns = check_vulnerability(url, form)
                        if vulns:
                            for v in vulns:
                                print(f"{Fore.RED}      [!] VULNERABILITY FOUND: {v}")
                            results[sub]['vulnerabilities'].extend(vulns) 
                else:
                    print(f"{Fore.WHITE}    [!] No forms detected on index page.")

    
    print(f"\n{Fore.CYAN}--- GENERATING FINAL REPORTS ---")
    
    if not os.path.exists("reports"):
        os.makedirs("reports")
        
    
    json_path = f"reports/{target}_data.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"{Fore.GREEN}[+] Machine-readable JSON saved to: {json_path}")

    
    report_path = generate_full_report(target, results)
    if report_path:
        print(f"{Fore.GREEN}[+] Human-readable HTML report saved to: {report_path}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user. Exiting...")
        sys.exit(0)
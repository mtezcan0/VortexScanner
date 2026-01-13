import asyncio
import argparse
import sys
import time
from colorama import Fore, Style, init
from modules.subdomain import start_subdomain_scan_async
from modules.crawler import start_crawling_async
from modules.scanner import start_scanning_async
from modules.reporter import generate_reports

init(autoreset=True)

def print_banner():
    banner = r"""
   _    ______  ____  _____________  __
  | |  / / __ \/ __ \/_  __/ ____/ |/ /
  | | / / / / / /_/ / / / / __/  |   / 
  | |/ / /_/ / _, _/ / / / /___ /    | 
  |___/\____/_/ |_| /_/ /_____//_/|_| 

  Vortex Cyber Scanner - Advanced Recon Edition (2026)
  Developed by Mehmet Tezcan | KTÜN Computer Engineering
  ============================================================
    """
    print(f"{Fore.CYAN}{Style.BRIGHT}{banner}")

async def run_full_analysis(url):
    print(f"{Fore.BLUE}🔎 Testing: {url}")
    forms = await start_crawling_async(url)
    
    vulns = []
    if forms:
        print(f"    {Fore.GREEN}[+] {len(forms)} forms detected. Starting automated payloads...")
        vulns = await start_scanning_async(url, forms)
    else:
        print(f"    {Fore.WHITE}[i] No forms found on the landing page.")
    
    return {"url": url, "forms_found": len(forms), "vulnerabilities": vulns}

async def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Vortex Cyber Scanner - High-Speed Async Recon Tool")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", default="data/subdomains.txt", help="Subdomain wordlist path")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Max concurrent requests")
    parser.add_argument("-o", "--output", action="store_true", help="Generate final reports")
    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    target_domain = args.domain
    wordlist = args.wordlist
    concurrency_limit = args.threads

    print(f"{Fore.BLUE}[*] Target: {target_domain}")
    print(f"[*] Max Concurrency: {concurrency_limit}")
    print("-" * 60)

    start_time = time.time()

    print(f"\n{Fore.YELLOW}[PHASE 1] Async Subdomain Enumeration Started...")
    subdomain_results = await start_subdomain_scan_async(target_domain, wordlist, concurrency_limit)

    active_targets = [f"http://{sub}" for sub, data in subdomain_results.items() if data.get('status') == 200]

    if not active_targets:
        print(f"{Fore.RED}[!] No active targets found. Exiting.")
        return

    print(f"\n{Fore.YELLOW}[PHASE 2 & 3] Analyzing {len(active_targets)} Targets (Forms & Vulns)...")
    
    scan_tasks = []
    for url in active_targets:
        scan_tasks.append(run_full_analysis(url))
    
    all_scan_results = await asyncio.gather(*scan_tasks)
    
    final_results = {}
    for sub, data in subdomain_results.items():
        url = f"http://{sub}"
        final_results[sub] = {
            "ip": data.get("ip"),
            "status": data.get("status"),
            "findings": next((res for res in all_scan_results if res['url'] == url), {"forms_found": 0, "vulnerabilities": []})
        }

    if args.output:
        print(f"\n{Fore.YELLOW}[PHASE 4] Generating Final Reports...")
        generate_reports(target_domain, final_results)

    end_time = time.time()
    duration = round(end_time - start_time, 2)
    print(f"\n{Fore.GREEN}[*] Scan Complete in {duration} seconds. Good luck!")

def run_main():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    run_main()
import asyncio
import argparse
import sys
import time
import os
import aiohttp # IP kontrolu icin eklendi
from colorama import Fore, Style, init
from modules.subdomain import start_subdomain_scan_async
from modules.crawler import start_crawling_async
from modules.scanner import start_scanning_async
from modules.reporter import generate_reports

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

init(autoreset=True)

def print_banner():
    banner = r"""
   _      ______  ____  _____________  __
  | |    / / __ \/ __ \/_  __/ ____/ |/ /
  | |   / / / / / /_/ / / / / __/    |   / 
  | |  / / /_/ / _, _/ / / / /___    |  | 
  |___/\____/_/ |_| /_/ /_____/   |__| 

  Vortex Cyber Scanner - Advanced Recon Edition (2026)
  Developed by Mehmet Tezcan 
  ============================================================
    """
    print(f"{Fore.CYAN}{Style.BRIGHT}{banner}")

async def check_direct_target(url):
    
    target_url = url if url.startswith("http") else f"http://{url}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=5) as resp:
                if resp.status == 200:
                    return target_url
    except:
        return None
    return None

async def run_full_analysis(url, semaphore):
    async with semaphore:
        print(f"{Fore.BLUE}[*] Deep Crawling: {url}")
        try:
            all_forms = await start_crawling_async(url)
            
            vulns = []
            if all_forms:
                print(f"    {Fore.GREEN}[+] {len(all_forms)} forms detected on {url}")
                if len(all_forms) > 0:
                    print(f"    {Fore.YELLOW}[>] Launching payloads on {url}...")
                    vulns = await start_scanning_async(url, all_forms)
            else:
                print(f"    {Fore.WHITE}[i] No forms found on {url}")
            
            return {"url": url, "forms_found": len(all_forms), "vulnerabilities": vulns}
        except Exception as e:
            return {"url": url, "forms_found": 0, "vulnerabilities": []}

async def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Vortex Cyber Scanner")
    parser.add_argument("-d", "--domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", default="subdomains.txt", help="Wordlist filename in data folder")
    parser.add_argument("-t", "--threads", type=int, default=50, help="DNS Concurrency limit")
    parser.add_argument("-o", "--output", action="store_true", help="Generate HTML report")
    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    target_domain = args.domain
    wordlist_name = os.path.basename(args.wordlist)
    dns_concurrency = args.threads

    print(f"{Fore.BLUE}[*] Target: {target_domain}")
    print(f"[*] Wordlist: {wordlist_name}")
    print("-" * 60)

    start_time = time.time()

    print(f"\n{Fore.YELLOW}[PHASE 1] Async Subdomain Enumeration...")
    
    
    subdomain_results = await start_subdomain_scan_async(target_domain, wordlist_name, dns_concurrency)
    active_targets = [f"http://{sub}" for sub, data in subdomain_results.items() if data.get('status') == 200]

    
    
    if not active_targets:
        print(f"{Fore.YELLOW}[!] No subdomains found. Checking target directly (IP/Port Mode)...")
        direct_url = await check_direct_target(target_domain)
        
        if direct_url:
            print(f"{Fore.GREEN}[+] Target is UP! Switching to Direct Scan Mode: {direct_url}")
            active_targets.append(direct_url)
            
            subdomain_results[target_domain] = {"ip": "Direct", "status": 200}
        else:
            print(f"{Fore.RED}[!] Target {target_domain} is unreachable. Exiting.")
            return
    

    print(f"\n{Fore.YELLOW}[PHASE 2 & 3] Analyzing {len(active_targets)} Live Targets...")
    
    scan_semaphore = asyncio.Semaphore(5)
    
    scan_tasks = []
    for url in active_targets:
        scan_tasks.append(run_full_analysis(url, scan_semaphore))
    
    all_scan_results = await asyncio.gather(*scan_tasks)
    
    final_results = {}
    total_vulns = 0

    for sub, data in subdomain_results.items():
        
        url = sub if sub.startswith("http") else f"http://{sub}"
        
        
        scan_data = next((res for res in all_scan_results if res['url'] == url), None)
        
      
        if not scan_data:
             scan_data = next((res for res in all_scan_results if sub in res['url']), None)

        forms = scan_data['forms_found'] if scan_data else 0
        vulns = scan_data['vulnerabilities'] if scan_data else []
        total_vulns += len(vulns)

        final_results[sub] = {
            "ip": data.get("ip"),
            "status": data.get("status"),
            "findings": {
                "forms_found": forms,
                "vulnerabilities": vulns
            }
        }

    if args.output:
        print(f"\n{Fore.YELLOW}[PHASE 4] Generating Report...")
        report_file = generate_reports(target_domain, final_results)
        print(f"{Fore.GREEN}[+] Report saved to: {report_file}")

    end_time = time.time()
    duration = round(end_time - start_time, 2)
    print(f"\n{Fore.MAGENTA}[*] Scan Complete in {duration} seconds. Found {total_vulns} vulnerabilities.")

def run_main():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    run_main()
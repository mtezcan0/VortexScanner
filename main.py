import asyncio
import argparse
import sys
import time
import os
import re
import aiohttp
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

def is_ip_address(target):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$')
    return ip_pattern.match(target) is not None

async def check_target_alive(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as resp:
                return resp.status if resp.status < 500 else None
    except:
        return None

async def worker(queue, results, semaphore, max_depth):
    while True:
        target_item = await queue.get()
        target_url = target_item['url']
        target_ip = target_item.get('ip', 'N/A')
        
        async with semaphore:
            try:
                print(f"{Fore.BLUE}[*] Processing Target: {target_url}")
                
                
                forms = await start_crawling_async(target_url, max_depth=max_depth)
                form_count = len(forms)
                
                vulns = []
                if form_count > 0:
                    print(f"    {Fore.GREEN}[+] {form_count} forms discovered. Starting Deep Scan...")
                    
                    vulns = await start_scanning_async(target_url, forms)
                else:
                    print(f"    {Fore.WHITE}[i] No forms found on {target_url}. Skipping attack phase.")

                results[target_url] = {
                    "ip": target_ip,
                    "status": 200,
                    "findings": {
                        "forms_found": form_count,
                        "vulnerabilities": vulns
                    }
                }
                
            except aiohttp.ClientError as e:
                print(f"    {Fore.RED}[!] Connection Error on {target_url}: {e}")
            except asyncio.TimeoutError:
                print(f"    {Fore.RED}[!] Timeout on {target_url}")
            except Exception as e:
                print(f"    {Fore.RED}[!] Unexpected Error on {target_url}: {e}")
            finally:
                queue.task_done()

async def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Vortex Cyber Scanner")
    parser.add_argument("-d", "--domain", help="Target domain or IP")
    parser.add_argument("-w", "--wordlist", default="subdomains.txt", help="Wordlist filename")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Global concurrency limit")
    parser.add_argument("--depth", type=int, default=2, help="Crawler depth level")
    parser.add_argument("-o", "--output", action="store_true", help="Generate HTML report")
    
    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    
    raw_target = args.domain
    if raw_target.startswith("http://"): raw_target = raw_target.replace("http://", "")
    if raw_target.startswith("https://"): raw_target = raw_target.replace("https://", "")
    raw_target = raw_target.rstrip('/')

    target_input = raw_target
    wordlist_name = os.path.basename(args.wordlist)
    concurrency = args.threads

    print(f"{Fore.BLUE}[*] Target: {target_input}")
    print(f"[*] Max Concurrency: {concurrency}")
    print("-" * 60)

    start_time = time.time()
    
    
    targets_to_scan = []
    
    if is_ip_address(target_input):
        print(f"\n{Fore.YELLOW}[!] IP detected. Direct Scan Mode.")
        base_url = f"http://{target_input}"
        status = await check_target_alive(base_url)
        if status:
            targets_to_scan.append({"url": base_url, "ip": target_input})
            print(f"{Fore.GREEN}[+] Host is UP.")
        else:
            print(f"{Fore.RED}[!] Host unreachable.")
            return
    else:
        print(f"\n{Fore.YELLOW}[PHASE 1] Subdomain Enumeration...")
        
        sub_results = await start_subdomain_scan_async(target_input, wordlist_name, 100)
        
        
        for sub, data in sub_results.items():
            if data.get('status') == 200:
                url = sub if sub.startswith("http") else f"http://{sub}"
                targets_to_scan.append({"url": url, "ip": data.get('ip')})
        
        
        if not targets_to_scan:
            print(f"{Fore.YELLOW}[!] No subdomains found. Checking root domain...")
            root_url = f"http://{target_input}"
            if await check_target_alive(root_url):
                targets_to_scan.append({"url": root_url, "ip": "Direct"})

    
    if not targets_to_scan:
        print(f"{Fore.RED}[!] No live targets found. Exiting.")
        return

    print(f"\n{Fore.YELLOW}[PHASE 2 & 3] Batch Scanning {len(targets_to_scan)} Targets...")
    
    queue = asyncio.Queue()
    final_results = {}
    
    
    for t in targets_to_scan:
        queue.put_nowait(t)

    
    sem = asyncio.Semaphore(concurrency)
    
    
    workers = []
    
    num_workers = min(concurrency, len(targets_to_scan))
    
    for _ in range(num_workers):
        task = asyncio.create_task(worker(queue, final_results, sem, args.depth))
        workers.append(task)

    
    await queue.join()
    
    
    for task in workers:
        task.cancel()

    
    total_vulns = sum(len(d['findings']['vulnerabilities']) for d in final_results.values())
    
    if args.output:
        print(f"\n{Fore.YELLOW}[PHASE 4] Generating Report...")
        report_file = generate_reports(target_input, final_results)
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
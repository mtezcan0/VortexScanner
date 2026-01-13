import asyncio
import aiodns
import aiohttp
import os
import datetime
from colorama import Fore

found_subdomains = {}

async def check_http(session, target):
    try:
        async with session.get(f"http://{target}", timeout=2, allow_redirects=True) as response:
            return response.status
    except:
        return "TIMEOUT"

async def resolve_dns(resolver, session, full_domain, semaphore):
    async with semaphore:
        try:
            result = await resolver.query(full_domain, 'A')
            ip = result[0].host
            status = await check_http(session, full_domain)
            
            color = Fore.GREEN if status == 200 else Fore.YELLOW
            print(f"{color}[+] Found: {full_domain:<25} | IP: {ip:<15} | Status: {status}{Fore.RESET}")
            
            found_subdomains[full_domain] = {"ip": ip, "status": status}
        except:
            pass

async def start_subdomain_scan_async(domain, wordlist_path, concurrency=100):
    found_subdomains.clear()
    resolver = aiodns.DNSResolver()
    semaphore = asyncio.Semaphore(concurrency)
    
    root_domain = domain.strip('.')
    
    print(f"{Fore.BLUE}[*] Starting Async Scan: {root_domain}")
    print(f"[*] Max Concurrency: {concurrency}\n{Fore.RESET}")

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        tasks = []
        tasks.append(resolve_dns(resolver, session, root_domain, semaphore))
        
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', encoding="utf-8", errors="ignore") as f:
                for line in f:
                    sub = line.strip().strip('.')
                    if sub:
                        tasks.append(resolve_dns(resolver, session, f"{sub}.{root_domain}", semaphore))
        
        await asyncio.gather(*tasks)
    
    return found_subdomains

def save_subdomain_report(target, results_dict):
    if not results_dict:
        return None

    if not os.path.exists("reports"):
        os.makedirs("reports")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"reports/{target}_{file_timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("="*75 + "\n")
        f.write(f"VORTEX SCANNER - ASYNC RECON REPORT\n")
        f.write(f"Target: {target} | Date: {timestamp}\n")
        f.write("="*75 + "\n\n")
        f.write(f"{'SUBDOMAIN':<35} | {'IP ADDRESS':<15} | {'STATUS':<10}\n")
        f.write("-" * 75 + "\n")
        
        for sub, data in results_dict.items():
            f.write(f"{sub:<35} | {data['ip']:<15} | {data['status']:<10}\n")
            
    return filename
import asyncio
import aiodns
import aiohttp
import os
import datetime
from colorama import Fore

found_subdomains = {}

DNS_SERVERS = [
    '1.1.1.1', '1.0.0.1',
    '8.8.8.8', '8.8.4.4',
    '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220'
]

async def check_http(session, target):
    try:
        url = f"http://{target}"
        async with session.get(url, timeout=3, allow_redirects=True) as response:
            return response.status
    except:
        return "TIMEOUT"

async def resolve_dns_retry(resolver, full_domain):
    for attempt in range(2):
        try:
            result = await resolver.query(full_domain, 'A')
            return result[0].host
        except aiodns.error.DNSError:
            break
        except Exception:
            if attempt == 0:
                await asyncio.sleep(0.1)
                continue
            break
    return None

async def worker(resolver, session, full_domain, semaphore):
    async with semaphore:
        ip = await resolve_dns_retry(resolver, full_domain)
        
        if ip:
            status = await check_http(session, full_domain)
            
            if status == 200:
                print(f"{Fore.GREEN}[+] Found: {full_domain:<35} | IP: {ip:<15} | Status: {status}{Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}[+] Found: {full_domain:<35} | IP: {ip:<15} | Status: {status}{Fore.RESET}")
            
            found_subdomains[full_domain] = {"ip": ip, "status": status}

async def start_subdomain_scan_async(domain, wordlist_name="subdomains.txt", concurrency=100):
    found_subdomains.clear()
    
    if os.path.exists(wordlist_name):
        wordlist_path = wordlist_name
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        clean_name = os.path.basename(wordlist_name)
        wordlist_path = os.path.join(base_dir, "data", clean_name)
    
    resolver = aiodns.DNSResolver(nameservers=DNS_SERVERS, rotate=True, timeout=2)
    semaphore = asyncio.Semaphore(concurrency)
    root_domain = domain.strip('.')
    
    print(f"{Fore.BLUE}[*] Starting Optimized Scan: {root_domain}")
    print(f"[*] DNS Servers: Rotating {len(DNS_SERVERS)} providers")
    print(f"[*] Max Concurrency: {concurrency}")
    
    if os.path.exists(wordlist_path):
        print(f"{Fore.CYAN}[*] Using Wordlist: {wordlist_path}{Fore.RESET}\n")
    else:
        print(f"{Fore.RED}[!] Wordlist NOT found at: {wordlist_path}{Fore.RESET}")
        print(f"{Fore.RED}[!] Scanning only root domain...{Fore.RESET}\n")

    conn = aiohttp.TCPConnector(ssl=False, limit=0, limit_per_host=0)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        tasks = []
        tasks.append(worker(resolver, session, root_domain, semaphore))
        
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', encoding="utf-8", errors="ignore") as f:
                for line in f:
                    sub = line.strip().strip('.')
                    if sub:
                        full_domain = f"{sub}.{root_domain}"
                        tasks.append(worker(resolver, session, full_domain, semaphore))
        
        await asyncio.gather(*tasks)
    
    return found_subdomains

def save_subdomain_report(target, results_dict):
    if not results_dict:
        return None

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_dir = os.path.join(base_dir, "reports")
    
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = os.path.join(report_dir, f"{target}_subdomain_report_{file_timestamp}.txt")

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
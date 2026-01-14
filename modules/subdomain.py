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

async def resolve_dns_fast(resolver, full_domain):
    try:
        query_task = resolver.query(full_domain, 'A')
        result = await asyncio.wait_for(query_task, timeout=2.0)
        return result[0].host
    except (asyncio.TimeoutError, aiodns.error.DNSError):
        return None
    except Exception:
        return None

async def check_http_fast(session, target):
    url = f"http://{target}"
    try:
        async with session.get(url) as response:
            return response.status
    except:
        return None

async def worker(queue, resolver, session):
    while True:
        full_domain = await queue.get()
        try:
            ip = await resolve_dns_fast(resolver, full_domain)
            
            if ip:
                status = await check_http_fast(session, full_domain)
                
                if status:
                    if status == 200:
                        print(f"{Fore.GREEN}[+] Found: {full_domain:<35} | IP: {ip:<15} | Status: {status}{Fore.RESET}")
                    else:
                        print(f"{Fore.YELLOW}[+] Found: {full_domain:<35} | IP: {ip:<15} | Status: {status}{Fore.RESET}")
                    
                    found_subdomains[full_domain] = {"ip": ip, "status": status}
        except Exception:
            pass
        finally:
            queue.task_done()

async def start_subdomain_scan_async(domain, wordlist_name="subdomains.txt", concurrency=50):
    found_subdomains.clear()
    
    if os.path.exists(wordlist_name):
        wordlist_path = wordlist_name
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        clean_name = os.path.basename(wordlist_name)
        wordlist_path = os.path.join(base_dir, "data", clean_name)
    
    print(f"{Fore.BLUE}[*] Starting Optimized Scan: {domain}")
    print(f"[*] DNS Servers: Rotating {len(DNS_SERVERS)} providers")
    print(f"[*] Max Concurrency: {concurrency}")
    
    if not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[!] Wordlist NOT found at: {wordlist_path}{Fore.RESET}")
        return found_subdomains

    queue = asyncio.Queue()
    
    queue.put_nowait(domain)
    
    with open(wordlist_path, 'r', encoding="utf-8", errors="ignore") as f:
        for line in f:
            sub = line.strip().strip('.')
            if sub:
                full_domain = f"{sub}.{domain}"
                queue.put_nowait(full_domain)
    
    print(f"{Fore.CYAN}[*] Loaded tasks into Queue. Workers starting...{Fore.RESET}\n")

    resolver = aiodns.DNSResolver(nameservers=DNS_SERVERS, rotate=True, timeout=2)
    
    timeout_settings = aiohttp.ClientTimeout(total=3, connect=2, sock_connect=2)
    conn = aiohttp.TCPConnector(ssl=False, limit=0, limit_per_host=0)
    
    async with aiohttp.ClientSession(connector=conn, timeout=timeout_settings) as session:
        workers = []
        for _ in range(concurrency):
            task = asyncio.create_task(worker(queue, resolver, session))
            workers.append(task)
        
        await queue.join()
        
        for task in workers:
            task.cancel()
    
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
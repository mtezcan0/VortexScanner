import asyncio
import aiodns
import aiohttp
import os
import datetime
from colorama import Fore

found_subdomains = {}


DNS_SERVERS = [
    '1.1.1.1', '8.8.8.8',           
    '1.0.0.1', '8.8.4.4',           
    '9.9.9.9'                       
]

async def resolve_dns_reliable(resolver, full_domain):
    
    try:
        query_task = resolver.query(full_domain, 'A')
        result = await asyncio.wait_for(query_task, timeout=4.0)
        return result[0].host
    except (aiodns.error.DNSError, asyncio.TimeoutError):
        return None
    except Exception:
        return None

async def check_http_tolerant(session, target):
   
    url_http = f"http://{target}"
    url_https = f"https://{target}"
    
    
    try:
        async with session.get(url_http, allow_redirects=True) as response:
            return response.status
    except (aiohttp.ClientConnectorError, asyncio.TimeoutError, aiohttp.ServerDisconnectedError):
        
        pass 
    except Exception:
        pass 

    try:
        async with session.get(url_https, allow_redirects=True, ssl=False) as response:
            return response.status
    except aiohttp.ClientConnectorError:
        return "CONN_REFUSED" 
    except asyncio.TimeoutError:
        return "HTTP_TIMEOUT" 
    except Exception:
        return "ERROR"

    return "CONN_REFUSED"

async def worker(queue, resolver, session):
    while True:
        full_domain = await queue.get()
        
        try:
            ip = await resolve_dns_reliable(resolver, full_domain)
            
            if ip:
                status_code = await check_http_tolerant(session, full_domain)
                
                
                if isinstance(status_code, int):
                    color = Fore.GREEN if status_code < 400 else Fore.YELLOW
                    print(f"{color}[+] Found (WEB): {full_domain:<35} | IP: {ip:<15} | Status: {status_code}{Fore.RESET}")
                    found_subdomains[full_domain] = {"ip": ip, "status": status_code}
                
                elif status_code in ["HTTP_TIMEOUT", "CONN_REFUSED", "ERROR"]:
                    print(f"{Fore.MAGENTA}[+] Found (DNS): {full_domain:<35} | IP: {ip:<15} | Status: DNS-ONLY ({status_code}){Fore.RESET}")
                    found_subdomains[full_domain] = {"ip": ip, "status": "DNS-ONLY"}

        except Exception as e:
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
    
    print(f"{Fore.BLUE}[*] Starting Tolerant Scan: {domain}")
    print(f"[*] DNS Policy: Reliable Servers (rotate=False)")
    print(f"[*] HTTP Policy: HTTP -> HTTPS Fallback Enabled")
    
    if not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[!] Wordlist NOT found at: {wordlist_path}{Fore.RESET}")
        return found_subdomains

    queue = asyncio.Queue()
    queue.put_nowait(domain)
    
    with open(wordlist_path, 'r', encoding="utf-8", errors="ignore") as f:
        count = 0
        for line in f:
            sub = line.strip().strip('.')
            if sub:
                full_domain = f"{sub}.{domain}"
                queue.put_nowait(full_domain)
                count += 1
    
    print(f"{Fore.CYAN}[*] Loaded {count} targets. Workers initialized.{Fore.RESET}\n")

    resolver = aiodns.DNSResolver(nameservers=DNS_SERVERS, rotate=False, timeout=4)
    
    timeout_settings = aiohttp.ClientTimeout(total=8, connect=3, sock_connect=3)
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
        
        sorted_results = sorted(results_dict.items(), key=lambda x: str(x[1]['status']))
        
        for sub, data in sorted_results:
            status = str(data['status'])
            f.write(f"{sub:<35} | {data['ip']:<15} | {status:<10}\n")
            
    return filename
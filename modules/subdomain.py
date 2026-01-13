import socket
import threading
import requests
import os
import datetime
from queue import Queue
from colorama import Fore

found_subdomains = {}
print_lock = threading.Lock()

def request_dns(target):
    
    
    target = target.strip('.')
    
    
    if not target or '..' in target:
        return

    try:
        
        ip = socket.gethostbyname(target)
        status_code = "N/A"

        try:
            
            response = requests.get(f"http://{target}", timeout=3, allow_redirects=True)
            status_code = response.status_code
        except:
            status_code = "TIMEOUT"

        with print_lock:
            color = Fore.GREEN if status_code == 200 else Fore.YELLOW
            print(f"{color}[+] Found: {target:<25} | IP: {ip:<15} | Status: {status_code}{Fore.RESET}")
            
            found_subdomains[target] = {"ip": ip, "status": status_code}

    except (socket.gaierror, socket.timeout, UnicodeError):
        
        pass

def worker(q):
    
    while not q.empty():
        target = q.get()
        request_dns(target)
        q.task_done()

def start_subdomain_scan(domain, wordlist_path, thread_count=50):
    
    q = Queue()
    found_subdomains.clear()

   
    root_domain = domain.strip('.')
    q.put(root_domain)

    try:
        if os.path.exists(wordlist_path):
           
            with open(wordlist_path, 'r', encoding="utf-8", errors="ignore") as f:
                for line in f:
                    sub = line.strip().strip('.')
                    if sub:
                        q.put(f"{sub}.{root_domain}")
        else:
            print(f"{Fore.RED}[!] Wordlist file not found. Scanning root domain only.{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading wordlist: {e}{Fore.RESET}")
    
    print(f"{Fore.BLUE}[*] Starting Scan: {root_domain}")
    print(f"[*] Threads: {thread_count}\n{Fore.RESET}")

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(q,))
        t.daemon = True 
        t.start()
        threads.append(t)

    q.join()
    return found_subdomains

def save_subdomain_report(target, results_dict):
    
    if not results_dict:
        print(f"{Fore.RED}[!] No results found. Report skipped.{Fore.RESET}")
        return None

    if not os.path.exists("reports"):
        os.makedirs("reports")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"reports/{target}_{file_timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("="*75 + "\n")
        f.write(f"VORTEX SCANNER - RECON REPORT\n")
        f.write(f"Target: {target} | Date: {timestamp}\n")
        f.write("="*75 + "\n\n")
        f.write(f"{'SUBDOMAIN':<35} | {'IP ADDRESS':<15} | {'STATUS':<10}\n")
        f.write("-" * 75 + "\n")
        
        for sub, data in results_dict.items():
            f.write(f"{sub:<35} | {data['ip']:<15} | {data['status']:<10}\n")
            
    print(f"\n{Fore.CYAN}[i] Report saved to: {filename}{Fore.RESET}")
    return filename
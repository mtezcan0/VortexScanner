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
    try:
        ip = socket.gethostbyname(target)
        with print_lock:
            print(f"{Fore.GREEN}[+] Found: {target} -> {ip} {ip}{Fore.RESET}")
            found_subdomains[target] = ip
    except(socket.gaierror, socket.timeout):
        pass

def worker(q):
    while not q.empty():
        target = q.get()
        request_dns(target)
        q.task_done()

def start_subdomain_scan(domain, wordlist_path, thread_count=50):
    q = Queue()
    found_subdomains.clear()

    try:
        with open(wordlist_path, 'r', encoding="utf-8") as f:
            for line in f:
                clean_line = line.strip()
                if clean_line:
                    q.put(f"{clean_line}.{domain}")       
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: {wordlist_path} not found.{Fore.RESET}")
        return {}
    
    print(f"{Fore.BLUE}[*] {thread_count} Scanning is initiated with thread...{Fore.RESET}\n")

    threads= []

    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(q,))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    return found_subdomains



def request_dns(target):
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
            print(f"{color} Found: {target:<25} | IP: {ip:<15} | Status: {status_code}{Fore.RESET}")
            
            found_subdomains[target] = {"ip": ip, "status":status_code}

    except(socket.gaierror, socket.timeout):
        pass




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
        f.write(f"VORTEX SCANNER - RECON REPORT\n")
        f.write(f"Target: {target} | Date: {timestamp}\n")
        f.write(f"Scan Date: {timestamp}\n")
        f.write("="*75 + "\n")
        

        f.write(f"{'SUBDOMAIN':<30} | {'IP ADDRESS':<15} | {'STATUS':<10}\n")
        f.write("-"*75 + "\n")
        
        
        for sub, data in results_dict.items():
            f.write(f"{sub:<35} | {data['ip']:<15} | {data['status']:<10}\n")
            
    return filename


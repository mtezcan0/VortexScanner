import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed 
from colorama import Fore
from urllib.parse import urljoin

def load_payloads(filename):
    path = os.path.join("data", filename)
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return list(set(line.strip() for line in f if line.strip()))
    except:
        pass
    return []

SQLI_PAYLOADS = load_payloads("sqli_payloads.txt")
XSS_PAYLOADS = load_payloads("xss_payloads.txt")

def test_payload(target_url, method, input_name, payload, vuln_type):
    try:
        data = {input_name: payload}
        headers = {'User-Agent': 'VortexScanner/1.1 (Security Audit)'}
        
        if method == "post":
            res = requests.post(target_url, data=data, headers=headers, timeout=5, allow_redirects=True)
        else:
            res = requests.get(target_url, params=data, headers=headers, timeout=5, allow_redirects=True)

        if vuln_type == "SQLi":
            errors = [
                "sql syntax", "mysql_fetch_array", "system.data.sqlclient", 
                "oracle error", "postgre", "driver queries", "sqlite3.error"
            ]
            if any(error in res.text.lower() for error in errors):
                return f"SQLi detected in '{input_name}' using: {payload}"
        
        elif vuln_type == "XSS":
            if payload in res.text:
                return f"XSS detected in '{input_name}' using: {payload}"
                
    except:
        pass
    return None

def check_vulnerability(url, form):
    vulnerabilities = []
    action = form.get('action', '')
    method = form.get('method', 'get').lower()
    
    target_url = urljoin(url, action)

    with ThreadPoolExecutor(max_workers=20) as executor:
        tasks = []
        for inp in form.get('inputs', []):
            input_name = inp.get('name')
            input_type = inp.get('type', 'text').lower()
            
            if input_name and input_type in ['text', 'search', 'password', 'textarea', 'email']:
                for p in SQLI_PAYLOADS:
                    tasks.append(executor.submit(test_payload, target_url, method, input_name, p, "SQLi"))
                
                for p in XSS_PAYLOADS:
                    tasks.append(executor.submit(test_payload, target_url, method, input_name, p, "XSS"))

        for future in as_completed(tasks):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return list(set(vulnerabilities))
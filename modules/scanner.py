import asyncio
import aiohttp
import os
from urllib.parse import urljoin, urlparse
from colorama import Fore

DEFAULT_SQL_PAYLOADS = [
    "'", 
    "\"", 
    "' OR '1'='1", 
    "admin' --",
    "' UNION SELECT 1, @@version --"
]

DEFAULT_XSS_PAYLOADS = [
    "<script>alert('VTX')</script>",
    "\" onmouseover=\"alert('VTX')",
    "' onmouseover='alert(\"VTX\")",
    "javascript:alert('VTX')",
    "\"><img src=x onerror=alert(1)>"
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "oracle error",
    "postgre-sql error",
    "sqlite/jdbc_driver",
    "microsoft ole db provider for odbc drivers",
    "system.data.sqlite.sqliteexception",
    "sql syntax"
]

def get_file_payloads(filename):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", filename)
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    return []

async def send_request(session, url, method, data):
    try:
        if method == "POST":
            async with session.post(url, data=data, timeout=5) as resp:
                return await resp.text()
        else:
            async with session.get(url, params=data, timeout=5) as resp:
                return await resp.text()
    except:
        return None

async def check_vulnerability(session, action, method, inputs, payload, vuln_type):
    data = {}
    target_param = None
    
    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        
        inp_type = inp.get("type", "text")
        
        
        if not target_param and inp_type in ["text", "search", "password", "url", "email"]:
            data[name] = payload
            target_param = name
        else:
            
            data[name] = inp.get("value", "test")
    
    if not target_param:
        return None

    response_text = await send_request(session, action, method, data)
    if not response_text:
        return None
    
    response_lower = response_text.lower()
    
    if vuln_type == "SQLi":
        for error in SQL_ERRORS:
            if error in response_lower:
                print(f"{Fore.RED}[!] SQL Injection Found on {action}")
                print(f"    Param: {target_param} | Payload: {payload} | Error: {error}{Fore.RESET}")
                return {
                    "type": "SQL Injection",
                    "parameter": target_param,
                    "payload": payload,
                    "url": action
                }
                
    elif vuln_type == "XSS":
        if payload in response_text:
            print(f"{Fore.MAGENTA}[!] Reflected XSS Found on {action}")
            print(f"    Param: {target_param} | Payload: {payload}{Fore.RESET}")
            return {
                "type": "Reflected XSS",
                "parameter": target_param,
                "payload": payload,
                "url": action
            }
            
    return None

async def process_form(session, form, semaphore):
    async with semaphore:
        action = form.get("action")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        
        if not inputs or not action:
            return []
            
        found_vulns = []
        
        
        sqli_found = False
        
        
        for payload in DEFAULT_SQL_PAYLOADS:
            result = await check_vulnerability(session, action, method, inputs, payload, "SQLi")
            if result:
                found_vulns.append(result)
                sqli_found = True
                break 
        
        
        if not sqli_found:
            file_sql_payloads = get_file_payloads("sqli_payloads.txt")
            for payload in file_sql_payloads:
                result = await check_vulnerability(session, action, method, inputs, payload, "SQLi")
                if result:
                    found_vulns.append(result)
                    break 

       
        xss_found = False
        
        
        for payload in DEFAULT_XSS_PAYLOADS:
            result = await check_vulnerability(session, action, method, inputs, payload, "XSS")
            if result:
                found_vulns.append(result)
                xss_found = True
                break 
        
        
        if not xss_found:
            file_xss_payloads = get_file_payloads("xss_payloads.txt")
            for payload in file_xss_payloads:
                result = await check_vulnerability(session, action, method, inputs, payload, "XSS")
                if result:
                    found_vulns.append(result)
                    break

        return found_vulns

async def start_scanning_async(url, forms):
    conn = aiohttp.TCPConnector(ssl=False, limit=0)
    headers = {"User-Agent": "VortexScanner/1.1 (Hybrid-Engine)"}
    
    
    semaphore = asyncio.Semaphore(15)
    all_vulns = []

    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        tasks = []
        for form in forms:
            tasks.append(process_form(session, form, semaphore))
        
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                all_vulns.extend(res)

    return all_vulns
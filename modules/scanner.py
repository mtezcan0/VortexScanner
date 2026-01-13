import asyncio
import aiohttp
import os
from colorama import Fore

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql_fetch_array()",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "oracle error",
    "postgre-sql error",
    "sqlite/jdbc_driver",
    "microsoft ole db provider for odbc drivers"
]

def load_payloads(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    return []

async def test_sqli_async(session, url, form, payloads, semaphore):
    async with semaphore:
        vulnerabilities = []
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        target_url = url if not action else (action if action.startswith('http') else f"{url.rstrip('/')}/{action.lstrip('/')}")
        
        for payload in payloads:
            data = {}
            for input_field in inputs:
                name = input_field.get('name')
                if not name: continue
                if input_field.get('type') in ['text', 'search', 'password']:
                    data[name] = payload
                else:
                    data[name] = input_field.get('value', 'test')

            try:
                if method == 'post':
                    async with session.post(target_url, data=data, timeout=5) as resp:
                        content = await resp.text()
                else:
                    async with session.get(target_url, params=data, timeout=5) as resp:
                        content = await resp.text()

                for error in SQLI_ERRORS:
                    if error in content.lower():
                        vulnerabilities.append({"type": "SQL Injection", "payload": payload, "parameter": name})
                        return vulnerabilities
            except:
                pass
        return vulnerabilities

async def test_xss_async(session, url, form, payloads, semaphore):
    async with semaphore:
        vulnerabilities = []
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        target_url = url if not action else (action if action.startswith('http') else f"{url.rstrip('/')}/{action.lstrip('/')}")
        
        for payload in payloads:
            data = {}
            for input_field in inputs:
                name = input_field.get('name')
                if not name: continue
                if input_field.get('type') in ['text', 'search']:
                    data[name] = payload
                else:
                    data[name] = input_field.get('value', 'test')

            try:
                if method == 'post':
                    async with session.post(target_url, data=data, timeout=5) as resp:
                        content = await resp.text()
                else:
                    async with session.get(target_url, params=data, timeout=5) as resp:
                        content = await resp.text()

                if payload in content:
                    vulnerabilities.append({"type": "Reflected XSS", "payload": payload, "parameter": name})
                    return vulnerabilities
            except:
                pass
        return vulnerabilities

async def start_scanning_async(url, forms):
    semaphore = asyncio.Semaphore(20)
    all_vulns = []
    
    sqli_list = load_payloads("data/sqli_payloads.txt")
    xss_list = load_payloads("data/xss_payloads.txt")
    
    if not sqli_list and not xss_list:
        return []

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        tasks = []
        for form in forms:
            if sqli_list:
                tasks.append(test_sqli_async(session, url, form, sqli_list, semaphore))
            if xss_list:
                tasks.append(test_xss_async(session, url, form, xss_list, semaphore))
        
        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                all_vulns.extend(res)
                
    return all_vulns
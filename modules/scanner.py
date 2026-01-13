import asyncio
import aiohttp
import os
from urllib.parse import urljoin

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

def load_payloads(filename):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", filename)
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    return []

async def test_sqli_async(session, base_url, form, payloads, semaphore):
    async with semaphore:
        vulnerabilities = []
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        target_url = urljoin(base_url, action)
        
        for payload in payloads:
            data = {}
            target_param = ""
            for input_field in inputs:
                name = input_field.get('name')
                if not name: continue
                
                if input_field.get('type') in ['text', 'search', 'password']:
                    data[name] = payload
                    target_param = name
                else:
                    data[name] = input_field.get('value', 'test')

            try:
                if method == 'post':
                    async with session.post(target_url, data=data, timeout=10) as resp:
                        content = await resp.text()
                else:
                    async with session.get(target_url, params=data, timeout=10) as resp:
                        content = await resp.text()

                for error in SQLI_ERRORS:
                    if error in content.lower():
                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "url": target_url,
                            "payload": payload,
                            "parameter": target_param
                        })
                        return vulnerabilities
            except:
                pass
        return vulnerabilities

async def test_xss_async(session, base_url, form, payloads, semaphore):
    async with semaphore:
        vulnerabilities = []
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        target_url = urljoin(base_url, action)
        
        for payload in payloads:
            data = {}
            target_param = ""
            for input_field in inputs:
                name = input_field.get('name')
                if not name: continue
                
                if input_field.get('type') in ['text', 'search']:
                    data[name] = payload
                    target_param = name
                else:
                    data[name] = input_field.get('value', 'test')

            try:
                if method == 'post':
                    async with session.post(target_url, data=data, timeout=10) as resp:
                        content = await resp.text()
                else:
                    async with session.get(target_url, params=data, timeout=10) as resp:
                        content = await resp.text()

                if payload in content:
                    vulnerabilities.append({
                        "type": "Reflected XSS",
                        "url": target_url,
                        "payload": payload,
                        "parameter": target_param
                    })
                    return vulnerabilities
            except:
                pass
        return vulnerabilities

async def start_scanning_async(url, forms):
    semaphore = asyncio.Semaphore(10)
    all_vulns = []
    
    sqli_list = load_payloads("sqli_payloads.txt")
    xss_list = load_payloads("xss_payloads.txt")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    if not sqli_list and not xss_list:
        return []

    async with aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=False)) as session:
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
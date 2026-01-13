import asyncio
import aiohttp
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

async def test_sqli_async(session, url, form, semaphore):
    async with semaphore:
        vulnerabilities = []
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        target_url = url if not action else (action if action.startswith('http') else f"{url.rstrip('/')}/{action.lstrip('/')}")
        
        payloads = ["'", "\"", "';--", "') OR '1'='1"]
        
        for payload in payloads:
            data = {}
            for input_field in inputs:
                if input_field.get('type') in ['text', 'search', 'password']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field.get('value', 'test')

            try:
                if method == 'post':
                    async with session.post(target_url, data=data, timeout=5) as resp:
                        content = await resp.text()
                else:
                    async with session.get(target_url, params=data, timeout=5) as resp:
                        content = await resp.text()

                for error in SQLI_ERRORS:
                    if error in content.lower():
                        vulnerabilities.append({"type": "SQL Injection", "payload": payload, "parameter": "Multiple"})
                        break
            except:
                pass
        return vulnerabilities

async def test_xss_async(session, url, form, semaphore):
    async with semaphore:
        vulnerabilities = []
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.get('inputs', [])
        target_url = url if not action else (action if action.startswith('http') else f"{url.rstrip('/')}/{action.lstrip('/')}")
        
        payload = "<script>alert('Vortex')</script>"
        data = {}
        for input_field in inputs:
            if input_field.get('type') in ['text', 'search']:
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field.get('value', 'test')

        try:
            if method == 'post':
                async with session.post(target_url, data=data, timeout=5) as resp:
                    content = await resp.text()
            else:
                async with session.get(target_url, params=data, timeout=5) as resp:
                    content = await resp.text()

            if payload in content:
                vulnerabilities.append({"type": "Reflected XSS", "payload": payload, "parameter": "Multiple"})
        except:
            pass
        return vulnerabilities

async def start_scanning_async(url, forms):
    semaphore = asyncio.Semaphore(10)
    all_vulns = []
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        tasks = []
        for form in forms:
            tasks.append(test_sqli_async(session, url, form, semaphore))
            tasks.append(test_xss_async(session, url, form, semaphore))
        
        results = await asyncio.gather(*tasks)
        for res in results:
            if res:
                all_vulns.extend(res)
                
    return all_vulns
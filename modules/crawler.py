import asyncio
import aiohttp
from bs4 import BeautifulSoup
from colorama import Fore

async def start_crawling_async(url):
    forms_data = []
    headers = {'User-Agent': 'VortexScanner/1.1 (Security Audit)'}
    
    try:
        async with aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=False)) as session:
            async with session.get(url, timeout=7, allow_redirects=True) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "lxml")
                forms = soup.find_all("form")

                for form in forms:
                    action = form.get("action", "")
                    method = form.get("method", "get").lower()
                    inputs = []

                    for input_tag in form.find_all(["input", "textarea", "select"]):
                        input_type = input_tag.get("type", "text")
                        input_name = input_tag.get("name")
                        
                        if input_name:
                            inputs.append({
                                "type": input_type, 
                                "name": input_name,
                                "value": input_tag.get("value", "")
                            })

                    forms_data.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs
                    })
            
    except:
        pass

    return forms_data
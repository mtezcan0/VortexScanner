import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

async def fetch_and_parse(session, url, semaphore):
    async with semaphore:
        try:
            async with session.get(url, timeout=10, allow_redirects=True) as response:
                if response.status != 200:
                    return [], []
                
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/html" not in content_type:
                    return [], []

                html = await response.read()
                soup = BeautifulSoup(html, "lxml")
                
                forms_list = []
                for form in soup.find_all("form"):
                    action = form.attrs.get("action", "")
                    method = form.attrs.get("method", "get").lower()
                    full_action_url = urljoin(url, action)
                    
                    inputs = []
                    critical_score = 0
                    
                    for tag in form.find_all(["input", "textarea", "select"]):
                        input_name = tag.attrs.get("name")
                        input_type = tag.attrs.get("type", "text")
                        
                        if input_name:
                            inputs.append({
                                "type": input_type,
                                "name": input_name,
                                "value": tag.attrs.get("value", "")
                            })
                            
                            if input_type in ["password", "email", "hidden"]:
                                critical_score += 2
                            elif input_type in ["text", "search"]:
                                critical_score += 1

                    if inputs:
                        forms_list.append({
                            "url": url,
                            "action": full_action_url,
                            "method": method,
                            "inputs": inputs,
                            "priority": critical_score,
                            "meta": {
                                "input_count": len(inputs),
                                "has_password": any(i["type"] == "password" for i in inputs)
                            }
                        })

                internal_links = set()
                base_domain = urlparse(url).netloc
                
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    full_link = urljoin(url, href)
                    parsed_link = urlparse(full_link)
                    
                    if parsed_link.netloc == base_domain:
                        clean_link = full_link.split("#")[0].rstrip("/")
                        if clean_link != url.rstrip("/"):
                            internal_links.add(clean_link)
                            
                return forms_list, list(internal_links)

        except Exception:
            return [], []

async def start_crawling_async(start_url, max_depth=2):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    semaphore = asyncio.Semaphore(10)
    visited = set()
    all_forms = []
    
    start_url = start_url.split("#")[0].rstrip("/")
    current_level_urls = {start_url}
    visited.add(start_url)
    
    conn = aiohttp.TCPConnector(ssl=False, limit=0, limit_per_host=0)
    
    async with aiohttp.ClientSession(headers=headers, connector=conn) as session:
        for _ in range(max_depth + 1):
            if not current_level_urls:
                break
                
            tasks = []
            for url in current_level_urls:
                tasks.append(fetch_and_parse(session, url, semaphore))
            
            results = await asyncio.gather(*tasks)
            
            next_level_urls = set()
            
            for forms, links in results:
                all_forms.extend(forms)
                for link in links:
                    if link not in visited:
                        visited.add(link)
                        next_level_urls.add(link)
            
            current_level_urls = next_level_urls

    unique_forms = []
    seen_signatures = set()
    
    
    sorted_forms = sorted(all_forms, key=lambda x: x['priority'], reverse=True)
    
    for form in sorted_forms:
        input_names = sorted([i['name'] for i in form['inputs']])
        signature = f"{form['action']}|{form['method']}|{','.join(input_names)}"
        
        if signature not in seen_signatures:
            seen_signatures.add(signature)
            unique_forms.append(form)

    return unique_forms
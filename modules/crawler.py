import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

async def get_internal_links(session, base_url):
    links = {base_url}
    try:
        async with session.get(base_url, timeout=5) as response:
            html = await response.text()
            soup = BeautifulSoup(html, "lxml")
            domain = urlparse(base_url).netloc

            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                url = urljoin(base_url, href)
                if urlparse(url).netloc == domain:
                    links.add(url.split("#")[0].rstrip("/"))
    except:
        pass
    return list(links)

async def extract_forms_async(session, url):
    forms_list = []
    try:
        async with session.get(url, timeout=5) as response:
            html = await response.text()
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                form_details = {
                    "url": url,
                    "action": form.attrs.get("action", ""),
                    "method": form.attrs.get("method", "get").lower(),
                    "inputs": []
                }
                for input_tag in form.find_all(["input", "textarea", "select"]):
                    form_details["inputs"].append({
                        "type": input_tag.attrs.get("type", "text"),
                        "name": input_tag.attrs.get("name"),
                        "value": input_tag.attrs.get("value", "")
                    })
                forms_list.append(form_details)
    except:
        pass
    return forms_list

async def start_crawling_async(url):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        all_links = await get_internal_links(session, url)
        tasks = [extract_forms_async(session, link) for link in all_links]
        results = await asyncio.gather(*tasks)
        return [form for sublist in results for form in sublist]
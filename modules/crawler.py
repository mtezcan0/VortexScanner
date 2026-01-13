import requests
from colorama import Fore
from bs4 import BeautifulSoup

def extract_forms(url):
    forms_data = []
    headers = {'User-Agent': 'VortexScanner/1.1 (Security Audit)'}
    
    try:
        response = requests.get(url, timeout=7, headers=headers, allow_redirects=True)
        soup = BeautifulSoup(response.content, "html.parser")
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
            
    except Exception as e:
        pass

    return forms_data
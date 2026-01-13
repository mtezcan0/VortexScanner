import requests
from colorama import Fore
from bs4 import BeautifulSoup

def extract_forms(url):
    forms_data = []
    try:
        responce = requests.get(url, timeout=5)
        soup = BeautifulSoup(responce.content, "html.parser")
        forms = soup.find_all("form")

        for form in forms:

            action = form.get("action", "")
            method = form.get("method", "get").lower()

            inputs = []

            for input_tag in form.find_all(["input", "textarea"]):
                input_type = input_tag.get("type", "text")
                input_name = input_tag.get("name", "")
                inputs.append({"type": input_type, "name": input_name})

            forms_data.append({

                "action": action,
                "method": method,
                "inputs": inputs
            })
    except Exception as e:
        print(f"{Fore.RED}[!] Error Crawler ({url}): {e}{Fore.RESET}")

    return forms_data


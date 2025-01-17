import requests
import json
import os

API_KEY = "your_api_key_here"

def update_oui_database():
    url = f"https://api.maclookup.app/v2/macs?apiKey={API_KEY}"
    response = requests.get(url)
    data = response.json()

    if response.status_code == 200 and "success" in data:
        with open("oui.json", "w") as f:
            json.dump(data, f)
        return True
    else:
        return False

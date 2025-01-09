import json
import requests
import os
from pathlib import Path
from typing import Dict, Optional
import threading
import time


IEEE_URL = "https://standards-oui.ieee.org/oui.json"

def download_ieee_data():
    """Download MAC OUI data from IEEE site"""
    try:
        response = requests.get(IEEE_URL)
        response.raise_for_status()
        return response.text, True
    except requests.exceptions.RequestException as e:
       return f"Error downloading OUI data: {e}", False
    except Exception as e:
        return f"An unexpected error occurred: {e}", False


def update_oui_database(assets_path):
        try:
            data, success = download_ieee_data()
            if success:
                try:
                  parsed_data = json.loads(data)
                  sorted_data = dict(sorted(parsed_data.items(), key=lambda item: item[1]))
                  oui_file_path = os.path.join(assets_path, 'oui.json')
                  with open(oui_file_path, 'w') as f:
                     json.dump(sorted_data, f, indent=4, ensure_ascii=False)
                  return True, "OUI database updated successfully!"
                except json.JSONDecodeError as e:
                    return False, f"Error parsing JSON data: {e}"
            else:
                return False, data

        except Exception as e:
            return False, f"An unexpected error occurred: {e}"

if __name__ == "__main__":
    # Replace 'assets' with your actual assets directory if needed
    current_dir = os.path.dirname(__file__)
    assets_directory = os.path.join(current_dir, '..','assets')
    success, message = update_oui_database(assets_directory)
    if success:
        print(message)
    else:
        print(f"Error during OUI update : {message}")
import json
import requests
import os
from pathlib import Path
from typing import Dict, Optional
import time
import logging
import urllib3

API_KEY = "01jhq7f0txkh03mq13ygydzvtf01jhq7tprvw15vnbkenfjtdr5d4phqbuyywted"
API_URL = "https://api.maclookup.app/v2/macs/"
MAX_RETRIES = 3  # Maximum number of retry attempts
TIMEOUT = 5  # Timeout for each request in seconds

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def download_ieee_data():
    """Download MAC OUI data using the maclookup.app API."""
    oui_data = {}
    for attempt in range(MAX_RETRIES):
        try:
            logging.debug(f"Attempt {attempt + 1} to download OUI data using API")
            # we will fetch the data for each mac address manually.

            with open(os.path.join(os.path.dirname(__file__), '..', 'assets', 'oui.json'), 'r') as f:
                data = json.load(f)
            for mac in data.keys():
                api_url = f"{API_URL}{mac.replace('-', '')}?apiKey={API_KEY}"
                response = requests.get(api_url, timeout=TIMEOUT)
                response.raise_for_status()  # if there is any HTTP error throw an exception.
                api_response = response.json()
                if api_response.get("success") == True:
                    company = api_response.get("company", "Unknown")
                    oui_data[mac] = company
                    logging.debug(f"Successfully retrieved company : {company} for mac address : {mac}")
                else:
                    logging.error(
                        f"Error fetching OUI data using API for mac address: {mac} error : {api_response.get('error', 'Unknown')}")
                    if api_response.get("errorCode") == 429:
                        return f"Too Many API requests", False  # return after getting rate limit.
            logging.debug(f"OUI data downloaded successfully using API.")
            return oui_data, True

        except requests.exceptions.RequestException as e:
            logging.error(f"Error downloading OUI data (Attempt {attempt + 1}): {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(2)  # Wait for 2 seconds before retrying.
                continue
            else:
                return f"Failed to download OUI data after {MAX_RETRIES} retries.", False

        except Exception as e:
            logging.error(f"An unexpected error occurred during OUI download: {e}")
            return f"An unexpected error occurred during OUI download: {e}", False

    return f"Failed to download OUI data after {MAX_RETRIES} retries.", False


def update_oui_database(assets_path):
    try:
        data, success = download_ieee_data()
        if success:
            try:
                sorted_data = dict(sorted(data.items(), key=lambda item: item[1]))
                oui_file_path = os.path.join(assets_path, 'oui.json')
                with open(oui_file_path, 'w', encoding="utf-8") as f:
                    json.dump(sorted_data, f, indent=4, ensure_ascii=False)
                return True, "OUI database updated successfully!"
            except json.JSONDecodeError as e:
                logging.error(f"Error parsing JSON data: {e}")
                return False, f"Error parsing JSON data: {e}"
        else:
            return False, data
    except Exception as e:
        logging.error(f"An unexpected error occurred during OUI update: {e}")
        return False, f"An unexpected error occurred during OUI update: {e}"


if __name__ == "__main__":
    # Replace 'assets' with your actual assets directory if needed
    current_dir = os.path.dirname(__file__)
    assets_directory = os.path.join(current_dir, '..', 'assets')
    success, message = update_oui_database(assets_directory)
    if success:
        print(message)
    else:
        print(f"Error during OUI update : {message}")
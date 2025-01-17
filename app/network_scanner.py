from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from ipaddress import ip_address, ip_network
import subprocess
import platform
import socket
import re
import requests
import json
import os
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


class NetworkScanner:
    def __init__(self):
        self.oui_data = self.load_oui_data()
        self.api_key = "01jhq7f0txkh03mq13ygydzvtf01jhq7tprvw15vnbkenfjtdr5d4phqbuyywted"

    def load_oui_data(self):
        oui_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'oui.json')
        try:
            if os.path.exists(oui_path):
                with open(oui_path, 'r', encoding="utf-8") as f:
                    return json.load(f)
            else:
                logging.error(f"OUI file not found: {oui_path}")
                return {}
        except FileNotFoundError:
            logging.error(f"OUI file not found: {oui_path}")
            return {}
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding json: {e}")
            return {}
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading oui data: {e}")
            return {}

    def scan(self, ip_range):
        logging.debug(f"Starting scan for IP range: {ip_range}")
        try:
            if "/" not in ip_range:
                ip_range = ip_range + "/24"  # default to /24 if subnet mask is not specified.
            subnet = ip_network(ip_range, False)
            total_ips = len(list(subnet))
            scanned_ips = 0
            for target_ip in subnet:
                logging.debug(f"Scanning IP: {target_ip}")
                try:
                    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target_ip))
                    responses, unanswered = srp(packet, timeout=1, verbose=0)

                    for _, received in responses:
                        ip = received.psrc
                        mac = received.hwsrc
                        yield {"ip": ip, "mac": mac}
                        logging.debug(f"Added basic result for IP: {ip}, MAC: {mac}")
                except Exception as e:
                    logging.error(f"Error during scan of IP: {target_ip} Error: {e}")
                    yield {"ip": None, "mac": None, "error": str(e)}

                scanned_ips += 1
                progress = int((scanned_ips / total_ips) * 100)
                yield "Progress", progress

        except Exception as e:
            logging.error(f"Error during subnet creation or iteration : {e}")
            yield {"ip": None, "mac": None, "error": str(e)}

        logging.debug(f"Scan finished.")

    def validate_ip(self, ip):
        try:
            ip_address(ip)
            return True
        except ValueError:
            try:
                ip_network(ip, False)  # strict = False to allow host bits set for single IPs
                return True
            except ValueError:
                return False

    def ping(self, host):
        """
        Returns either the delay in seconds or None if timeout.
        """
        import time
        try:
            start = time.time()
            subprocess.check_output(["ping", "-n", "1", host], timeout=1)
            end = time.time()
            return (end - start) * 1000  # in ms
        except subprocess.TimeoutExpired:
            return 0
        except Exception as e:
            return 0  # Or handle as needed

    def get_device_type(self, mac):
        try:
            oui = mac.replace(":", "").upper()[:6]  # Get the first 6 characters of MAC Address
            if oui in self.oui_data:
                return self.oui_data[oui]
            else:
                return "Unknown"
        except Exception as e:
            return "Unknown"

    def get_os_info(self, ip):
        try:
            # Using nmap for OS detection (requires nmap installed)
            try:
                os_detection = subprocess.check_output(["nmap", "-O", ip], timeout=10).decode('utf-8')
                match = re.search(r'OS details: (.+)', os_detection)
                if match:
                    return match.group(1).strip()
            except:
                # Fallback to ping-based OS detection
                ping_output = subprocess.check_output(["ping", "-n", "1", ip], timeout=1).decode('utf-8')

                if "TTL=128" in ping_output:
                    return "Windows"
                elif "TTL=64" in ping_output:
                    return "Linux/Android"
                elif "TTL=255" in ping_output:
                    return "macOS/iOS"
                else:
                    return "Unknown"
            return "Unknown"
        except Exception as e:
            return "Unknown"

    def get_device_name(self, ip):
        try:
            device_name = socket.gethostbyaddr(ip)[0]
            return device_name
        except Exception as e:
            return "Unknown"

    def get_model_info(self, mac):
        try:
            url = f"https://api.maclookup.app/v2/macs/{mac}?apiKey={self.api_key}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()

            if data.get("success") == True:
                vendor = data.get("company", "Unknown")
                model = data.get("model", "Unknown")
                device_name = data.get("device_name", "Unknown")
                return {"model": model, "make": vendor, "version": device_name}
            else:
                logging.debug(f"API error for MAC {mac}: {data.get('message', 'Unknown error')}")
                return {"model": "Unknown", "make": "Unknown", "version": "Unknown"}

        except requests.exceptions.RequestException as e:
            logging.error(f"API request error for MAC {mac}: {e}")
            return {"model": "Unknown", "make": "Unknown", "version": "Unknown"}
        except Exception as e:
            logging.error(f"An unexpected error occurred during get model info : {e}")
            return {"model": "Unknown", "make": "Unknown", "version": "Unknown"}
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


class NetworkScanner:
    def __init__(self):
        self.oui_data = self.load_oui_data()

    def load_oui_data(self):
        oui_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'oui.json')
        if os.path.exists(oui_path):
            with open(oui_path, 'r') as f:
                return json.load(f)
        else:
            return {}

    def scan(self, ip_range):
        results = []
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
            responses, _ = srp(packet, timeout=2, verbose=0)
            for _, received in responses:
                ip = received.psrc
                mac = received.hwsrc
                device_type = self.get_device_type(mac)
                ping = self.ping(ip)
                os_info = self.get_os_info(ip)
                device_name = self.get_device_name(ip)
                model_info = self.get_model_info(mac)

                results.append((ip, mac, device_type, f"{ping:.2f} ms" if ping else "Unreachable", os_info, device_name,
                                model_info.get("model", "Unknown"), model_info.get("make", "Unknown"),
                                model_info.get("version", "Unknown")))
        except Exception as e:
            results.append(f"Error during scan: {e}")
        return results

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
            oui = mac.replace(":", "")[:6]
            #  API lookup (replace with your chosen API)
            url = f"https://api.macvendors.com/{oui}"  # using macvendors API
            response = requests.get(url)
            if response.status_code == 200:
                return {"model": "Unknown", "make": response.text.strip(), "version": "Unknown"}
            else:
                return {"model": "Unknown", "make": "Unknown", "version": "Unknown"}
        except Exception as e:
            return {"model": "Unknown", "make": "Unknown", "version": "Unknown"}
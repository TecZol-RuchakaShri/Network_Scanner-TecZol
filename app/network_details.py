import platform
import socket
import requests
import json
import speedtest
import psutil
import ipaddress
import subprocess
import re
import datetime

class NetworkDetailsApp:
    def __init__(self, root):
        self.root = root

    def get_all_network_details(self):
        return {
            "SSID": self.get_ssid(),
            "Computer Name": self.get_computer_name(),
            "OS Version": self.get_os_version(),
            "MAC Address": self.get_mac_address(),
            "LAN/WAN IP": self.get_lan_ip_with_mask(),
            "Public IP": self.get_public_ip(),
            "ISP": self.get_isp_name(),
            "Upload Speed": self.get_internet_upload_speed(),
            "Download Speed": self.get_internet_download_speed(),
            "Ping Speed": self.get_ping_internet_speed(),
        }

    def get_ssid(self):
        try:
            ssid_output = subprocess.check_output(["netsh", "wlan", "show", "interfaces"]).decode('utf-8')
            match = re.search(r'SSID\s+:\s+(.+)', ssid_output)
            return match.group(1).strip() if match else "Unknown"
        except Exception:
            return "Error fetching SSID"

    def get_computer_name(self):
        return platform.node()

    def get_os_version(self):
        return platform.platform()

    def get_mac_address(self):
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        return addr.address
            return "Unknown"
        except Exception:
            return "Error fetching MAC Address"

    def get_lan_ip_with_mask(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == ip_address:
                        netmask = addr.netmask
                        if netmask:
                            ip = ipaddress.IPv4Interface(f"{ip_address}/{netmask}")
                            return str(ip)
            return f"{ip_address}/24"
        except Exception:
            return "Error fetching LAN IP"

    def get_public_ip(self):
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            return response.json().get("ip", "Unknown")
        except Exception:
            return "Error fetching Public IP"

    def get_isp_name(self):
        try:
            public_ip = self.get_public_ip()
            response = requests.get(f"http://ip-api.com/json/{public_ip}", timeout=5)
            return response.json().get("isp", "Unknown")
        except Exception:
            return "Error fetching ISP Name"

    def get_internet_upload_speed(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            upload_speed = st.upload() / 1_000_000  # Mbps
            return f"{upload_speed:.2f} Mbps"
        except Exception:
            return "Error fetching Upload Speed"

    def get_internet_download_speed(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1_000_000  # Mbps
            return f"{download_speed:.2f} Mbps"
        except Exception:
            return "Error fetching Download Speed"

    def get_ping_internet_speed(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            return f"{st.results.ping:.2f} ms"
        except Exception:
            return "Error fetching Ping Speed"

    def get_current_date_time(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
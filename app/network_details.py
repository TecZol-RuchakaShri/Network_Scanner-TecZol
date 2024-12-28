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
        details = {
            "SSID": self.get_ssid(),
            "Name of the computer that run the application": self.get_computer_name(),
            "OS version": self.get_os_version(),
            "MAC address": self.get_mac_address(),
            "LAN/WAN IP address": self.get_lan_ip_with_mask(),
            "Public IP address": self.get_public_ip(),
            "ISP Name": self.get_isp_name(),
            "Average Internet Upload Speed": self.get_internet_upload_speed(),
            "Average Internet Download Speed": self.get_internet_download_speed(),
            "Ping Internet Speed": self.get_ping_internet_speed(),
            "Average LAN Upload Speed": self.get_lan_upload_speed(),
            "Average LAN Download Speed": self.get_lan_download_speed(),
            "Ping LAN Speed": self.get_ping_lan_speed(),
            "Default Gateway": self.get_default_gateway(),
            "IP Range": self.get_ip_range(),
        }
        return details

    def get_ssid(self):
        try:
            ssid = subprocess.check_output(["netsh", "wlan", "show", "interfaces"]).decode('utf-8')
            match = re.search(r'SSID\s+:\s+(.+)', ssid)
            if match:
                return match.group(1).strip()
            else:
                return "Not Available"

        except Exception as e:
            return f"Error: {e}"

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
            return "Not Found"
        except Exception as e:
            return f"Error: {e}"

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

            return f"{ip_address}/24"  # default if not found netmask
        except Exception as e:
            return f"Error: {e}"

    def get_public_ip(self):
        try:
            response = requests.get("https://api.ipify.org?format=json")
            data = response.json()
            return data["ip"]
        except Exception as e:
            return f"Error: {e}"

    def get_isp_name(self):
        try:
            public_ip = self.get_public_ip()
            response = requests.get(f"http://ip-api.com/json/{public_ip}")
            data = response.json()
            if data["status"] == "success":
                return data["isp"]
            else:
                return "Not Available"
        except Exception as e:
            return f"Error: {e}"

    def get_internet_upload_speed(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            upload_speed = st.upload() / 1000000  # Mbps
            return f"{upload_speed:.2f} Mbps"
        except Exception as e:
            return f"Error: {e}"

    def get_internet_download_speed(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1000000  # Mbps
            return f"{download_speed:.2f} Mbps"
        except Exception as e:
            return f"Error: {e}"

    def get_ping_internet_speed(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            ping_speed = st.results.ping
            return f"{ping_speed:.2f} ms"
        except Exception as e:
            return f"Error: {e}"

    def get_lan_upload_speed(self):
        try:
            upload_speed = 0
            bytes_sent = psutil.net_io_counters().bytes_sent
            for i in range(3):
                psutil.net_io_counters()
                upload_speed = (psutil.net_io_counters().bytes_sent - bytes_sent)
                bytes_sent = psutil.net_io_counters().bytes_sent
                if upload_speed > 0:
                    break
            upload_speed_mbps = (upload_speed / 1024 / 1024) / 3  # Mbps
            return f"{upload_speed_mbps:.2f} Mbps"
        except Exception as e:
            return f"Error: {e}"

    def get_lan_download_speed(self):
        try:
            download_speed = 0
            bytes_received = psutil.net_io_counters().bytes_recv
            for i in range(3):
                psutil.net_io_counters()
                download_speed = (psutil.net_io_counters().bytes_recv - bytes_received)
                bytes_received = psutil.net_io_counters().bytes_recv
                if download_speed > 0:
                    break
            download_speed_mbps = (download_speed / 1024 / 1024) / 3  # Mbps
            return f"{download_speed_mbps:.2f} Mbps"
        except Exception as e:
            return f"Error: {e}"

    def get_ping_lan_speed(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            hostname = socket.gethostname()
            remote_ip = socket.gethostbyname(hostname)
            if local_ip == remote_ip:
                return "Local IP same as remote IP"
            else:
                return f"{self.ping(remote_ip):.2f} ms"
        except Exception as e:
            return f"Error: {e}"

    def ping(self, host):
        """
        Returns either the delay in seconds or None if timeout.
        """
        import time
        try:
            import subprocess
            start = time.time()
            subprocess.check_output(["ping", "-n", "1", host], timeout=5)
            end = time.time()
            return (end - start) * 1000  # in ms
        except subprocess.TimeoutExpired:
            return 0
        except Exception as e:
            return 0  # or handle it according to the requirements

    def get_default_gateway(self):
        try:
            import subprocess
            default_gateway = subprocess.check_output(["ipconfig", "|", "findstr", "Default Gateway"]).decode('utf-8')
            return default_gateway.split(":")[-1].strip().split("\r\n")[0]
        except Exception as e:
            return "Not Found"

    def get_ip_range(self):
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
                            ip_range = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                            return f"{ip_range.network_address} - {ip_range.broadcast_address}"
            return f"Not Found"
        except Exception as e:
            return f"Error: {e}"

    def get_current_date_time(self):
        now = datetime.datetime.now()
        return now.strftime("%Y-%m-%d %H:%M:%S")
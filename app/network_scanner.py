from scapy.all import ARP, Ether, srp
from ipaddress import ip_network

class NetworkScanner:
    def scan(self, ip_range, progress_callback):
        results = []
        subnet = list(ip_network(ip_range, strict=False).hosts())
        total = len(subnet)
        for i, ip in enumerate(subnet, start=1):
            progress_callback(int((i / total) * 100))
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip))
            answered, _ = srp(packet, timeout=2, verbose=0)
            for _, recv in answered:
                results.append({"ip": str(ip), "mac": recv.hwsrc, "vendor": "Unknown"})
        return results

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from ipaddress import ip_address, ip_network

class NetworkScanner:
    def __init__(self):
        pass

    def scan(self, ip_range):
        results = []
        try:
          packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
          responses, _ = srp(packet, timeout=2, verbose=0)
          for _, received in responses:
              ip = received.psrc
              mac = received.hwsrc
              results.append((ip, mac, "Unknown", "Reachable", "Unknown", "Unknown"))
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
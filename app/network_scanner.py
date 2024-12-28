from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

class NetworkScanner:
    def __init__(self):
        pass

    def scan(self, ip_range):
        results = []
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        responses, _ = srp(packet, timeout=2, verbose=0)
        for _, received in responses:
            ip = received.psrc
            mac = received.hwsrc
            results.append((ip, mac, "Unknown", "Reachable", "Unknown", "Unknown"))
        return results

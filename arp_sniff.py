from scapy.config import conf
from scapy.layers.l2 import ARP
from scapy.sendrecv import sniff
from orm import save


# NO momento só observará opcode 2 (reply)
def arp_monitor_callback(pkt):
    if pkt[ARP].op == 2:
        print(f"ARP Reply: IP {pkt[ARP].psrc} - MAC {pkt[ARP].hwsrc}")
        save(ip=pkt[ARP].psrc, mac=pkt[ARP].hwsrc)


sniff(prn=arp_monitor_callback, filter="arp", store=0)

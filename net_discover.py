from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from orm import save, EnumMethods


def get_gateway_ip():
    return conf.route.route("0.0.0.0")[2]


arp2_callback_aux = set()


def arp2_monitor_callback(pkt):
    if pkt[ARP].op == 2:
        if pkt[ARP].hwsrc in arp2_callback_aux:
            return
        arp2_callback_aux.add(pkt[ARP].hwsrc)
        print(f"ARP Reply: IP {pkt[ARP].psrc} - MAC {pkt[ARP].hwsrc}")
        save(ip=pkt[ARP].psrc, mac=pkt[ARP].hwsrc, gateway=(pkt[ARP].psrc == get_gateway_ip()),
             method=EnumMethods.ARP_2)


def icmp_scan(ip_dst="192.168.0.100/28", timeout=3):
    ans, unans = srp(Ether() / IP(dst=ip_dst) / ICMP(), timeout=timeout)
    for sent, received in ans:
        mac_ = received[Ether].src
        gateway_ = get_gateway_ip()

        save(ip=received[IP].src, mac=mac_, gateway=(received[IP].src == gateway_),
             method=EnumMethods.ICMP_ECHO_RESPONSE)

    for sent in unans:
        print(sent[IP].dst)
        if sent[IP].dst != sent[IP].src:  # Evita que diga que o próprio dispositivo está offline
            save(ip=sent[IP].dst, method=EnumMethods.ICMP_ECHO_RESPONSE_TIMEOUT)

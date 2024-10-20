from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, sr

ans, unans = sr(IP(dst="192.168.0.0/24") / ICMP(), timeout=3)

ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))

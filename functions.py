"""
Contém as funções callback chamadas para cada chave=valor de uma requisição SNMP
a função deve ser do tipo:
    func(s: VariableBinding)-> Tuple[int, SNMPLeafValue|None]:
    O valor inteiro indica o erro
"""
import subprocess
from multiprocessing import Process

from scapy.sendrecv import sniff

import orm
import settings
from math import log2

from net_discover import arp2_monitor_callback, icmp_scan
from snmp_agent.snmp import VariableBinding, IPAddress, Integer, Boolean


def get_ip_address_scan(s: VariableBinding):
    print(f"REQ {s.oid}")
    ip_addr = settings.get_setting('ip_address')
    return 0, IPAddress(ip_addr)


def set_ip_address_scan(s: VariableBinding):
    print(f"SET {s.oid} TO {s.value.value}")
    ip_addr = '.'.join(f'{c}' for c in s.value.value)
    settings.set_setting("ip_address", ip_addr)
    return 0, IPAddress(ip_addr)


def get_ip_mask_scan(s: VariableBinding):
    print(f"REQ {s.oid}")
    y = lambda x: (2 ** x - 1) << 32 - x
    ip_mask = settings.get_setting('ip_mask')
    mask_bytes = y(int(ip_mask))
    mask_str = '.'.join(f'{c}' for c in mask_bytes.to_bytes(4, 'big'))
    return 0, IPAddress(mask_str)


def set_ip_mask_scan(s: VariableBinding):
    print(f"SET {s.oid} TO {s.value.value}")
    ip_mask = sum([log2(x + 1) for x in s.value.value])
    settings.set_setting("ip_mask", int(ip_mask))
    return 0, IPAddress('.'.join([str(x) for x in s.value.value]))


def get_arp2_timeout(s: VariableBinding):
    print(f"REQ {s.oid}")
    timeout = settings.get_setting("timeout")
    return 0, Integer(timeout)


def set_arp2_timeout(s: VariableBinding):
    print(f"SET {s.oid} TO {s.value.value}")
    settings.set_setting("timeout", s.value.value)
    return 0, Integer(s.value.value)


def another_proc_arp2_run(timeout):
    settings.set_setting("arp2_run", True)
    sniff(prn=arp2_monitor_callback, filter="arp", store=0, timeout=timeout)
    settings.set_setting("arp2_run", False)


def another_proc_icmp_run(ip):
    settings.set_setting("icmp_run", True)
    icmp_scan(ip_dst=ip, timeout=3)
    settings.set_setting("icmp_run", False)


def set_arp2_run(s: VariableBinding):
    print(f"SET {s.oid} TO {s.value.value}")
    current = settings.get_setting("arp2_run")
    if current:
        return 5, Integer(current)  # Genéric Error
    timeout: int = settings.get_setting("timeout")
    # FIXME
    """ Here u r executing a sudo command with parameter injection 
    readed by a file that can be editted by network or local users"""
    p = Process(target=another_proc_arp2_run, args=(timeout,))
    p.start()
    return 0, Integer(s.value.value)


def set_icmp_run(s: VariableBinding):
    print(f"SET {s.oid} TO {s.value.value}")
    current = settings.get_setting("arp2_run")
    if current:
        return 5, Integer(current)  # Genéric Error
    ip: str = settings.get_setting("ip_address")
    mask: str = settings.get_setting("ip_mask")
    # FIXME
    """ Here u r executing a sudo command with parameter injection 
    readed by a file that can be editted by network or local users"""
    p = Process(target=another_proc_icmp_run, args=(ip + '/' + mask,))
    print("AAAAA", ip + '/' + mask)
    p.start()
    return 0, Integer(s.value.value)


def get_arp2_run(s: VariableBinding):
    v: bool = settings.get_setting("arp2_run")
    print(f"GET {s.oid}, is {v}")
    return 0, Integer(v)


def get_icmp_run(s: VariableBinding):
    v: bool = settings.get_setting("icmp_run")
    print(f"GET {s.oid}, is {v}")
    return 0, Integer(v)


def delete(s: VariableBinding):
    orm.drop_devices()
    return 0, Integer(True)
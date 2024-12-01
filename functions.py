"""
Contém as funções callback chamadas para cada chave=valor de uma requisição SNMP
a função deve ser do tipo:
    func(s: VariableBinding)-> Union[int, SNMPLeafValue]:
    O valor inteiro indica o erro

funcoes para get_next_request são parecidas:
    func(s: VariableBinding)-> Union[int, SNMPLeafValue, oid]:
"""
from math import log2
from multiprocessing import Process

from scapy.sendrecv import sniff

import orm
import settings
from net_discover import arp2_monitor_callback, icmp_scan
from snmp_agent.snmp import VariableBinding, IPAddress, Integer, OctetString, NoSuchInstance, EndOfMibView, \
    NoSuchObject, Counter32


def get_next_root(s: VariableBinding):
    s.oid = "1.3.6.1.3.1.1.1.1"
    return *get_ip_address_scan(s), s.oid


def get_ip_address_scan(s: VariableBinding):
    ip_addr = settings.get_setting('ip_address')
    return 0, IPAddress(ip_addr)


def get_next_ip_adrress_scan(s: VariableBinding):
    s.oid = "1.3.6.1.3.1.1.1.2"
    return *get_ip_mask_scan(s), s.oid


def set_ip_address_scan(s: VariableBinding):
    ip_addr = '.'.join(f'{c}' for c in s.value.value)
    settings.set_setting("ip_address", ip_addr)
    return 0, IPAddress(ip_addr)


def get_ip_mask_scan(s: VariableBinding):
    ip_mask = int(settings.get_setting('ip_mask'))
    mask_bytes = (2 ** ip_mask - 1) << 32 - ip_mask
    mask_str = '.'.join(f'{c}' for c in mask_bytes.to_bytes(4, 'big'))
    return 0, IPAddress(mask_str)


def get_next_ip_mask_scan(s: VariableBinding):
    s.oid = "1.3.6.1.3.1.1.1.3"
    return *get_icmp_run(s), s.oid


def set_ip_mask_scan(s: VariableBinding):
    ip_mask = sum([log2(x + 1) for x in s.value.value])
    settings.set_setting("ip_mask", int(ip_mask))
    return 0, IPAddress('.'.join([str(x) for x in s.value.value]))


def get_arp2_timeout(s: VariableBinding):
    timeout = settings.get_setting("timeout")
    return 0, Integer(timeout)


def get_next_arp2_timeout(s: VariableBinding):
    s.oid = "1.3.6.1.3.1.1.2.2"
    return *get_arp2_run(s), s.oid


def set_arp2_timeout(s: VariableBinding):
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
    current = settings.get_setting("arp2_run")
    if current:
        return 5, NoSuchObject()
    ip: str = settings.get_setting("ip_address")
    mask: str = settings.get_setting("ip_mask")
    # FIXME
    """It's executing as sudo"""
    p = Process(target=another_proc_icmp_run, args=(ip + '/' + mask,))
    p.start()
    return 0, Integer(s.value.value)


def get_arp2_run(s: VariableBinding):
    v: bool = settings.get_setting("arp2_run")
    return 0, Integer(v)


def get_next_arp2_run(s: VariableBinding):
    if orm.count_history_line() > 0:
        s.oid = "1.3.6.1.3.1.2.1.1"
        return *get_table_history(s), s.oid
    elif orm.count_device_line() > 0:
        s.oid = "1.3.6.1.3.1.3.1.1"
        return *get_table_device(s), s.oid
    else:
        return 2, NoSuchInstance(), s.oid


def get_icmp_run(s: VariableBinding):
    v: bool = settings.get_setting("icmp_run")
    return 0, Integer(v)


def get_next_icmp_run(s: VariableBinding):
    s.oid = "1.3.6.1.3.1.1.2.1"
    return *get_arp2_timeout(s), s.oid


def delete(s: VariableBinding):
    orm.drop_devices()
    return 0, Integer(True)


def get_table_history(s: VariableBinding):
    oid = s.oid.split(".")
    if len(oid) != 9:
        return 2, NoSuchInstance()
    column, line = [int(i) for i in oid[-2:]]
    value = get_history(line, column)
    if value is None:
        return 2, NoSuchInstance()
    if column == 1:  # MAC
        return 0, OctetString(value.replace(":", ""))
    elif column == 2:  # IP
        return 0, IPAddress(value)
    elif column == 3:  # Discovered Method
        return 0, OctetString(value)
    elif column == 4:  # Discovery At
        return 0, OctetString(str(value))
    return 2, NoSuchInstance()


def get_next_table_history(s: VariableBinding):
    oid = s.oid.split(".")
    if len(oid) != 9:
        return 2, NoSuchInstance()
    column, line = [int(i) for i in oid[-2:]]

    if line >= orm.count_history_line():
        if column == 4:
            s.oid = "1.3.6.1.3.1.3.1.1"
            return *get_table_device(s), s.oid
        elif 4 > column > 0:
            s.oid = s.oid[:-3] + f"{column + 1}.{1}"
            return *get_table_history(s), s.oid
    else:
        s.oid = s.oid[:-3] + f"{column}.{line + 1}"
        return *get_table_history(s), s.oid

    return 2, NoSuchInstance(), s.oid


def get_next_table_device(s: VariableBinding):
    oid = s.oid.split(".")
    if len(oid) != 9:
        return 2, NoSuchInstance()
    column, line = [int(i) for i in oid[-2:]]

    if line >= orm.count_device_line():
        if column == 6:
            return 0, EndOfMibView(), s.oid
        elif 6 > column > 0:
            s.oid = s.oid[:-3] + f"{column + 1}.{1}"
            return *get_table_device(s), s.oid
    else:
        s.oid = s.oid[:-3] + f"{column}.{line + 1}"
        return *get_table_device(s), s.oid

    return 2, NoSuchInstance(), s.oid


def get_table_device(s: VariableBinding):
    oid = s.oid.split(".")
    if len(oid) != 9:
        return 2, NoSuchInstance()
    column, line = [int(i) for i in oid[-2:]]
    try:
        value = get_device(line, column)
    except IndexError:
        return 2, NoSuchInstance()
    if value is None:
        return 2, NoSuchInstance()
    if column == 3:  # STATUS
        return 0, OctetString(value)
    elif column == 1:  # MAC
        return 0, OctetString(value.replace(":", ""))
    elif column == 2:  # IP
        return 0, IPAddress(value)
    elif column == 4:  # GATEWAY
        return 0, Integer(value)
    elif column == 5:  # FIRST CONN AT
        return 0, OctetString(value)
    elif column == 6:
        return 0, Counter32(value)

    return 2, NoSuchInstance()


# GET_NEXT_REQUEST


# ------ DATABASE ACCESS --------------
def get_history(id_: int, column: int):
    if line := orm.get_line_history(id_ - 1):
        return line[column - 1] if len(line) > column else None


def get_device(id_: int, column: int):
    if line := orm.get_line_device(id_):  # FIXME Nomeia direito estas  funcoes
        return line[column - 1] if len(line) >= column else None
    return None

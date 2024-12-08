import asyncio

from snmp_agent import utils
from snmp_agent.server import Server
from snmp_agent.snmp import SNMPResponse, SNMPRequest, VariableBind

import functions

SUFFIX = "1.3.6.1.3.1."


async def handler(req: SNMPRequest) -> SNMPResponse:
    v_list = {
        # INTERMEDIATE NOTES (SNMPWALK)
        SUFFIX[:-1]: VariableBind(SUFFIX[:-1], get_next=functions.get_next_root),
        SUFFIX+"1": VariableBind(SUFFIX+"1", get_next=functions.get_next_root),
        SUFFIX+"1.1": VariableBind(SUFFIX+"1.1", get_next=functions.get_next_root),
        SUFFIX+"1.2": VariableBind(SUFFIX+"1.2", get_next=functions.get_next_arp2),
        SUFFIX+"2": VariableBind(SUFFIX+"2", get_next=functions.get_next_history),
        SUFFIX+"3": VariableBind(SUFFIX+"3", get_next=functions.get_next_device),

        # ICMP SCAN
        SUFFIX + "1.1.1": VariableBind(SUFFIX + "1.1.1", write=functions.set_ip_address_scan,
                                       read=functions.get_ip_address_scan, get_next=functions.get_next_ip_adrress_scan),
        SUFFIX + "1.1.2": VariableBind(SUFFIX + "1.1.2", write=functions.set_ip_mask_scan,
                                       read=functions.get_ip_mask_scan, get_next=functions.get_next_ip_mask_scan),
        SUFFIX + "1.1.3": VariableBind(SUFFIX + "1.1.3", write=functions.set_icmp_run,
                                       read=functions.get_icmp_run, get_next=functions.get_next_icmp_run),

        # ARP_2 SCAN
        SUFFIX + "1.2.1": VariableBind(SUFFIX + "1.2.1", write=functions.set_arp2_timeout,
                                       read=functions.get_arp2_timeout, get_next=functions.get_next_arp2_timeout),
        SUFFIX + "1.2.2": VariableBind(SUFFIX + "1.2.2", write=functions.set_arp2_run,
                                       read=functions.get_arp2_run, get_next=functions.get_next_arp2_run),

        # TABLE HISTORY
        SUFFIX + "2.": VariableBind(SUFFIX + "2", read=functions.get_table_history, use_start_with=True,
                                   get_next=functions.get_next_table_history),

        # TABLE DEVICE
        SUFFIX + "3.": VariableBind(SUFFIX + "3", read=functions.get_table_device, use_start_with=True,
                                   get_next=functions.get_next_table_device),

        # DELETE
        SUFFIX + "4": VariableBind(SUFFIX + "4", write=functions.delete),
    }
    res_vbs, error_status, error_index = utils.handle_request(req=req, vbs=v_list)

    res = req.create_response(res_vbs, error_status, error_index)

    return res


async def main():
    sv = Server(handler=handler, host='0.0.0.0', port=161)
    await sv.start()
    while True:
        await asyncio.sleep(3600)


loop = asyncio.get_event_loop()
loop.run_until_complete(main())

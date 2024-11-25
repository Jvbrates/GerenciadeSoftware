import asyncio

from typing import Tuple

from snmp_agent import utils
from snmp_agent.server import Server

from snmp_agent.snmp import SNMPResponse, SNMPRequest, VariableBind

import functions

SUFFIX = "1.3.6.1.3.1."


"""def test_write(s: VariableBinding) -> Tuple[int, SNMPLeafValue | None]:
    print(f"TAG: {s.value.tag} {s.value.tag_tuple}\n"
          f"VALUE: {s.value.value} \n"
          f"TO: {s.oid}\n")
    return 0, None"""


async def handler(req: SNMPRequest) -> SNMPResponse:
    v_list = {
        # ICMP SCAN
        SUFFIX + "1.1.1": VariableBind(SUFFIX + "1.1.1", write=functions.set_ip_address_scan, read=functions.get_ip_address_scan),
        SUFFIX + "1.1.2": VariableBind(SUFFIX + "1.1.2", write=functions.set_ip_mask_scan, read=functions.get_ip_mask_scan),
        SUFFIX + "1.1.3": VariableBind(SUFFIX + "1.1.3", write=functions.set_icmp_run, read=functions.get_icmp_run),

        # ARP_2 SCAN
        SUFFIX + "1.2.1": VariableBind(SUFFIX + "1.2.1", write=functions.set_arp2_timeout, read=functions.get_arp2_timeout),
        SUFFIX + "1.2.2": VariableBind(SUFFIX + "1.2.2", write=functions.set_arp2_run, read=functions.get_arp2_run),

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

# Keep it here as a sheet
"""
vbs = [
    VariableBinding(
        '1.3.6.1.2.1.1.1.0', OctetString('System')),
    VariableBinding(
        '1.3.6.1.2.1.1.3.0', TimeTicks(100)),
    VariableBinding(
        '1.3.6.1.2.1.2.2.1.1.1', Integer(1)),
    VariableBinding(
        '1.3.6.1.2.1.2.2.1.2.1', OctetString('fxp0')),
    VariableBinding(
        '1.3.6.1.2.1.2.2.1.5.1', Gauge32(0)),
    VariableBinding(
        '1.3.6.1.2.1.2.2.1.10.1', Counter32(1000)),
    VariableBinding(
        '1.3.6.1.2.1.2.2.1.16.1', Counter32(1000)),
    VariableBinding(
        '1.3.6.1.2.1.31.1.1.1.6.1', Counter64(1000)),
    VariableBinding(
        '1.3.6.1.2.1.31.1.1.1.10.1', Counter64(1000)),
    VariableBinding(
        '1.3.6.1.2.1.4.20.1.1.10.0.0.1', IPAddress('10.0.0.1')),
]
"""
